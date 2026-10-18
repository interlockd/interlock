"""Native HTTP API (design §5.1) on the standard library, loopback by default.

  GET  /interlock/v1/health                 no auth
  GET  /interlock/v1/limits                 bearer
  POST /interlock/v1/decide                 bearer   InterlockEvent -> Verdict
  POST /interlock/v1/hooks/kiro             bearer   raw Kiro hook payload -> Verdict (daemon normalizes)
  GET  /interlock/v1/events/<event_id>      bearer
  GET  /interlock/v1/events?workspace=&limit=  bearer  (tail)

OGR conformance (design §5.2), served at the bare /v1 prefix the spec uses:
  GET  /v1/health                           no auth
  GET  /v1/limits                           bearer
  POST /v1/evaluate                         bearer   GuardEvent -> OGR Verdict
  POST /v1/heartbeat                        bearer
  GET|POST|DELETE /mcp/<name>/<secret>      route secret   MCP gateway for remote servers (mcp_http.py)
  GET  /v1/rules                            404      (optional per spec; not implemented)
"""

from __future__ import annotations

import json
import logging
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import ValidationError

from . import __version__
from .auth import check_bearer
from .config import MAX_REQUEST_BYTES
from .models import InterlockEvent
from .normalize.claude_code import normalize_claude_code
from .normalize.cursor import normalize_cursor
from .normalize.gemini_cli import normalize_gemini_cli
from .normalize.kiro import normalize_kiro
from .normalize.more import normalize_antigravity, normalize_copilot, normalize_windsurf
from .ogr import PROTOCOLS, evaluate_guard_event
from .pipeline import Daemon
from .render import (
    render_antigravity,
    render_claude_code,
    render_copilot,
    render_cursor,
    render_gemini_cli,
    render_text,
)

log = logging.getLogger("interlockd.api")


class _Server(ThreadingHTTPServer):
    """HTTPServer.server_bind resolves the host with socket.getfqdn(), a reverse-DNS lookup that can stall for tens
    of seconds on machines with slow DNS (seen on CI runners). The daemon binds loopback; it never needs the name."""

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name, self.server_port = str(host), port


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """The same API on a Unix socket created with mode 0600: only the owning user can connect at all."""
    daemon_threads = True

    def server_bind(self):
        import os

        path = self.server_address
        if os.path.exists(path):
            os.unlink(path)                       # a stale socket from a previous run
        old = os.umask(0o177)
        try:
            super().server_bind()
        finally:
            os.umask(old)
        os.chmod(path, 0o600)


class ApiServer:
    def __init__(self, daemon: Daemon, token: str, host: str, port: int, *, unix_socket: str | None = None):
        self.daemon, self.token = daemon, token
        handler = self._make_handler()
        self.httpd = _Server((host, port), handler)
        self.httpd.daemon_threads = True
        self.unix = _UnixServer(unix_socket, handler) if unix_socket else None
        self._thread: threading.Thread | None = None
        self._unix_thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self.httpd.server_address[0], self.httpd.server_address[1]

    def serve_forever(self) -> None:
        if self.unix is not None and self._unix_thread is None:
            self._unix_thread = threading.Thread(target=self.unix.serve_forever, kwargs={"poll_interval": 0.5},
                                                 name="interlock-api-unix", daemon=True)
            self._unix_thread.start()
        self.httpd.serve_forever(poll_interval=0.5)

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, name="interlock-api", daemon=True)
        self._thread.start()

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self.unix is not None:
            import os

            if self._unix_thread is not None:      # socketserver.shutdown() blocks forever if its loop never started
                self.unix.shutdown()
            self.unix.server_close()
            try:
                os.unlink(self.unix.server_address)
            except OSError:
                pass

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = f"interlockd/{__version__}"

            def log_message(self, fmt, *args):  # quiet by default; the audit store is the log
                log.debug(fmt, *args)

            # -- helpers
            def _send(self, status: int, body: dict[str, Any]) -> None:
                data = json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _authed(self) -> bool:
                if check_bearer(self.headers.get("Authorization"), server.token):
                    return True
                self._send(401, {"error": "unauthorized"})
                return False

            def _read_json(self) -> Any | None:
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_REQUEST_BYTES:
                    self._send(413, {"error": "request too large", "max_request_bytes": MAX_REQUEST_BYTES})
                    return None
                raw = self.rfile.read(n) if n else b""
                try:
                    return json.loads(raw or b"{}")
                except json.JSONDecodeError as e:
                    self._send(400, {"error": f"invalid json: {e.msg}"})
                    return None

            # -- routes
            def _mcp(self, method: str) -> bool:
                if not self.path.startswith("/mcp/"):
                    return False
                from .mcp_http import handle

                return handle(self, server.daemon, method)

            def do_DELETE(self) -> None:
                if not self._mcp("DELETE"):
                    self._send(404, {"error": "not found"})

            def do_GET(self) -> None:
                if self._mcp("GET"):
                    return
                u = urlparse(self.path)
                if u.path == "/interlock/v1/health":
                    s = server.daemon.settings
                    self._send(200, {"status": "ok", "version": __version__, "mode": server.daemon.mode, "profile": s.profile,
                                     "policy_sha256": server.daemon.policy_sha256})
                    return
                if u.path == "/v1/health":  # OGR health is unauthenticated per the spec
                    self._send(200, {"status": "ok", "version": __version__, "provider": "interlock"})
                    return
                if not self._authed():
                    return
                if u.path == "/v1/limits":  # OGR
                    self._send(200, {"max_request_bytes": MAX_REQUEST_BYTES, "protocols": list(PROTOCOLS),
                                     "decisions": ["allow", "block"], "ask_maps_to_default": "block"})
                    return
                if u.path == "/v1/rules":  # optional per the OGR spec; Interlock does not expose it
                    self._send(404, {"error": "rules endpoint not implemented"})
                    return
                if u.path == "/interlock/v1/limits":
                    s = server.daemon.settings
                    self._send(200, {"max_request_bytes": MAX_REQUEST_BYTES, "pre_timeout_ms": s.pre_timeout_ms,
                                     "post_timeout_ms": s.post_timeout_ms, "fail_mode": server.daemon.policy.fail_mode, "mode": server.daemon.mode})
                    return
                if u.path.startswith("/interlock/v1/events/"):
                    eid = u.path.rsplit("/", 1)[-1]
                    rec = server.daemon.repo.get_event(eid) if server.daemon.repo else None
                    if rec is None:
                        rec = next((r for r in server.daemon.spool.iter_records() if r["event_id"] == eid), None)
                    self._send(200, rec) if rec else self._send(404, {"error": "not found"})
                    return
                if u.path == "/interlock/v1/events":
                    q = parse_qs(u.query)
                    limit = min(int(q.get("limit", ["50"])[0]), 500)
                    ws = q.get("workspace", [None])[0]
                    rows = [r for r in server.daemon.spool.iter_records(limit=limit * 4)
                            if ws is None or r.get("agent_workspace") == ws][:limit]
                    self._send(200, {"events": rows})
                    return
                self._send(404, {"error": "not found"})

            def do_POST(self) -> None:
                if self._mcp("POST"):
                    return
                u = urlparse(self.path)
                if u.path in ("/v1/evaluate", "/v1/heartbeat"):  # OGR conformance seat (design §5.2)
                    if not self._authed():
                        return
                    body = self._read_json()
                    if body is None:
                        return
                    if u.path == "/v1/heartbeat":
                        self._send(200, {"status": "ok", "version": __version__, "provider": "interlock"})
                        return
                    try:
                        ask = parse_qs(u.query).get("ask_maps_to", ["block"])[0]
                        verdict = evaluate_guard_event(server.daemon, body, ask_maps_to=ask)
                    except Exception as e:
                        log.exception("ogr evaluate failed")
                        self._send(400, {"error": f"evaluate failed: {type(e).__name__}: {e}"})
                        return
                    self._send(200, verdict)
                    return
                if u.path not in ("/interlock/v1/decide", "/interlock/v1/hooks/kiro", "/interlock/v1/hooks/claude-code",
                                  "/interlock/v1/hooks/codex", "/interlock/v1/hooks/cursor", "/interlock/v1/hooks/gemini-cli",
                                  "/interlock/v1/hooks/claude-agent-sdk",
                                  "/interlock/v1/hooks/copilot-cli", "/interlock/v1/hooks/windsurf", "/interlock/v1/hooks/antigravity"):
                    self._send(404, {"error": "not found"})
                    return
                if not self._authed():
                    return
                body = self._read_json()
                if body is None:
                    return
                try:
                    shim = body.get("adapter") or {}
                    if u.path == "/interlock/v1/hooks/kiro":
                        event = normalize_kiro(body.get("payload") or {}, agent_id=server.daemon.settings.agent_id,
                                               adapter_version=str(shim.get("version", "0")))
                    elif u.path == "/interlock/v1/hooks/cursor":
                        event = normalize_cursor(body.get("payload") or {}, agent_id=server.daemon.settings.agent_id,
                                                 adapter_version=str(shim.get("version", "0")))
                    elif u.path in ("/interlock/v1/hooks/copilot-cli", "/interlock/v1/hooks/windsurf", "/interlock/v1/hooks/antigravity"):
                        fn = {"copilot-cli": normalize_copilot, "windsurf": normalize_windsurf,
                              "antigravity": normalize_antigravity}[u.path.rsplit("/", 1)[-1]]
                        event = fn(body.get("payload") or {}, event=str(shim.get("event") or "pre"),
                                   agent_id=server.daemon.settings.agent_id, adapter_version=str(shim.get("version", "0")))
                    elif u.path == "/interlock/v1/hooks/gemini-cli":
                        event = normalize_gemini_cli(body.get("payload") or {}, agent_id=server.daemon.settings.agent_id,
                                                     adapter_version=str(shim.get("version", "0")))
                    elif u.path.startswith("/interlock/v1/hooks/"):
                        harness = u.path.rsplit("/", 1)[-1]
                        payload = body.get("payload") or {}
                        event = normalize_claude_code(payload, agent_type=harness, agent_id=server.daemon.settings.agent_id,
                                                      adapter_version=str(shim.get("version", "0")))
                    else:
                        event = InterlockEvent.model_validate(body)
                except ValidationError as e:
                    self._send(400, {"error": "invalid event", "details": json.loads(e.json())[:5]})
                    return
                except Exception as e:  # noqa: BLE001  boundary: malformed hook payloads must never take the daemon down
                    self._send(400, {"error": f"could not normalize payload: {type(e).__name__}"})
                    return
                try:
                    verdict = server.daemon.decide(event)
                except Exception as e:
                    log.exception("decide failed")
                    self._send(500, {"error": f"decide failed: {type(e).__name__}"})
                    return
                fmt = parse_qs(u.query).get("format", [""])[0]
                if fmt == "text":
                    data = render_text(verdict).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if fmt in ("claude-code", "cursor", "gemini-cli", "copilot-cli", "antigravity"):
                    # The exact JSON the hook prints on stdout; an empty body means "no opinion" (the shim decides
                    # how to express that to its harness).
                    payload = (body.get("payload") or {}) if u.path.startswith("/interlock/v1/hooks/") else {}
                    raw = payload.get("tool_output", payload.get("result_json")) if fmt == "cursor" else payload.get("tool_response")
                    renderer = {"claude-code": render_claude_code, "cursor": render_cursor, "gemini-cli": render_gemini_cli,
                                "copilot-cli": render_copilot, "antigravity": render_antigravity}[fmt]
                    extra = {"harness": u.path.rsplit("/", 1)[-1]} if fmt == "claude-code" else {}
                    out = renderer(verdict, kind=event.kind, tool_response=raw, **extra)
                    data = json.dumps(out, separators=(",", ":")).encode() if out else b""
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self._send(200, verdict.model_dump())

        return Handler
