"""Native HTTP API (design §5.1) on the standard library, loopback by default.

  GET  /interlock/v1/health                 no auth
  GET  /interlock/v1/limits                 bearer
  POST /interlock/v1/decide                 bearer   InterlockEvent -> Verdict
  POST /interlock/v1/hooks/kiro             bearer   raw Kiro hook payload -> Verdict (daemon normalizes)
  GET  /interlock/v1/events/<event_id>      bearer
  GET  /interlock/v1/events?workspace=&limit=  bearer  (tail)
  POST /interlock/v1/control/operator-action   bearer   record an Operator_Action (operator.py)
  POST /interlock/v1/control/ack               bearer   clear acknowledged Protection_State reasons

OGR conformance (design §5.2), served at the bare /v1 prefix the spec uses:
  GET  /v1/health                           no auth
  GET  /v1/limits                           bearer
  POST /v1/evaluate                         bearer   GuardEvent -> OGR Verdict
  POST /v1/heartbeat                        bearer
  GET|POST|DELETE /mcp/<name>/<secret>      route secret   MCP gateway for remote servers (mcp_http.py)
  GET  /v1/rules                            404      (optional per spec; not implemented)
"""

from __future__ import annotations

import hashlib
import json
import logging
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import ValidationError

from . import __version__, capture, operator, tamper
from . import identity as identity_mod
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



# Measured on Windsurf (Devin.app) 3.10.67: every hook runs twice, ~60 ms apart, with the same execution_id. The
# repeat gets the first answer instead of a second decision (no duplicate audit record, no double denial count).
REPEAT_TTL_S = 5.0
_REPEATS: dict[tuple[str, str, str], tuple[float, bytes]] = {}


def _windsurf_repeat_key(path: str, body: dict) -> tuple[str, str, str] | None:
    p = body.get("payload") if path == "/interlock/v1/hooks/windsurf" else None
    if not isinstance(p, dict) or not p.get("execution_id"):
        return None
    digest = hashlib.sha256(json.dumps(p.get("tool_info"), sort_keys=True, default=str).encode()).hexdigest()
    return str(p["execution_id"]), str(p.get("agent_action_name")), digest

def _policy_pin(daemon: Any) -> dict[str, Any]:
    """Pinned (Integrity_Baseline) versus on-disk digest of `<Home>/policy.yaml`; "" when absent or unpinned."""
    from . import integrity

    provider = getattr(daemon, "baseline_provider", None)
    try:
        baseline = provider() if provider is not None else None
    except Exception:  # health must answer even when the baseline cannot be read
        log.exception("cannot read the integrity baseline for health")
        baseline = None
    pinned = baseline.policy_file_sha256 if baseline is not None else ""
    on_disk = integrity.file_sha256(daemon.settings.home / integrity.POLICY_FILE)
    return {"pinned_sha256": pinned, "on_disk_sha256": on_disk, "modified": bool(pinned) and pinned != on_disk}


def _fail_mode_tamper(daemon: Any) -> str:
    """The effective `fail_mode.tamper`: the policy's value when it is open or closed, else closed (4.1, 4.7)."""
    fm = getattr(daemon.policy, "fail_mode", None)
    value = fm.get("tamper") if isinstance(fm, dict) else getattr(fm, "tamper", None)
    return value if value in ("open", "closed") else "closed"


class _Server(ThreadingHTTPServer):
    """HTTPServer.server_bind resolves the host with socket.getfqdn(), a reverse-DNS lookup that can stall for tens
    of seconds on machines with slow DNS (seen on CI runners). The daemon binds loopback; it never needs the name."""

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name, self.server_port = str(host), port


class _UnixServer(socketserver.ThreadingMixIn, getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)):
    """The same API on a Unix socket created with mode 0600: only the owning user can connect at all.
    (Windows Python has no UnixStreamServer: the base falls back so this module imports, and nothing creates one.)"""
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
    def __init__(self, daemon: Daemon, token: str, host: str, port: int, *, unix_socket: str | None = None,
                 identity: str | None = None):
        self.daemon, self.token = daemon, token
        # Sent as X-Interlock-Identity on every reply. `interlock serve` derives it, writes <Home>/identity and
        # passes it in; embedded servers (tests, bench) get a fresh token-bound value so the header is never absent.
        self.identity = identity or identity_mod.derive(token, identity_mod.new_nonce())
        handler = self._make_handler()
        self.httpd = _Server((host, port), handler)
        self.httpd.daemon_threads = True
        if unix_socket and not hasattr(socketserver, "UnixStreamServer"):
            raise OSError("Unix sockets are not available on this platform")
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
            def send_response(self, code: int, message: str | None = None) -> None:
                # Every final reply (hook verdicts in every format, the Windsurf repeat, health, MCP gateway, 4xx/5xx
                # errors and BaseHTTPRequestHandler.send_error) goes through here exactly once, on TCP and the Unix
                # socket alike, so the identity header is added exactly once per reply. A `100 Continue` interim
                # response uses send_response_only and carries no identity, so a shim never sees it twice.
                super().send_response(code, message)
                if code >= 200:
                    self.send_header(identity_mod.HEADER, server.identity)

            def _send(self, status: int, body: dict[str, Any]) -> None:
                data = json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _authed(self, body_bytes: bytes | None = None) -> bool:
                # `body_bytes` is the bounded raw body of a hook request, read before auth so a rejection can be
                # attributed to the self-reported adapter (token-rejection recording, task 5.3). Never echoed.
                # Routes that read no body before auth pass None (the adapter is then `unknown`).
                header = self.headers.get("Authorization")
                if check_bearer(header, server.token):
                    return True
                rejections = getattr(server.daemon, "tamper", None)
                if rejections is not None:
                    # Recorded synchronously before the 401 leaves (2.4); the presented value is passed for the
                    # rotation-grace digest comparison only and is never stored or recorded.
                    presented = header[7:].strip() if header and header.startswith("Bearer ") else ""
                    try:
                        rejections.token_rejected(adapter=tamper.adapter_name(body_bytes),
                                                  addr=tamper.format_addr(self.server.server_address),
                                                  presented=presented)
                    except Exception:  # a recording failure must not change the 401
                        log.exception("cannot record a token rejection")
                self._send(401, {"error": "unauthorized"})
                return False

            def _read_raw(self, limit: int = MAX_REQUEST_BYTES) -> tuple[bytes | None, tuple[int, dict] | None]:
                """Read the declared body without replying: (raw, None), or (None, (status, error body)) when the
                Content-Length is invalid or over the limit (nothing is read then)."""
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = -1
                if n < 0:              # rfile.read(-1) would block until the client closes the connection
                    return None, (400, {"error": "invalid content-length"})
                if n > limit:
                    return None, (413, {"error": "request too large", "max_request_bytes": limit})
                return (self.rfile.read(n) if n else b""), None

            def _parse_json(self, raw: bytes | None) -> Any | None:
                try:
                    return json.loads(raw or b"{}")
                except json.JSONDecodeError as e:
                    self._send(400, {"error": f"invalid json: {e.msg}"})
                    return None

            def _read_json(self, limit: int = MAX_REQUEST_BYTES) -> Any | None:
                raw, err = self._read_raw(limit)
                if err is not None:
                    self._send(*err)
                    return None
                return self._parse_json(raw)

            def _health(self) -> dict[str, Any]:
                """Unauthenticated, loopback only, content-free: state names, reason codes, timestamps, harness
                names and policy-file digests. No paths, no token or identity material."""
                d = server.daemon
                out: dict[str, Any] = {"status": "ok", "version": __version__, "mode": d.mode,
                                       "profile": d.settings.profile, "policy_sha256": d.policy_sha256}
                protection = getattr(d, "protection", None)
                if protection is not None:
                    out["protection"] = protection.snapshot()
                out["policy_pin"] = _policy_pin(d)
                out["fail_mode_tamper"] = _fail_mode_tamper(d)
                return out

            # -- routes
            def _control(self, path: str) -> None:
                """Operator-action and ack routes (Requirement 11). Bearer first, then a small bounded body;
                validation errors are fixed text, never echoed from the body. Served in every Protection_State
                so the Operator can always repair (11.8)."""
                if not self._authed():
                    return
                body = self._read_json(limit=operator.MAX_BODY_BYTES)
                if body is None:
                    return
                handle = operator.handle_operator_action if path == operator.ROUTE else operator.handle_ack
                try:
                    reply = handle(server.daemon, body)
                except operator.BadRequest as e:
                    self._send(400, {"error": str(e)})
                    return
                except Exception as e:  # boundary: a failed record must not take the daemon down
                    log.exception("control route %s failed", path)
                    self._send(500, {"error": f"control failed: {type(e).__name__}"})
                    return
                self._send(200, reply)

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
                    self._send(200, self._health())
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
                if u.path in (operator.ROUTE, operator.ACK_ROUTE):
                    self._control(u.path)
                    return
                if u.path not in ("/interlock/v1/decide", "/interlock/v1/hooks/kiro", "/interlock/v1/hooks/claude-code",
                                  "/interlock/v1/hooks/codex", "/interlock/v1/hooks/cursor", "/interlock/v1/hooks/gemini-cli",
                                  "/interlock/v1/hooks/claude-agent-sdk",
                                  "/interlock/v1/hooks/copilot-cli", "/interlock/v1/hooks/windsurf", "/interlock/v1/hooks/antigravity"):
                    self._send(404, {"error": "not found"})
                    return
                # The bounded body is read before auth (an over-limit or invalid Content-Length reads nothing), but
                # the replies keep their order: 401 first, then 400/413, then invalid JSON.
                raw, err = self._read_raw()
                if not self._authed(raw):
                    return
                if err is not None:
                    self._send(*err)
                    return
                body = self._parse_json(raw)
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
                        extra = {"hook_cwd": shim.get("cwd")} if fn is normalize_windsurf and isinstance(shim.get("cwd"), str) else {}
                        event = fn(body.get("payload") or {}, event=str(shim.get("event") or "pre"),
                                   agent_id=server.daemon.settings.agent_id, adapter_version=str(shim.get("version", "0")), **extra)
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
                repeat_key = _windsurf_repeat_key(u.path, body)
                if repeat_key is not None:
                    hit = _REPEATS.get(repeat_key)
                    if hit is not None and time.monotonic() - hit[0] < REPEAT_TTL_S:
                        self.send_response(200)        # the same hook call again: same answer, not a second decision
                        self.send_header("Content-Type", "text/plain; charset=utf-8")
                        self.send_header("Content-Length", str(len(hit[1])))
                        self.end_headers()
                        self.wfile.write(hit[1])
                        return
                verification = None
                verifier = getattr(server.daemon, "verifier", None)
                if verifier is not None and u.path.startswith("/interlock/v1/hooks/"):
                    # Every hook request, before the verdict (5.1). The shim reports the file that ran (5.10);
                    # pre-0.2.0 shims send none and are verified at the manifest path (5.13).
                    reported = shim.get("shim")
                    try:
                        verification = verifier.verify(u.path.rsplit("/", 1)[-1],
                                                       reported if isinstance(reported, str) else None)
                    except Exception:  # a verifier bug must not take the hook route down
                        log.exception("enforcement-point verification failed")
                try:
                    verdict = (server.daemon.decide(event) if verification is None
                               else server.daemon.decide(event, integrity=verification))
                except Exception as e:
                    log.exception("decide failed")
                    self._send(500, {"error": f"decide failed: {type(e).__name__}"})
                    return
                fmt = parse_qs(u.query).get("format", [""])[0]
                harness = u.path.rsplit("/", 1)[-1] if u.path.startswith("/interlock/v1/hooks/") else event.adapter.name
                home = server.daemon.settings.home
                if not capture.active(home, harness):
                    harness = None

                def captured(reply):
                    if harness:
                        capture.record(home, harness, body, event, verdict, reply)

                if fmt == "text":
                    data = render_text(verdict).encode()
                    if repeat_key is not None:
                        if len(_REPEATS) > 512:
                            _REPEATS.clear()
                        _REPEATS[repeat_key] = (time.monotonic(), data)
                    captured(data)
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
                    extra = {"harness": u.path.rsplit("/", 1)[-1], "tool_input": payload.get("tool_input")} if fmt == "claude-code" else {}
                    out = renderer(verdict, kind=event.kind, tool_response=raw, **extra)
                    data = json.dumps(out, separators=(",", ":")).encode() if out else b""
                    captured(data)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                captured(json.dumps(verdict.model_dump(), default=str))
                self._send(200, verdict.model_dump())

        return Handler
