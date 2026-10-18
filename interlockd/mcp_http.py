"""The MCP gateway for remote (Streamable HTTP) servers, served by the daemon itself.

    agent  ──HTTP──▶  http://127.0.0.1:7391/mcp/<name>/<route secret>  ──HTTPS──▶  upstream MCP server

`interlock gateway wrap` rewrites a remote server's `url` to the local route and records the upstream in
~/.interlock/gateway-routes.json. The route secret stands in for the daemon's bearer token, because MCP clients send
their own Authorization header, which is forwarded to the upstream untouched.

Each POST is run through the same interception core as the stdio proxy (tool-definition pins, poisoned-tool hiding,
tools/call decisions, result probing), for both application/json and text/event-stream responses; SSE is re-emitted
event by event as it arrives. GET (server-initiated stream) and DELETE (session end) pass through. When the daemon is
down, remote servers are unreachable: the HTTP gateway fails closed by construction.
"""

from __future__ import annotations

import hmac
import http.client
import io
import json
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding"}


class Routes:
    """~/.interlock/gateway-routes.json: {"secret": "...", "routes": {name: {"url": upstream}}} (mode 0600)."""

    def __init__(self, home: Path):
        self.path = home / "gateway-routes.json"

    def load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {"secret": "", "routes": {}}

    def save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data, indent=2) + "\n")
        os.replace(tmp, self.path)

    def secret(self) -> str:
        data = self.load()
        if not data.get("secret"):
            data["secret"] = secrets.token_urlsafe(18)
            data.setdefault("routes", {})
            self.save(data)
        return data["secret"]

    def add(self, name: str, upstream: str) -> str:
        sec = self.secret()
        data = self.load()
        data.setdefault("routes", {})[name] = {"url": upstream}
        self.save(data)
        return sec

    def remove(self, name: str) -> str | None:
        data = self.load()
        r = (data.get("routes") or {}).pop(name, None)
        if r is not None:
            self.save(data)
        return (r or {}).get("url")

    def local_url(self, listen: str, name: str) -> str:
        return f"http://{listen}/mcp/{name}/{self.secret()}"

    def resolve(self, name: str, secret: str) -> str | None:
        data = self.load()
        if not data.get("secret") or not hmac.compare_digest(secret, data["secret"]):
            return None
        return ((data.get("routes") or {}).get(name) or {}).get("url")


def _core(daemon, name: str, session: str):
    from .mcp_proxy import Proxy
    from .models import InterlockEvent

    def decider(event: dict) -> dict:
        return daemon.decide(InterlockEvent.model_validate(event)).model_dump()

    out = io.StringIO()
    core = Proxy(name, [], daemon.settings, client_in=io.StringIO(), client_out=out, decider=decider,
                 mode_fn=lambda: daemon.mode, session=session, quiet=True)
    return core, out


def _upstream(url: str) -> tuple[http.client.HTTPConnection, str]:
    u = urlsplit(url)
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.hostname, u.port, timeout=60)
    return conn, (u.path or "/") + (f"?{u.query}" if u.query else "")


def handle(handler, daemon, method: str) -> bool:
    """Serve /mcp/<name>/<secret>[...] on the daemon's API handler. Returns False if the path is not an MCP route."""
    parts = handler.path.split("?", 1)[0].split("/")
    if len(parts) < 4 or parts[1] != "mcp":
        return False
    name, sec = parts[2], parts[3]
    upstream = Routes(daemon.settings.home).resolve(name, sec)
    if upstream is None:
        handler._send(404, {"error": "unknown MCP route"})
        return True
    headers = {k: v for k, v in handler.headers.items() if k.lower() not in HOP_BY_HOP}
    session = f"mcp-http-{name}-{handler.headers.get('Mcp-Session-Id') or 'none'}"
    core, refusals_out = _core(daemon, name, session)

    body = b""
    if method == "POST":
        n = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(n) if n else b""
        try:
            parsed = json.loads(body) if body else None
        except ValueError:
            parsed = None
        if parsed is not None:
            msgs = parsed if isinstance(parsed, list) else [parsed]
            forward = [m for m in (core.on_client_message(x) if isinstance(x, dict) else x for x in msgs) if m is not None]
            refusals = [json.loads(line) for line in refusals_out.getvalue().splitlines()]
            if not forward:                                   # everything was answered here
                _reply_json(handler, refusals if isinstance(parsed, list) else refusals[0])
                return True
            body = json.dumps(forward if isinstance(parsed, list) else forward[0]).encode()
        else:
            refusals = []
    else:
        refusals = []

    try:
        conn, path = _upstream(upstream)
        conn.request(method, path, body=body if method == "POST" else None, headers=headers)
        resp = conn.getresponse()
    except OSError as e:
        handler._send(502, {"error": f"upstream unreachable: {type(e).__name__}"})
        return True
    ctype = resp.getheader("Content-Type", "")
    pass_headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in HOP_BY_HOP]
    if method == "POST" and ctype.startswith("application/json"):
        raw = resp.read()
        try:
            data = json.loads(raw)
            msgs = data if isinstance(data, list) else [data]
            out = [core.on_server_message(m) if isinstance(m, dict) else m for m in msgs] + refusals
            raw = json.dumps(out if isinstance(data, list) or refusals else out[0]).encode()
        except ValueError:
            pass
        _write(handler, resp.status, pass_headers, raw)
    elif method == "POST" and ctype.startswith("text/event-stream"):
        _stream_sse(handler, resp, pass_headers, core, refusals)
    elif ctype.startswith("text/event-stream"):
        _stream_sse(handler, resp, pass_headers, None, [])
    else:
        _write(handler, resp.status, pass_headers, resp.read())
    conn.close()
    return True


def _reply_json(handler, obj: Any) -> None:
    _write(handler, 200, [("Content-Type", "application/json")], json.dumps(obj).encode())


def _write(handler, status: int, headers: list[tuple[str, str]], data: bytes) -> None:
    handler.send_response(status)
    for k, v in headers:
        handler.send_header(k, v)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _stream_sse(handler, resp, headers, core, refusals: list[dict]) -> None:
    """Relay an SSE stream event by event, transforming JSON-RPC `data:` payloads when a core is given."""
    handler.send_response(resp.status)
    for k, v in headers:
        handler.send_header(k, v)
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.close_connection = True
    w = handler.wfile
    for r in refusals:
        w.write(f"event: message\ndata: {json.dumps(r)}\n\n".encode()); w.flush()
    event: list[str] = []
    while True:
        line = resp.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        if text:
            event.append(text)
            continue
        w.write(_transform_event(event, core).encode()); w.flush()
        event = []
    if event:
        w.write(_transform_event(event, core).encode()); w.flush()


def _transform_event(lines: list[str], core) -> str:
    data = "\n".join(ln[5:].lstrip() for ln in lines if ln.startswith("data:"))
    other = [ln for ln in lines if not ln.startswith("data:")]
    if core is not None and data:
        try:
            msg = json.loads(data)
            if isinstance(msg, dict):
                data = json.dumps(core.on_server_message(msg))
        except ValueError:
            pass
    return "\n".join(other + ([f"data: {data}"] if data or not other else [])) + "\n\n"
