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


def _write_private(path: Path, data: dict) -> None:
    """Atomic JSON write, mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, path)


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
        _write_private(self.path, data)

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


class OAuthPins:
    """~/.interlock/mcp-oauth-pins.json: {server: {"authorization_servers": [...], "pinned_at": ...}} (mode 0600)."""

    def __init__(self, home: Path):
        self.path = home / "mcp-oauth-pins.json"

    def load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def check(self, server: str, auth_servers: list[str]) -> list[str] | None:
        """The pinned list when it differs from `auth_servers`; pins on first use (returns None)."""
        data = self.load()
        pinned = (data.get(server) or {}).get("authorization_servers")
        if pinned is None:
            from .pipeline import _now_iso

            data[server] = {"authorization_servers": sorted(auth_servers), "pinned_at": _now_iso()}
            _write_private(self.path, data)
            return None
        return pinned if sorted(pinned) != sorted(auth_servers) else None

    def accept(self, server: str) -> bool:
        data = self.load()
        if data.pop(server, None) is None:
            return False
        _write_private(self.path, data)
        return True


def _oauth_decide(daemon, name: str, upstream: str, facts: dict) -> dict | None:
    """Run the gateway's OAuth observations through the pipeline. Returns the verdict when it stops the request."""
    from .det.oauth import TOOL
    from .models import InterlockEvent

    ev = InterlockEvent.model_validate({
        "kind": "pre_action", "adapter": {"name": "mcp-http", "version": "1"}, "session_hint": f"mcp-http-{name}",
        "identity": {"agent_type": "mcp-gateway"},
        "tool_call": {"name": TOOL, "arguments": {"server": name, "upstream": upstream, **facts}},
        "context": {"cwd": str(Path.cwd()), "mcp_server": {"name": name, "source": "mcp-http"}},
        "capabilities": {"ask": False, "rewrite": False, "withhold": False}})
    v = daemon.decide(ev).model_dump()
    return v if v.get("mode") == "enforce" and v.get("disposition") in ("block", "ask") else None


def _check_token(daemon, name: str, upstream: str, authorization: str | None) -> dict | None:
    import hashlib

    from .det.oauth import token_facts

    facts = token_facts(authorization)
    if facts.get("token") != "jwt":
        return None                                       # opaque tokens carry nothing to check here
    cache = daemon.__dict__.setdefault("_oauth_token_verdicts", {})   # one decision per token, mode and server
    key = (name, daemon.mode, hashlib.sha256((authorization or "").encode()).hexdigest())
    if key not in cache:
        if len(cache) > 1024:
            cache.clear()
        cache[key] = _oauth_decide(daemon, name, upstream, facts) or {}
    return cache[key] or None


def _check_challenge(daemon, name: str, upstream: str, www_authenticate: str) -> dict | None:
    """A 401/403 from the server: check the scopes it asks for and, through its metadata, who issues its tokens."""
    from .det.oauth import _host, _same_site, challenge_facts

    facts = challenge_facts(www_authenticate)
    meta_url = facts.get("resource_metadata")
    if meta_url and _same_site(_host(meta_url), _host(upstream)) and meta_url.split(":", 1)[0] in ("https", urlsplit(upstream).scheme):
        meta = _fetch_json(meta_url)
        if isinstance(meta, dict):
            facts["resource"] = str(meta.get("resource") or "")
            servers = [str(x) for x in (meta.get("authorization_servers") or []) if isinstance(x, str)]
            facts["authorization_servers"] = servers
            if servers and daemon.policy.mcp.oauth.pin_authorization_servers:
                pinned = OAuthPins(daemon.settings.home).check(name, servers)
                if pinned is not None:
                    facts["auth_servers_changed"], facts["pinned_authorization_servers"] = True, pinned
    if not facts:
        return None
    return _oauth_decide(daemon, name, upstream, facts)


def _fetch_json(url: str, timeout: float = 5.0) -> Any:
    import urllib.request

    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=timeout) as r:
            return json.loads(r.read(256 * 1024))
    except Exception:  # noqa: BLE001  unreachable metadata: nothing to compare
        return None


def _refuse(handler, verdict: dict) -> None:
    msg = verdict.get("notice") or f"[interlock] refused: {verdict.get('reason')}"
    _write(handler, 403, [("Content-Type", "application/json")], json.dumps({"error": "interlock_refused", "message": msg}).encode())


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
    stop = _check_token(daemon, name, upstream, handler.headers.get("Authorization"))
    if stop:                                              # the token never reaches the upstream
        _refuse(handler, stop)
        return True
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
    if resp.status in (401, 403) and resp.getheader("WWW-Authenticate"):
        stop = _check_challenge(daemon, name, upstream, resp.getheader("WWW-Authenticate"))
        if stop:                                          # the client never sees where to get a token
            resp.read(); conn.close()
            _refuse(handler, stop)
            return True
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
