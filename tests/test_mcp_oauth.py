"""OAuth checks in the HTTP MCP gateway: token audience, denied and broad scopes, server metadata identity, and
authorization-server pinning. A fake upstream answers 401 with a Bearer challenge until it sees a token."""

from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from interlockd.api import ApiServer
from interlockd.det.oauth import challenge_facts, token_facts
from interlockd.mcp_http import OAuthPins, Routes


def jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


class Upstream:
    def __init__(self):
        self.meta = {"authorization_servers": ["https://auth.example.com"]}
        self.scope = "repo read:user"
        self.seen: list[str | None] = []
        up = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a): ...

            def do_GET(self):
                if self.path.startswith("/.well-known/oauth-protected-resource"):
                    return self._json(200, {"resource": up.url, **up.meta})
                self._json(405, {})

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                auth = self.headers.get("Authorization")
                up.seen.append(auth)
                if not auth:
                    return self._json(401, {"error": "unauthorized"}, {"WWW-Authenticate":
                        f'Bearer resource_metadata="{up.base}/.well-known/oauth-protected-resource", scope="{up.scope}"'})
                self._json(200, {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})

            def _json(self, status, obj, extra=None):
                data = json.dumps(obj).encode()
                self.send_response(status); self.send_header("Content-Type", "application/json")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]  # noqa: UP031
        self.url = self.base + "/mcp"


@pytest.fixture
def gw(settings, tmp_path):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    up = Upstream()
    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    pol.mcp.oauth.deny_scopes = ["admin:*"]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    api = ApiServer(d, "tok", "127.0.0.1", 0); api.start_background()
    Routes(settings.home).add("remote", up.url)
    yield Routes(settings.home).local_url("{}:{}".format(*api.address), "remote"), up, d
    api.shutdown(); up.httpd.shutdown()


def call(url, token=None):
    req = urllib.request.Request(url, data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}', method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read() or b"{}")


def rules(d):
    return [f["rule"] for r in d.spool.iter_records(reverse=False) for f in r.get("findings") or []]


def test_facts_never_include_the_token():
    tok = jwt({"aud": "https://mcp.example.com", "scope": "repo read:user", "iss": "https://auth.example.com"})
    f = token_facts(f"Bearer {tok}")
    assert f == {"token": "jwt", "aud": ["https://mcp.example.com"], "token_scopes": ["repo", "read:user"],
                 "iss": "https://auth.example.com"} and tok not in json.dumps(f)
    assert token_facts("Bearer opaque-123") == {"token": "opaque"}
    assert challenge_facts('Bearer error="insufficient_scope", scope="a b"') == {"requested_scopes": ["a", "b"], "error": "insufficient_scope"}


def test_challenge_pins_auth_server_and_catches_a_change(gw):
    url, up, d = gw
    status, headers, _ = call(url)
    assert status == 401 and "resource_metadata" in headers.get("WWW-Authenticate", "")    # first use: passed, pinned
    assert OAuthPins(d.settings.home).load()["remote"]["authorization_servers"] == ["https://auth.example.com"]
    up.meta = {"authorization_servers": ["https://login.attacker.example"]}
    status, headers, body = call(url)
    assert status == 403 and "WWW-Authenticate" not in headers and body["error"] == "interlock_refused"
    assert "mcp.oauth_auth_server_changed" in rules(d)
    OAuthPins(d.settings.home).accept("remote")                                             # `interlock mcp-pins --accept`
    assert call(url)[0] == 401


def test_requested_denied_scope_is_refused(gw):
    url, up, d = gw
    up.scope = "repo admin:org"
    status, _, _ = call(url)
    assert status == 403 and "mcp.oauth_denied_scope" in rules(d)


def test_token_for_another_resource_never_reaches_the_server(gw):
    url, up, d = gw
    status, _, _ = call(url, jwt({"aud": "https://api.other.example", "scope": "repo"}))
    assert status == 403 and up.seen == [] and "mcp.oauth_audience_mismatch" in rules(d)


def test_good_token_passes_and_broad_scope_is_recorded(gw):
    url, up, d = gw
    tok = jwt({"aud": up.url, "scope": "repo delete_repo"})
    assert call(url, tok)[0] == 200 and call(url, tok)[0] == 200
    assert len(up.seen) == 2 and rules(d).count("mcp.oauth_broad_scope") == 1                # decided once per token
    assert call(url, "opaque-token")[0] == 200


def test_shadow_mode_records_but_passes(gw):
    url, _, d = gw
    d.mode = "shadow"
    assert call(url, jwt({"aud": "https://api.other.example"}))[0] == 200
    assert "mcp.oauth_audience_mismatch" in rules(d)


# Captured 2026-10-18 from the public, unauthenticated 401 responses and metadata of three remote MCP servers.
REAL = [
    ("https://api.githubcopilot.com/mcp/",
     ('Bearer error="invalid_request", error_description="No access token was provided in this request", '
      'resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"'),
     {"resource": "https://api.githubcopilot.com/mcp/", "authorization_servers": ["https://github.com/login/oauth"]}),
    ("https://mcp.notion.com/mcp",
     'Bearer realm="OAuth", resource_metadata="https://mcp.notion.com/.well-known/oauth-protected-resource/mcp", scope="default"',
     {"resource": "https://mcp.notion.com/mcp", "authorization_servers": ["https://mcp.notion.com"]}),
    ("https://mcp.linear.app/mcp",
     'Bearer realm="OAuth", resource_metadata="https://mcp.linear.app/.well-known/oauth-protected-resource/mcp", scope="read write"',
     {"resource": "https://mcp.linear.app/mcp", "authorization_servers": ["https://mcp.linear.app"]}),
]


@pytest.mark.parametrize(("upstream", "challenge", "meta"), REAL, ids=["github", "notion", "linear"])
def test_real_servers_raise_nothing(upstream, challenge, meta):
    from interlockd.det import DetResult
    from interlockd.det.oauth import check
    from interlockd.policy import Policy

    facts = {**challenge_facts(challenge), "resource": meta["resource"], "authorization_servers": meta["authorization_servers"]}
    assert facts["resource_metadata"].startswith(upstream.split("/mcp")[0])
    res = DetResult()
    check({"server": "s", "upstream": upstream, **facts}, res, Policy())
    assert res.findings == []


def test_broad_scopes():
    from interlockd.det import DetResult
    from interlockd.det.oauth import check
    from interlockd.policy import Policy

    for scopes, broad in ((["read", "write", "default", "repo", "read:org"], False), (["admin:org"], True), (["*"], True),
                          (["Files.ReadWrite.All"], True), (["write:packages"], True)):
        res = DetResult()
        check({"server": "s", "upstream": "https://x.example/mcp", "token_scopes": scopes}, res, Policy())
        assert bool(res.findings) is broad, scopes
