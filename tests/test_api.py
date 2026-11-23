import itertools
import json
import os
import shutil
import socket
import socketserver
import statistics
import string
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from conftest import PRE_BASH, PRE_READ
from hypothesis import event, given
from hypothesis import strategies as st
from props.strategies import PROPS

from interlockd import identity as identity_mod
from interlockd.api import ApiServer

TOKEN = "test-token-123"


@pytest.fixture
def server(daemon):
    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0)
    s.start_background()
    yield s
    s.shutdown()


def _call(server, method, path, body=None, token=TOKEN):
    host, port = server.address
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{host}:{port}{path}", data=data, method=method)
    req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_health_no_auth(server):
    status, body = _call(server, "GET", "/interlock/v1/health", token=None)
    assert status == 200 and body["status"] == "ok" and body["mode"] == "shadow"


def _install_claude(settings, tmp_path):
    """A claude-code enforcement point as `interlock init` leaves it: shim, hook config, manifest."""
    from interlockd.cli import CLAUDE_SHIM_SRC
    from interlockd.onboard import Manifest

    shim = settings.home / "adapters" / "claude-code" / "interlock-hook.sh"
    shim.parent.mkdir(parents=True)
    shim.write_text(CLAUDE_SHIM_SRC.read_text(encoding="utf-8").replace("__HARNESS__", "claude-code"), encoding="utf-8")
    hooks = tmp_path / "claude-settings.json"
    hooks.write_text(f'{{"hooks": {{"PreToolUse": [{{"hooks": [{{"command": "sh {shim}"}}]}}]}}}}', encoding="utf-8")
    Manifest(created_at="2026-10-18T00:00:00Z", hooks=[{"harness": "claude-code", "file": str(hooks),
                                                         "marker": str(shim), "created": False}]).save(settings.home)
    return shim


def _records(daemon, name):
    return [r for r in daemon.spool.iter_records(reverse=False) if (r.get("arguments") or {}).get("record") == name]


def test_health_shape_without_integrity(server):
    """A daemon built without the tamper-detection wiring (tests, embedded use) still answers the new keys."""
    status, body = _call(server, "GET", "/interlock/v1/health", token=None)
    assert status == 200 and "protection" not in body
    assert body["policy_pin"] == {"pinned_sha256": "", "on_disk_sha256": "", "modified": False}
    assert body["fail_mode_tamper"] == "closed"


def test_health_reports_protection_and_policy_pin(daemon, settings, tmp_path):
    from interlockd.cli import attach_integrity

    _install_claude(settings, tmp_path)
    (settings.home / "policy.yaml").write_text("mode: shadow\n", encoding="utf-8")
    attach_integrity(daemon, settings.home, None)
    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0)
    s.start_background()
    try:
        status, body = _call(s, "GET", "/interlock/v1/health", token=None)
        assert status == 200
        prot = body["protection"]
        assert prot == daemon.protection.snapshot()                   # one source of truth (9.10)
        assert prot["aggregate"] == "observing" and prot["home_reasons"] == []
        assert prot["harnesses"]["claude-code"] == {"state": "observing", "reasons": []}
        pin = body["policy_pin"]
        assert pin["pinned_sha256"] == pin["on_disk_sha256"] and len(pin["pinned_sha256"]) == 64
        assert pin["modified"] is False
        (settings.home / "policy.yaml").write_text("mode: shadow\nfail_mode: {default: open}\n", encoding="utf-8")
        pin = _call(s, "GET", "/interlock/v1/health", token=None)[1]["policy_pin"]
        assert pin["modified"] is True and pin["pinned_sha256"] != pin["on_disk_sha256"]
        # unauthenticated and content-free: no Home path, no token, no identity value
        raw = json.dumps(_call(s, "GET", "/interlock/v1/health", token=None)[1])
        assert str(settings.home) not in raw and TOKEN not in raw and s.identity not in raw
    finally:
        s.shutdown()


def test_first_start_seeds_baseline_without_tamper_event(daemon, settings, tmp_path):
    from interlockd import integrity
    from interlockd.cli import attach_integrity

    shim = _install_claude(settings, tmp_path)
    (settings.home / "policy.yaml").write_text("mode: shadow\n", encoding="utf-8")
    attach_integrity(daemon, settings.home, None)
    b = integrity.Baseline.load(settings.home)
    assert b is not None and b.shims["claude_code"] == integrity.file_sha256(shim)
    assert [r["arguments"]["policy_kind"] for r in _records(daemon, "policy_baseline_set")] == ["policy"]
    assert len(_records(daemon, "baseline_created")) == 1
    assert not [r for r in daemon.spool.iter_records() if r.get("disposition") == "flag"]   # no Tamper_Event
    assert daemon.verifier.verify("claude-code").problem == ""
    attach_integrity(daemon, settings.home, None)                     # the next start loads it: nothing new
    assert len(_records(daemon, "baseline_created")) == 1 and len(_records(daemon, "policy_baseline_set")) == 1


def test_hook_route_verifies_the_reported_shim_before_deciding(daemon, settings, tmp_path):
    from interlockd.cli import attach_integrity

    shim = _install_claude(settings, tmp_path)
    attach_integrity(daemon, settings.home, None)
    calls, seen = [], []
    real_verify, real_decide = daemon.verifier.verify, daemon.decide

    def verify(harness, reported=None):
        calls.append((harness, reported))
        return real_verify(harness, reported)

    def decide(event, **kw):
        seen.append(kw.get("integrity"))
        return real_decide(event, **kw)

    daemon.verifier.verify, daemon.decide = verify, decide
    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0)
    s.start_background()
    try:
        payload = _payload("claude-code")
        adapter = {"name": "claude-code", "version": "t", "event": "pre", "cwd": "/ws/proj"}
        assert _call(s, "POST", "/interlock/v1/hooks/claude-code", {"adapter": {**adapter, "shim": str(shim)},
                                                                    "payload": payload})[0] == 200
        assert _call(s, "POST", "/interlock/v1/hooks/claude-code", {"adapter": adapter, "payload": payload})[0] == 200
        other = tmp_path / "elsewhere.sh"
        other.write_text("#!/bin/sh\n", encoding="utf-8")
        assert _call(s, "POST", "/interlock/v1/hooks/claude-code", {"adapter": {**adapter, "shim": str(other)},
                                                                    "payload": payload})[0] == 200
        # the native decide route has no harness enforcement point: no verification
        ev = {"kind": "pre_action", "adapter": {"name": "langgraph"},
              "tool_call": {"name": "Read", "arguments": {"file_path": "/ws/proj/x"}}}
        assert _call(s, "POST", "/interlock/v1/decide", ev)[0] == 200
        # rejected before verification
        assert _call(s, "POST", "/interlock/v1/hooks/claude-code", {"payload": payload}, token="wrong")[0] == 401
    finally:
        s.shutdown()
    assert calls == [("claude-code", str(shim)), ("claude-code", None), ("claude-code", str(other))]
    assert [v.problem if v is not None else None for v in seen] == ["", "", "shim_relocated", None]


def test_reply_order_with_body_read_before_auth(server):
    from interlockd.config import MAX_REQUEST_BYTES

    host, port = server.address

    def post(token, data, length=None):
        head = ["POST /interlock/v1/hooks/kiro HTTP/1.1", "Host: x", "Connection: close",
                f"Content-Length: {len(data) if length is None else length}"]
        if token:
            head.append(f"Authorization: Bearer {token}")
        with socket.create_connection((host, port), timeout=5) as c:
            c.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + data)
            raw = b""
            try:
                while chunk := c.recv(65536):
                    raw += chunk
            except ConnectionResetError:
                pass
        return int(raw.split(b" ", 2)[1])

    assert post("wrong", b"", MAX_REQUEST_BYTES + 1) == 401          # auth is still answered first
    assert post("wrong", b"{nope") == 401
    assert post(TOKEN, b"", MAX_REQUEST_BYTES + 1) == 413
    assert post(TOKEN, b"", "-5") == 400
    assert post(TOKEN, b"{nope") == 400


def test_auth_required(server):
    assert _call(server, "GET", "/interlock/v1/limits", token=None)[0] == 401
    assert _call(server, "POST", "/interlock/v1/hooks/kiro", {"payload": PRE_READ}, token="wrong")[0] == 401


def test_kiro_hook_roundtrip_and_event_lookup(server):
    status, v = _call(server, "POST", "/interlock/v1/hooks/kiro", {"adapter": {"name": "kiro", "version": "t"}, "payload": PRE_BASH})
    assert status == 200 and v["disposition"] == "allow" and v["tier"] == 2
    status, rec = _call(server, "GET", f"/interlock/v1/events/{v['event_id']}")
    assert status == 200 and rec["tool_name"] == "execute_bash" and rec["adapter_version"] == "t"
    status, tail = _call(server, "GET", "/interlock/v1/events?limit=5")
    assert status == 200 and tail["events"][0]["event_id"] == v["event_id"]


def test_native_decide_validates(server):
    status, body = _call(server, "POST", "/interlock/v1/decide", {"kind": "pre_action"})
    assert status == 400 and body["error"] == "invalid event"
    ev = {"kind": "pre_action", "adapter": {"name": "langgraph"}, "tool_call": {"name": "Read", "arguments": {"file_path": "/ws/proj/x"}}}
    status, v = _call(server, "POST", "/interlock/v1/decide", ev)
    assert status == 200 and v["tier"] == 0


def test_bad_json_is_400(server):
    host, port = server.address
    req = urllib.request.Request(f"http://{host}:{port}/interlock/v1/decide", data=b"{nope", method="POST")
    req.add_header("authorization", f"Bearer {TOKEN}")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=5)
    assert e.value.code == 400


def test_tier0_latency_budget(server):
    """Design §1: p95 ≤ 60 ms on the deterministic path, end to end over HTTP with an fsync'd spool write.

    Measured as 5 batches of 50 after a 20-call warm-up; the p50 gate is on the *best* batch median. A real
    regression (slower rule engine, extra fsync, blocking I/O) moves every batch; a noisy-neighbour stall on a shared
    CI runner (seen on the GitHub Windows runner: one 60 ms p50, green on re-run) hits only some batches.
    """
    body = {"adapter": {"name": "kiro", "version": "t"}, "payload": PRE_READ}
    for _ in range(20):  # warm: imports, connection paths, spool file, OS caches
        _call(server, "POST", "/interlock/v1/hooks/kiro", body)
    batches = []
    for _ in range(5):
        batch = []
        for _ in range(50):
            t0 = time.perf_counter()
            status, _ = _call(server, "POST", "/interlock/v1/hooks/kiro", body)
            batch.append((time.perf_counter() - t0) * 1000)
            assert status == 200
        batches.append(batch)
    medians = [statistics.median(b) for b in batches]
    samples = sorted(x for b in batches for x in b)
    p50, p95 = statistics.median(samples), samples[int(len(samples) * 0.95) - 1]
    print(f"\ntier-0 HTTP round trip: p50={p50:.2f} ms p95={p95:.2f} ms max={samples[-1]:.2f} ms "
          f"batch medians={[round(m, 2) for m in medians]}")
    # Windows loopback HTTP + fsync costs a few ms more per call than macOS/Linux; the budget still sits an order of
    # magnitude above a healthy run (~2-5 ms), so a real regression fails on every platform
    assert min(medians) < (30 if sys.platform == "win32" else 20)
    # shared CI runners have fsync stalls of 100+ ms that say nothing about Interlock; there, only catch gross regressions
    assert p95 < (500 if os.environ.get("CI") else 60)


def test_text_format_for_shell_shims(server):
    host, port = server.address
    req = urllib.request.Request(f"http://{host}:{port}/interlock/v1/hooks/kiro?format=text",
                                 data=json.dumps({"adapter": {"name": "kiro"}, "payload": PRE_BASH}).encode(), method="POST")
    req.add_header("authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.headers["Content-Type"].startswith("text/plain")
        lines = r.read().decode().splitlines()
    assert lines[0] == "allow shadow 2"
    assert lines[1] == ""  # no finding, no reason


def test_shutdown_from_serving_thread_does_not_deadlock(daemon):
    """Regression: a SIGTERM handler runs on the serve_forever thread; shutdown must be dispatched elsewhere."""
    import threading

    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0)

    def serve_then_stop():
        # emulate the signal handler firing while serve_forever runs on this same thread
        threading.Timer(0.2, lambda: threading.Thread(target=s.shutdown, daemon=True).start()).start()
        s.serve_forever()

    t = threading.Thread(target=serve_then_stop, daemon=True)
    t.start()
    t.join(timeout=5)
    assert not t.is_alive(), "serve_forever did not return after shutdown"


# ------------------------------------------------------------------------------------------------ identity header

_FIXTURES = Path(__file__).parent / "fixtures"
_HOOKS = ("kiro", "claude-code", "codex", "cursor", "gemini-cli", "claude-agent-sdk", "copilot-cli", "windsurf",
          "antigravity")
_FORMATS = ("", "text", "claude-code", "cursor", "gemini-cli", "copilot-cli", "antigravity")
_HOOK_PAYLOADS = {
    "kiro": PRE_BASH,
    "claude-code": "claude-code/pre-bash-block.json",
    "codex": "codex/pre-bash-benign.json",
    "claude-agent-sdk": "claude-code/pre-bash-block.json",
    "cursor": "cursor/pre-shell-benign.json",
    "gemini-cli": "gemini-cli/pre-shell-benign.json",
    "copilot-cli": "copilot-cli/pre-bash-benign.json",
    "windsurf": "windsurf/pre-shell-benign.json",
    "antigravity": {"tool_name": "run_command", "tool_input": {"command": "ls"}},   # no recorded fixture
}
_UNIX_OK = hasattr(socket, "AF_UNIX") and hasattr(socketserver, "UnixStreamServer")
_PATH_CHARS = string.ascii_letters + string.digits + "-._~/%?=&"


def _payload(harness: str) -> dict:
    p = _HOOK_PAYLOADS[harness]
    return p if isinstance(p, dict) else json.loads((_FIXTURES / p).read_text(encoding="utf-8"))


def _route():
    """(method, path, harness or None): hook routes x formats, native decide, health, the other authenticated and
    OGR routes, the control routes the operator-action tasks add, the MCP gateway, and unknown paths."""
    hook = st.builds(lambda h, f: ("POST", f"/interlock/v1/hooks/{h}" + (f"?format={f}" if f else ""), h),
                     st.sampled_from(_HOOKS), st.sampled_from(_FORMATS))
    fixed = st.sampled_from([
        ("POST", "/interlock/v1/decide", None),
        ("GET", "/interlock/v1/health", None),
        ("GET", "/v1/health", None),
        ("GET", "/interlock/v1/limits", None),
        ("GET", "/v1/limits", None),
        ("GET", "/v1/rules", None),
        ("GET", "/interlock/v1/events?limit=3", None),
        ("GET", "/interlock/v1/events/01NOPE", None),
        ("POST", "/v1/evaluate", None),
        ("POST", "/v1/heartbeat", None),
        ("POST", "/interlock/v1/control/operator-action", None),
        ("POST", "/interlock/v1/control/ack", None),
        ("GET", "/mcp/nope/secret", None),
        ("POST", "/mcp/nope/secret", None),
        ("DELETE", "/mcp/nope/secret", None),
    ])
    unknown = st.builds(lambda m, p: (m, "/" + p, None), st.sampled_from(("GET", "POST", "DELETE")),
                        st.text(alphabet=_PATH_CHARS, max_size=40))
    return st.one_of(hook, fixed, unknown)


def _body(variant: str, method: str, path: str, harness: str | None, n: int) -> tuple[bytes, int | None]:
    """(bytes to send, Content-Length to declare when it differs from len(bytes))."""
    from interlockd.config import MAX_REQUEST_BYTES

    if variant == "oversize":
        return b"", MAX_REQUEST_BYTES + 1             # declared only; the daemon answers before reading a body
    if variant == "invalid":
        return b"{not json", None
    if variant == "none" or method != "POST":
        return b"", None
    if harness is not None:
        payload = dict(_payload(harness))
        if harness == "windsurf":
            payload["execution_id"] = f"prop2-{n}"    # the same id twice exercises the Windsurf repeat branch
        doc = {"adapter": {"name": harness, "version": "t", "event": "pre", "cwd": "/ws/proj"}, "payload": payload}
    elif path == "/interlock/v1/decide":
        doc = {"kind": "pre_action", "adapter": {"name": "langgraph"},
               "tool_call": {"name": "Read", "arguments": {"file_path": "/ws/proj/x"}}}
    else:
        doc = {}
    return json.dumps(doc).encode(), None


def _exchange(connect, method: str, path: str, token: str | None, body: bytes, length: int | None):
    """One request on a fresh connection; returns (status, X-Interlock-Identity values, raw head)."""
    head = [f"{method} {path} HTTP/1.1", "Host: interlock", "Connection: close", "Content-Type: application/json",
            f"Content-Length: {len(body) if length is None else length}"]
    if token is not None:
        head.append(f"Authorization: Bearer {token}")
    with connect() as c:
        c.settimeout(10)
        c.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + body)
        raw = b""
        try:
            while chunk := c.recv(65536):
                raw += chunk
        except ConnectionResetError:                  # the daemon closed with an unread body; the reply was sent
            pass
    text = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = text.split("\r\n")
    status = int(lines[0].split()[1])
    values = [ln.split(":", 1)[1].strip() for ln in lines[1:]
              if ln.lower().startswith(identity_mod.HEADER.lower() + ":")]
    return status, values, text


@pytest.fixture
def identity_servers(daemon):
    """One real ApiServer per run, serving TCP loopback and (where available) a Unix socket in a short /tmp dir."""
    home = daemon.settings.home
    value = identity_mod.derive(TOKEN, identity_mod.new_nonce())
    identity_mod.write(home, value)
    sock_dir = Path(tempfile.mkdtemp(prefix="ilp2", dir="/tmp")) if _UNIX_OK else None
    sock_path = str(sock_dir / "s.sock") if sock_dir else None
    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0, unix_socket=sock_path, identity=value)
    s.start_background()
    transports = {"tcp": lambda: socket.create_connection(s.address, timeout=10)}
    if sock_path:
        def unix():
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect(sock_path)
            return c
        transports["unix"] = unix
    try:
        yield home, transports
    finally:
        s.shutdown()
        if sock_dir:
            shutil.rmtree(sock_dir, ignore_errors=True)


_counter = itertools.count()


# Feature: hook-tamper-detection, Property 2: Every daemon reply carries exactly one identity header
@PROPS
@given(data=st.data(), route=_route(), bearer=st.sampled_from(("valid", "missing", "wrong")),
       body=st.sampled_from(("valid", "invalid", "oversize", "none")))
def test_identity_header_everywhere(identity_servers, data, route, bearer, body):
    """For any route x bearer x body x transport, the reply carries exactly one X-Interlock-Identity whose value
    equals <Home>/identity.

    **Validates: Requirements 1.1**
    """
    home, transports = identity_servers
    transport = data.draw(st.sampled_from(sorted(transports)), label="transport")
    method, path, harness = route
    token = {"valid": TOKEN, "missing": None, "wrong": "wrong-" + TOKEN}[bearer]
    sent, length = _body(body, method, path, harness, next(_counter))
    expected = identity_mod.read(home)
    assert expected is not None
    repeats = 2 if harness == "windsurf" and body == "valid" else 1
    for _ in range(repeats):
        status, values, head = _exchange(transports[transport], method, path, token, sent, length)
        event(f"{transport} {status}")               # coverage shows in --hypothesis-show-statistics
        assert 200 <= status < 600, head
        assert values == [expected], (transport, method, path, bearer, body, head)
