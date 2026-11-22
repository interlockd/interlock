"""The 0.1.8 shim fixtures and their recorded allow / ask / block outputs (hook-tamper-detection Req 1.5, 1.9, 14.6).

Each recording in fixtures/shims-0.1.8/recorded/ is replayed against the fixture shim it came from (the harness is
deterministic) and against the shim this tree ships (byte-identical output for a reply from this home's daemon).
Re-record with `python tests/shim_stub.py record`."""

from __future__ import annotations

import hashlib
import http.client
import socket

import pytest
from shim_stub import (
    CURRENT_SHIMS,
    HAVE_SH,
    HAVE_UNIX,
    IDENTITY_HEADER,
    RUNTIMES,
    SHIMS_018,
    Reply,
    StubDaemon,
    load_recording,
    play,
    runtime_available,
)

CASES = [(rt, c) for rt in RUNTIMES for c in load_recording(rt)["cases"]]


def _id(item) -> str:
    rt, c = item
    return f"{rt}/{c['harness']}/{c['case']}"


@pytest.mark.parametrize("runtime", list(RUNTIMES))
def test_fixture_shim_is_the_recorded_018_template(runtime):
    rec = load_recording(runtime)
    data = (SHIMS_018 / rec["shim"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == rec["shim_sha256"]
    assert b'"0.1.8"' in data or b'"__VERSION__"' in data
    assert {c["case"] for c in rec["cases"]} >= {"pre-allow", "pre-ask", "pre-block"}


@pytest.mark.parametrize("source", ["fixture", "current"])
@pytest.mark.parametrize("item", CASES, ids=[_id(i) for i in CASES])
def test_replay(item, source):
    runtime, case = item
    if not runtime_available(runtime):
        pytest.skip(f"{runtime}: runtime not available")
    root = SHIMS_018 if source == "fixture" else CURRENT_SHIMS
    outcome, request = play(runtime, case, root / RUNTIMES[runtime][0])
    assert outcome == case["expect"]
    want = case["request"]
    assert request is not None and request["count"] == want["count"] == 1
    assert (request["method"], request["path"], request["authorization_ok"]) == (
        want["method"], want["path"], True)
    for k, v in want["adapter"].items():        # later shims may add keys (the `shim` path) and bump the version
        if not (k == "version" and source == "current"):
            assert request["adapter"].get(k) == v, k


@pytest.mark.skipif(not (HAVE_SH and HAVE_UNIX), reason="needs sh, curl and Unix sockets")
def test_claude_code_sh_over_the_unix_socket():
    rec = load_recording("claude-code-sh")
    case = next(c for c in rec["cases"] if c["harness"] == "claude-code" and c["case"] == "pre-block")
    outcome, request = play("claude-code-sh", case, SHIMS_018 / rec["shim"], unix_socket=True)
    assert outcome == case["expect"] and request["path"] == case["request"]["path"]


def _get(stub: StubDaemon, timeout: float = 5) -> http.client.HTTPResponse:
    host, port = stub.listen.split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
    conn.request("POST", "/x?y=1", body=b'{"adapter":{"shim":"/s"}}', headers={"Content-Type": "application/json"})
    return conn.getresponse()


def test_stub_reply_controls_and_request_recording():
    with StubDaemon() as stub:
        stub.set(status=401, body='{"error":"unauthorized"}', identity=["a" * 32, "a" * 32])
        r = _get(stub)
        assert r.status == 401 and r.read() == b'{"error":"unauthorized"}'
        assert r.msg.get_all(IDENTITY_HEADER) == ["a" * 32, "a" * 32]
        stub.reply = Reply(status=200, body=b"", identity=[], content_type=None)
        r = _get(stub)
        assert r.status == 200 and r.msg.get_all(IDENTITY_HEADER) is None and r.getheader("Content-Type") is None
        assert [(q.method, q.path, q.json()["adapter"]["shim"]) for q in stub.requests] == [("POST", "/x?y=1", "/s")] * 2
        assert stub.requests[0].header("content-type") == ["application/json"]
        stub.set(close_without_reply=True)
        with pytest.raises(http.client.RemoteDisconnected):
            _get(stub)
        stub.set(delay_s=1.0)
        with pytest.raises((TimeoutError, socket.timeout)):
            _get(stub, timeout=0.2)
