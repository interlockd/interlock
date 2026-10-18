import json
import os
import statistics
import time
import urllib.error
import urllib.request

import pytest
from conftest import PRE_BASH, PRE_READ

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
    """Design §1: p95 ≤ 60 ms on the deterministic path, end to end over HTTP with an fsync'd spool write."""
    body = {"adapter": {"name": "kiro", "version": "t"}, "payload": PRE_READ}
    _call(server, "POST", "/interlock/v1/hooks/kiro", body)  # warm
    samples = []
    for _ in range(200):
        t0 = time.perf_counter()
        status, _ = _call(server, "POST", "/interlock/v1/hooks/kiro", body)
        samples.append((time.perf_counter() - t0) * 1000)
        assert status == 200
    samples.sort()
    p50, p95 = statistics.median(samples), samples[int(len(samples) * 0.95) - 1]
    print(f"\ntier-0 HTTP round trip: p50={p50:.2f} ms p95={p95:.2f} ms max={samples[-1]:.2f} ms")
    assert p50 < 20
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
