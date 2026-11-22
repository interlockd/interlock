"""Operator_Actions: the grace table, seeding from the spool, the control routes and the CLI's delivery with its
2 s fallback to a direct spool append (Requirements 11.1, 11.2, 11.5, 11.7, 11.8)."""

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from interlockd import identity as identity_mod
from interlockd import operator, records
from interlockd.api import ApiServer
from interlockd.protection import ProtectionState
from interlockd.store.spool import Spool

TOKEN = "test-token-operator"
MARKER = "SECRET-MARKER-41"


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch)) + f".{int(epoch * 1000) % 1000:03d}Z"


def _action(action: str, at: float, **kw) -> dict:
    return records.operator_action(action, at=_iso(at), **kw)


def _ops(spool, recs=(), now=None):
    ops = operator.OperatorActions(spool, now=(lambda: now) if now is not None else time.time)
    for r in recs:
        ops.add(r)
    return ops


def _control_records(spool, record):
    return [r for r in spool.iter_records(reverse=False)
            if r.get("kind") == "control" and r["arguments"].get("record") == record]


# ---- grace table ------------------------------------------------------------------------------------------------

def test_grace_table_covers_the_requirement_minimum():
    assert {"uninstall", "init"} <= operator.EXPLAINS["enforcement_point"]
    assert "policy_accept" in operator.EXPLAINS["policy"]
    assert {"token_rotate", "init"} <= operator.EXPLAINS["token"]
    assert {"uninstall", "stop"} <= operator.EXPLAINS["daemon"]
    assert operator.GRACE_S == 120.0


def test_explains_newest_mapped_action_within_grace(tmp_path):
    t0 = 1_800_000_000.0
    ops = _ops(Spool(tmp_path / "s"), [_action("init", t0), _action("token_rotate", t0 + 10), _action("stop", t0 + 20)])
    hit = ops.explains("token", t0 + 30)
    assert hit is not None and hit["action"] == "token_rotate"
    assert ops.explains("enforcement_point", t0 + 30)["action"] == "init"
    assert ops.explains("token", t0 + 10 + 119.9)["action"] == "token_rotate"
    assert ops.explains("token", t0 + 10 + 120) is None                 # both init and the rotation are 120 s+ old
    assert ops.explains("enforcement_point", t0 + 120) is None          # 120 s is outside the window
    assert ops.explains("policy", t0 + 30)["action"] == "init"
    assert ops.explains("managed_policy", t0 + 30) is None              # init does not explain the Console's file
    assert ops.explains("no_such_kind", t0 + 30) is None
    assert ops.explains("daemon", t0 + 19) is not None and ops.explains("daemon", t0 + 19)["action"] == "token_rotate"


def test_explains_ignores_future_and_failed_actions(tmp_path):
    t0 = 1_800_000_000.0
    ops = _ops(Spool(tmp_path / "s"), [_action("token_rotate", t0, failed=True), _action("init", t0 + 50)])
    assert ops.explains("token", t0 + 10) is None        # failed rotation starts no grace (2.6); init is in the future
    assert ops.explains("token", t0 + 60)["action"] == "init"


# ---- seeding ----------------------------------------------------------------------------------------------------

def test_seed_loads_recent_operator_actions_only(tmp_path):
    spool = Spool(tmp_path / "spool")
    now = time.time()
    spool.append(_action("init", now - 900))                       # older than the 600 s lookback
    spool.append(_action("uninstall", now - 300))
    spool.append(_action("token_rotate", now - 5, failed=True))   # failed: no grace
    spool.append(records.daemon_started(False))                    # another control record
    spool.append({"event_id": "x", "kind": "pre_action", "received_at": _iso(now - 1), "arguments": {}})
    spool.append(_action("stop", now - 2))
    ops = operator.OperatorActions(spool)
    assert ops.seed() == 2
    assert [e["action"] for e in ops.recent()] == ["uninstall", "stop"]
    assert ops.explains("daemon", now)["action"] == "stop"
    assert ops.seed() == 2 and len(ops.recent()) == 2              # seeding twice adds no duplicates


# ---- the routes -------------------------------------------------------------------------------------------------

@pytest.fixture
def server(daemon):
    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0)
    s.start_background()
    yield s
    s.shutdown()


def _post(server, path, body, token=TOKEN, raw: bytes | None = None):
    host, port = server.address
    data = raw if raw is not None else json.dumps(body).encode()
    req = urllib.request.Request(f"http://{host}:{port}{path}", data=data, method="POST")
    req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_operator_action_route_requires_bearer(server, daemon):
    for token in (None, "wrong"):
        assert _post(server, operator.ROUTE, {"action": "stop"}, token=token)[0] == 401
        assert _post(server, operator.ACK_ROUTE, {"reasons": ["home:token_modified"]}, token=token)[0] == 401
    assert _control_records(daemon.spool, "operator_action") == []
    assert _control_records(daemon.spool, "operator_ack") == []


def test_operator_action_route_records_and_adds(server, daemon):
    daemon.operator_actions = operator.OperatorActions(daemon.spool)
    daemon.protection = ProtectionState(daemon.settings.home, daemon.spool, None, lambda: daemon.mode,
                                        harnesses=list)
    eid = records.operator_action("x")["event_id"]
    status, body = _post(server, operator.ROUTE, {"event_id": eid, "action": "token_rotate", "grace_s": 120})
    assert status == 200 and body == {"event_id": eid}
    [rec] = _control_records(daemon.spool, "operator_action")
    assert rec["event_id"] == eid and rec["arguments"]["action"] == "token_rotate"
    assert rec["arguments"]["via"] == "cli" and rec["arguments"]["protection_state"] == "observing"
    assert rec["mode"] == daemon.mode and "cwd" not in rec and "state" not in rec
    assert daemon.operator_actions.explains("token")["event_id"] == eid
    assert daemon.spool.verify()["ok"]


def test_failed_action_cancels_the_one_it_follows(server, daemon):
    """2.6: a rotation that fails is marked failed, and the grace period its first record opened is withdrawn."""
    daemon.operator_actions = ops = operator.OperatorActions(daemon.spool)
    eid = records.operator_action("x")["event_id"]
    assert _post(server, operator.ROUTE, {"event_id": eid, "action": "token_rotate"})[0] == 200
    assert ops.explains("token") is not None
    assert _post(server, operator.ROUTE, {"action": "token_rotate", "cancels": eid})[0] == 400   # needs failed
    status, _ = _post(server, operator.ROUTE, {"action": "token_rotate", "failed": True, "cancels": eid})
    assert status == 200 and ops.explains("token") is None
    failed = _control_records(daemon.spool, "operator_action")[-1]
    assert failed["arguments"]["failed"] is True and failed["arguments"]["caused_by"] == eid
    reseeded = operator.OperatorActions(daemon.spool)
    reseeded.seed()
    assert reseeded.explains("token") is None                      # the cancellation survives a restart


def test_record_rejects_cancels_without_failed(settings):
    with pytest.raises(ValueError):
        operator.record(settings, "token_rotate", cancels=records.operator_action("x")["event_id"])


@pytest.mark.parametrize("action,observing", [("shadow", True), ("enforce", False)])
def test_shadow_and_enforce_set_the_operators_observing_reason(server, daemon, action, observing):
    daemon.protection = ps = ProtectionState(daemon.settings.home, daemon.spool, None, lambda: "enforce",
                                             harnesses=list)
    ps.set_observing(not observing, caused_by="")
    assert _post(server, operator.ROUTE, {"action": action})[0] == 200
    assert ps.snapshot()["observing"] is observing
    assert ps.aggregate() == ("observing" if observing else "protected")


def test_record_sends_nothing_without_this_homes_identity(settings):
    """No identity file: no daemon of this Home has started, so the token is not sent to whoever listens."""
    hits = []

    class Listener(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.headers.get("Authorization"))
            self.send_response(500)
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Listener)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        _wire_home(settings, httpd.server_address[1])              # token and daemon.json, no identity
        rec = operator.record(settings, "stop")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert hits == []
    [stored] = _control_records(Spool(settings.spool_dir), "operator_action")
    assert stored["event_id"] == rec["event_id"]


def test_operator_action_route_degrades_without_daemon_attributes(server, daemon):
    assert not hasattr(daemon, "operator_actions") and not hasattr(daemon, "protection")
    status, body = _post(server, operator.ROUTE, {"action": "stop"})
    assert status == 200 and body["event_id"]
    [rec] = _control_records(daemon.spool, "operator_action")
    assert rec["event_id"] == body["event_id"] and rec["arguments"]["protection_state"] == ""


@pytest.mark.parametrize("body", [
    {"action": f"stop{MARKER}"},
    {"action": "stop", "note": MARKER},
    {"action": "stop", "harness": MARKER},
    {"action": "stop", "via": "hook_session"},                 # only the daemon may tag a hook session
    {"action": "stop", "grace_s": 10_000},
    {"action": "stop", "grace_s": True},
    {"action": "stop", "event_id": MARKER},
    [MARKER],
])
def test_operator_action_route_rejects_invalid_bodies_without_echo(server, daemon, body):
    status, reply = _post(server, operator.ROUTE, body)
    assert status == 400 and MARKER not in json.dumps(reply)
    assert _control_records(daemon.spool, "operator_action") == []


def test_control_routes_bound_the_body(server, daemon):
    big = json.dumps({"action": "stop", "harness": "a" * (operator.MAX_BODY_BYTES + 10)}).encode()
    assert _post(server, operator.ROUTE, None, raw=big)[0] == 413
    assert _post(server, operator.ACK_ROUTE, None, raw=b"{not json")[0] == 400
    assert _control_records(daemon.spool, "operator_action") == []


# ---- hook-session correlation (design decision 8) ---------------------------------------------------------------

def _agent_runs(daemon, adapter: str, command: str):
    """The agent proposes `command` through the harness's shell tool; the daemon judges it like any hook request."""
    from interlockd.normalize.claude_code import normalize_claude_code
    from interlockd.normalize.kiro import normalize_kiro

    if adapter == "claude-code":
        return daemon.decide(normalize_claude_code({
            "session_id": "s-cc", "hook_event_name": "PreToolUse", "cwd": "/ws/proj", "tool_name": "Bash",
            "tool_use_id": f"tu-{time.monotonic_ns()}", "tool_input": {"command": command}}))
    return daemon.decide(normalize_kiro({
        "session_id": "s-kiro", "hook_event_name": "PreToolUse", "cwd": "/ws/proj", "tool_name": "execute_bash",
        "tool_input": {"command": command}}))


def _decision(daemon, event_id):
    return next(r for r in daemon.spool.iter_records() if r.get("event_id") == event_id)


@pytest.mark.parametrize("mode, adapter, via, confirmed", [
    ("enforce", "claude-code", "hook_session", True),    # ask shown to a harness that prompts: it ran, so approved
    ("shadow", "claude-code", "hook_session", False),    # ran under the harness's own permissions: no approval
    ("shadow", "kiro", "hook_session", False),
    ("enforce", "kiro", "cli", False),                   # Kiro renders ask as a refusal: that call never ran
])
def test_operator_action_route_correlates_a_real_decision(server, daemon, mode, adapter, via, confirmed):
    daemon.mode = mode
    daemon.operator_actions = operator.OperatorActions(daemon.spool)
    v = _agent_runs(daemon, adapter, "interlock token --rotate")
    pre = _decision(daemon, v.event_id)
    assert pre["kind"] == "pre_action" and pre["mode"] == mode and pre["disposition"] == "ask"
    assert pre["normalized"]["interlock_control"] == "token --rotate"
    assert "persistence.interlock_control" in [f["rule"] for f in pre["findings"]]
    assert _post(server, operator.ROUTE, {"action": "token_rotate"})[0] == 200
    [rec] = _control_records(daemon.spool, "operator_action")
    assert rec["arguments"]["via"] == via and rec["arguments"]["confirmed"] is confirmed
    assert rec["arguments"]["caused_by"] == (v.event_id if via == "hook_session" else "")
    assert daemon.spool.verify()["ok"]


def test_correlation_matches_the_subcommand_and_is_one_to_one(server, daemon):
    daemon.mode = "enforce"
    daemon.operator_actions = operator.OperatorActions(daemon.spool)
    v = _agent_runs(daemon, "claude-code", "interlock stop")
    _agent_runs(daemon, "claude-code", "interlock status")            # read-only: no finding, nothing kept
    for action in ("restart", "stop", "stop"):
        assert _post(server, operator.ROUTE, {"action": action})[0] == 200
    restart, first, second = _control_records(daemon.spool, "operator_action")
    assert restart["arguments"]["via"] == "cli" and restart["arguments"]["caused_by"] == ""
    assert first["arguments"]["via"] == "hook_session" and first["arguments"]["caused_by"] == v.event_id
    assert second["arguments"]["via"] == "cli" and second["arguments"]["caused_by"] == ""   # already used


def test_correlation_prefers_the_newest_unclaimed_decision(daemon):
    daemon.mode = "shadow"
    daemon.operator_actions = ops = operator.OperatorActions(daemon.spool)
    old = _agent_runs(daemon, "claude-code", "interlock shadow")
    new = _agent_runs(daemon, "claude-code", "interlock shadow")
    assert ops.correlate_hook_session("shadow")["event_id"] == new.event_id
    assert ops.correlate_hook_session("shadow")["event_id"] == old.event_id
    assert ops.correlate_hook_session("shadow") is None


def test_failed_action_is_not_correlated(server, daemon):
    daemon.mode = "enforce"
    daemon.operator_actions = operator.OperatorActions(daemon.spool)
    v = _agent_runs(daemon, "claude-code", "interlock token --rotate")
    assert _post(server, operator.ROUTE, {"action": "token_rotate", "failed": True})[0] == 200
    assert _post(server, operator.ROUTE, {"action": "token_rotate"})[0] == 200
    failed, ok = _control_records(daemon.spool, "operator_action")
    assert failed["arguments"]["via"] == "cli" and ok["arguments"]["caused_by"] == v.event_id


def test_correlation_window_is_thirty_seconds(daemon):
    daemon.mode = "enforce"
    v = _agent_runs(daemon, "claude-code", "interlock uninstall")
    t0 = 1_800_000_000.0
    pre = {**_decision(daemon, v.event_id), "received_at": _iso(t0)}
    for dt, hit in ((29.9, True), (30.0, False), (-2.0, False)):
        ops = operator.OperatorActions(daemon.spool)
        ops.note_decision(pre)
        got = ops.correlate_hook_session("uninstall", t0 + dt)
        assert (got is not None) is hit, dt
        if hit:
            assert got == {"event_id": v.event_id, "disposition": "ask", "mode": "enforce", "session_id": "s-cc",
                           "confirmed": True}


_BASE = {"event_id": "01JDPRE0000000000000000000", "kind": "pre_action", "received_at": "2026-10-17T10:00:00.000Z",
         "session_id": "s1", "normalized": {"interlock_control": "policy accept"},
         "findings": [{"rule": "persistence.interlock_control", "category": "security.persistence"}],
         "capabilities": {"ask": True}}
_VIA_TRANSCRIPT = {"rule": None, "category": "x.interlock.confirmed_via_transcript"}


@pytest.mark.parametrize("change, kept, confirmed", [
    ({"mode": "enforce", "disposition": "ask"}, True, True),
    ({"mode": "enforce", "disposition": "ask", "capabilities": {"ask": False}}, False, False),   # rendered as a refusal
    ({"mode": "enforce", "disposition": "block"}, False, False),                                # did not run
    ({"mode": "enforce", "disposition": "allow"}, True, False),                                 # policy override
    ({"mode": "enforce", "disposition": "allow", "findings": [*_BASE["findings"], _VIA_TRANSCRIPT]}, True, True),
    ({"mode": "shadow", "disposition": "block"}, True, False),                                  # not enforced: ran
    ({"mode": "shadow", "disposition": "ask"}, True, False),
    ({"mode": "enforce", "disposition": "ask", "kind": "post_action"}, False, False),
    ({"mode": "enforce", "disposition": "ask", "findings": []}, False, False),
    ({"mode": "enforce", "disposition": "ask", "normalized": {"action_class": "shell"}}, False, False),
    ({"mode": "enforce", "disposition": "ask", "received_at": "not a time"}, False, False),
])
def test_which_decisions_can_explain_an_action(change, kept, confirmed):
    e = operator._hook_session_entry({**_BASE, **change})
    assert (e is not None) is kept
    if e is not None:
        assert e["action"] == "policy_accept" and e["confirmed"] is confirmed


def test_seed_restores_recent_decisions_and_their_claims(daemon):
    daemon.mode = "enforce"
    used = _agent_runs(daemon, "claude-code", "interlock ack -y")
    free = _agent_runs(daemon, "claude-code", "interlock restart")
    daemon.spool.append(records.operator_action("ack", via="cli", caused_by=used.event_id))
    ops = operator.OperatorActions(daemon.spool)          # a restarted daemon: nothing in memory
    ops.seed()
    assert ops.correlate_hook_session("ack") is None      # claimed by the record above
    assert ops.correlate_hook_session("restart")["event_id"] == free.event_id


def test_ack_route_clears_listed_reasons_and_records(server, daemon):
    ps = ProtectionState(daemon.settings.home, daemon.spool, None, lambda: "enforce", harnesses=lambda: ["claude-code"])
    daemon.protection = ps
    ps.add_reason("claude-code", "shim_modified", "", records.now_iso())
    ps.add_reason("home", "policy_modified", "", records.now_iso())
    assert ps.aggregate() == "compromised"
    status, body = _post(server, operator.ACK_ROUTE, {"reasons": ["claude-code:shim_modified", "home:token_missing"]})
    assert status == 200 and body["cleared"] == ["claude-code:shim_modified"]
    [ack] = _control_records(daemon.spool, "operator_ack")
    assert ack["event_id"] == body["event_id"] and ack["arguments"]["reasons"] == ["claude-code:shim_modified"]
    assert [r.code for r in ps.reasons()] == ["home:policy_modified"]
    last = _control_records(daemon.spool, "protection_state")[-1]
    assert last["arguments"]["caused_by"] == ack["event_id"]
    # nothing unresolved among the listed reasons: no record (11.9)
    status, body = _post(server, operator.ACK_ROUTE, {"reasons": ["claude-code:shim_modified"]})
    assert status == 200 and body == {"event_id": None, "cleared": []}
    assert len(_control_records(daemon.spool, "operator_ack")) == 1
    # works while compromised (11.8) and clears the rest
    assert _post(server, operator.ACK_ROUTE, {"reasons": ["home:policy_modified"]})[1]["cleared"] == ["home:policy_modified"]
    assert ps.aggregate() == "protected"
    assert daemon.spool.verify()["ok"]


@pytest.mark.parametrize("reasons", [[], ["home:shim_modified"], ["claude-code:policy_modified"], [f"home:{MARKER}"],
                                     ["home:token_modified"] * 2 + [1], ["x:y"] * 65])
def test_ack_route_rejects_invalid_reasons(server, daemon, reasons):
    status, reply = _post(server, operator.ACK_ROUTE, {"reasons": reasons})
    assert status == 400 and MARKER not in json.dumps(reply)
    assert _control_records(daemon.spool, "operator_ack") == []


# ---- the CLI side -----------------------------------------------------------------------------------------------

def _wire_home(settings, server_or_port, identity=None):
    settings.token_path.write_text(TOKEN + "\n", encoding="utf-8")
    port = server_or_port if isinstance(server_or_port, int) else server_or_port.address[1]
    (settings.home / "daemon.json").write_text(json.dumps({"listen": f"127.0.0.1:{port}"}), encoding="utf-8")
    if identity is not None:
        identity_mod.write(settings.home, identity)


def test_record_delivers_through_the_daemon(server, daemon, settings):
    daemon.operator_actions = operator.OperatorActions(daemon.spool)
    _wire_home(settings, server, server.identity)
    rec = operator.record(settings, "shadow")
    [stored] = _control_records(daemon.spool, "operator_action")
    assert stored["event_id"] == rec["event_id"]
    assert stored["mode"] == daemon.mode                       # written by the daemon, not appended by the CLI
    assert daemon.operator_actions.explains("policy")["event_id"] == rec["event_id"]


def test_record_falls_back_when_daemon_down(settings):
    with socket.socket() as s:                                  # a port nobody listens on
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    _wire_home(settings, port, "0" * 32)
    rec = operator.record(settings, "stop")
    [stored] = _control_records(Spool(settings.spool_dir), "operator_action")
    assert stored["event_id"] == rec["event_id"] and stored["mode"] == ""


def test_record_falls_back_within_timeout_when_daemon_hangs(settings):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)                                          # accepts the connection, never answers
    try:
        _wire_home(settings, listener.getsockname()[1], "0" * 32)
        t0 = time.monotonic()
        rec = operator.record(settings, "restart", timeout_s=0.5)
        assert time.monotonic() - t0 < 1.5
    finally:
        listener.close()
    [stored] = _control_records(Spool(settings.spool_dir), "operator_action")
    assert stored["event_id"] == rec["event_id"]


def test_record_default_timeout_is_two_seconds():
    import inspect
    assert inspect.signature(operator.record).parameters["timeout_s"].default == 2.0


def test_record_does_not_trust_a_process_without_this_homes_identity(settings):
    class Foreign(BaseHTTPRequestHandler):                      # #29: another process answering on the port
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            data = json.dumps({"event_id": "whatever"}).encode()
            self.send_response(200)
            self.send_header("X-Interlock-Identity", "f" * 32)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Foreign)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        _wire_home(settings, httpd.server_address[1], "0" * 32)
        rec = operator.record(settings, "uninstall")
    finally:
        httpd.shutdown()
        httpd.server_close()
    [stored] = _control_records(Spool(settings.spool_dir), "operator_action")
    assert stored["event_id"] == rec["event_id"]


def test_record_rejects_unknown_action(settings):
    with pytest.raises(ValueError):
        operator.record(settings, "rm -rf")


def test_directly_appended_action_is_seeded_at_start(settings):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    _wire_home(settings, port)
    rec = operator.record(settings, "token_rotate")
    ops = operator.OperatorActions(Spool(settings.spool_dir))
    ops.seed()
    assert ops.explains("token")["event_id"] == rec["event_id"]


def test_operator_records_are_chained_and_tamper_evident(tmp_path):
    spool = Spool(tmp_path / "spool")
    spool.append(_action("init", time.time()))
    spool.append(records.operator_ack(["home:token_modified"]))
    spool.append(_action("stop", time.time()))
    assert spool.verify()["ok"]
    seg = spool.segments()[0]
    lines = seg.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("home:token_modified", "home:token_missing")
    seg.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = Spool(tmp_path / "spool").verify()
    assert not res["ok"] and res["break"]["line"] == 2


@pytest.mark.parametrize("body", [
    {"action": "stop", "harness": "kiro\n"},
    {"action": "stop", "event_id": records.operator_action("stop")["event_id"] + "\n"},
    {"action": "token_rotate", "failed": True, "cancels": records.operator_action("stop")["event_id"] + "\n"},
])
def test_action_body_rejects_a_trailing_newline(body):
    with pytest.raises(operator.BadRequest):
        operator.parse_action_body(body)


def test_ack_body_rejects_a_trailing_newline():
    assert operator.parse_ack_body({"reasons": ["kiro:shim_modified"]}) == ["kiro:shim_modified"]
    with pytest.raises(operator.BadRequest):
        operator.parse_ack_body({"reasons": ["kiro:shim_modified\n"]})
