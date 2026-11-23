"""Token rejection as a tamper signal: record shape, rate limit and summary, rotation and selftest grace, and the
unchanged 401 on the API (Requirements 2.4, 2.5, 2.7, 14.7)."""

import json
import urllib.error
import urllib.request

import pytest

from interlockd import integrity, operator, records, tamper
from interlockd.api import ApiServer
from interlockd.auth import load_or_create_token, rotate_token

TOKEN = "test-token-tamper"
T0 = 1_800_000_000.0


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _control(spool, record):
    return [r for r in spool.iter_records(reverse=False)
            if r.get("kind") == "control" and r["arguments"].get("record") == record]


def _action(action: str, at: float) -> dict:
    return records.operator_action(action, at=tamper.iso(at))


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def rejections(daemon, clock):
    daemon.operator_actions = operator.OperatorActions(daemon.spool, now=clock)
    daemon.tamper = tamper.TokenRejections(daemon, now=clock)
    return daemon.tamper


# ---- adapter_name and classify_rejection ------------------------------------------------------------------------

def test_adapter_name_self_reported_truncated_or_unknown():
    assert tamper.adapter_name(b'{"adapter":{"name":"claude-code"},"payload":{}}') == "claude-code"
    assert tamper.adapter_name(json.dumps({"adapter": {"name": "x" * 200}}).encode()) == "x" * 64
    assert tamper.adapter_name(json.dumps({"adapter": {"name": "a\nb\x00c"}}).encode()) == "abc"
    for body in (None, b"", b"not json", b"[1]", b'{"adapter":"kiro"}', b'{"adapter":{"name":7}}',
                 b'{"adapter":{"name":""}}', b"\xff\xfe", b"[" * 5000):
        assert tamper.adapter_name(body) == "unknown"


def test_adapter_name_large_body_reads_only_the_prefix():
    big = b'{"adapter":{"name":"kiro","version":"0.2.0"},"payload":' + json.dumps({"x": "y" * 100_000}).encode() + b"}"
    assert len(big) > tamper.PARSE_LIMIT
    assert tamper.adapter_name(big) == "kiro"
    assert tamper.adapter_name(b'{"payload":' + b'"' + b"z" * 100_000 + b'"}') == "unknown"


def test_classify_rejection_previous_token_within_grace(tmp_path):
    path = tmp_path / "token"
    old = load_or_create_token(path)
    previous = integrity.file_sha256(path)          # the baseline's digest is of the file bytes
    rotate_token(path)
    assert tamper.classify_rejection(old, previous, T0, T0 + 5) == "expected_after_rotate"
    assert tamper.classify_rejection(old, previous, T0, T0 + 119.9) == "expected_after_rotate"
    assert tamper.classify_rejection(old, previous, T0, T0 + 120) == "token_rejected"
    assert tamper.classify_rejection(old, previous, T0, T0 - 1) == "token_rejected"
    assert tamper.classify_rejection("another", previous, T0, T0 + 5) == "token_rejected"
    assert tamper.classify_rejection(old, "", T0, T0 + 5) == "token_rejected"
    assert tamper.classify_rejection(old, previous, None, T0 + 5) == "token_rejected"


# ---- limiter ----------------------------------------------------------------------------------------------------

def test_limiter_five_per_rolling_window_then_one_summary():
    lim = tamper.RejectionLimiter()
    out = [lim.observe("kiro", T0 + i, tamper.iso(T0 + i)) for i in range(12)]
    assert [w for _, w, _ in out] == [True] * 5 + [False] * 7
    assert all(not due for _, _, due in out)
    assert lim.pending_summaries(T0 + 60) == []                         # first collapse at T0+5: due at T0+65
    [s] = lim.pending_summaries(T0 + 65)
    assert s == {"adapter": "kiro", "count": 7, "first_at": tamper.iso(T0 + 5), "last_at": tamper.iso(T0 + 11)}
    assert lim.pending_summaries(T0 + 200) == []


def test_limiter_flushes_due_summary_on_next_rejection_and_resumes():
    lim = tamper.RejectionLimiter()
    for i in range(6):
        lim.observe("codex", T0 + i, tamper.iso(T0 + i))
    _, write, due = lim.observe("codex", T0 + 70, tamper.iso(T0 + 70))
    assert write is True                                                # the earlier records left the window
    assert due == [{"adapter": "codex", "count": 1, "first_at": tamper.iso(T0 + 5), "last_at": tamper.iso(T0 + 5)}]


def test_limiter_bounds_distinct_adapter_names():
    lim = tamper.RejectionLimiter(max_adapters=4)
    names = [lim.observe(f"a{i}", T0, tamper.iso(T0))[0] for i in range(50)]
    assert names[:4] == ["a0", "a1", "a2", "a3"] and set(names[4:]) == {tamper.OVERFLOW}
    assert len(lim) == 5
    assert sum(w for _, w, _ in (lim.observe(f"b{i}", T0, tamper.iso(T0)) for i in range(50))) == 0
    assert lim.observe("new", T0 + 61, tamper.iso(T0 + 61))[0] == "new"     # idle names are released


# ---- TokenRejections ---------------------------------------------------------------------------------------------

def test_record_shape_is_content_free(daemon, rejections):
    presented = "presented-SECRET-token-value"
    rec = rejections.token_rejected("claude-code", "127.0.0.1:7391", presented)
    [stored] = _control(daemon.spool, "token_rejected")
    assert stored["event_id"] == rec["event_id"]
    assert stored["arguments"] == {"record": "token_rejected", "tamper_kind": "token_rejected",
                                   "adapter": "claude-code", "addr": "127.0.0.1:7391"}
    assert stored["disposition"] == "flag" and stored["received_at"] == tamper.iso(T0)
    assert stored["findings"][0]["rule"] == "control.token_rejected"
    text = json.dumps(stored)
    assert all(presented[i:i + 8] not in text for i in range(len(presented) - 7))
    for d in tamper._token_digests(presented):
        assert d not in text
    assert daemon.spool.verify()["ok"]


def test_collapse_after_five_and_summary_counts(daemon, rejections, clock):
    for i in range(9):
        clock.t = T0 + i
        rejections.token_rejected("kiro", "127.0.0.1:7391", "wrong")
    assert len(_control(daemon.spool, "token_rejected")) == 5
    assert rejections.pending_summaries(T0 + 30) == []
    [summary] = rejections.pending_summaries(T0 + 66)
    assert summary["arguments"]["count"] == 4 and summary["arguments"]["adapter"] == "kiro"
    assert summary["arguments"]["first_at"] == tamper.iso(T0 + 5)
    assert summary["arguments"]["last_at"] == tamper.iso(T0 + 8)
    assert len(_control(daemon.spool, "token_rejected_summary")) == 1


def test_rotation_grace_previous_token_is_expected(daemon, rejections, clock, tmp_path):
    path = tmp_path / "token"
    old = load_or_create_token(path)
    daemon.baseline = integrity.Baseline(token_sha256_previous=integrity.file_sha256(path))
    rotate_token(path)
    daemon.operator_actions.add(_action("token_rotate", T0))
    clock.t = T0 + 10
    rejections.token_rejected("claude-code", "a", old)
    rejections.token_rejected("claude-code", "a", "not-the-previous-token")
    assert len(_control(daemon.spool, "expected_after_rotate")) == 1
    assert len(_control(daemon.spool, "token_rejected")) == 1
    clock.t = T0 + 121                                                  # grace over: a Tamper_Event again
    rejections.token_rejected("claude-code", "a", old)
    assert len(_control(daemon.spool, "token_rejected")) == 2
    assert old not in json.dumps(list(daemon.spool.iter_records()))


def test_rotation_then_selftest_still_honours_rotation(daemon, rejections, clock, tmp_path):
    path = tmp_path / "token"
    old = load_or_create_token(path)
    daemon.baseline = integrity.Baseline(token_sha256_previous=integrity.file_sha256(path))
    daemon.operator_actions.add(_action("token_rotate", T0))
    daemon.operator_actions.add(_action("selftest", T0 + 5))
    clock.t = T0 + 10
    rejections.token_rejected("kiro", "a", old)
    assert len(_control(daemon.spool, "expected_after_rotate")) == 1


def test_selftest_grace_records_token_rejected(daemon, rejections, clock):
    daemon.operator_actions.add(_action("selftest", T0))
    clock.t = T0 + 3
    rec = rejections.token_rejected("cursor", "a", "deliberately-wrong")
    assert rec is not None and rec["arguments"]["adapter"] == "cursor"     # selftest checks for this record (14.3)
    assert daemon.operator_actions.explains("token_rejected", clock.t)["action"] == "selftest"   # attribution (14.7)


# ---- API: 401 unchanged, recorded with the adapter name ---------------------------------------------------------

@pytest.fixture
def server(daemon):
    s = ApiServer(daemon, TOKEN, "127.0.0.1", 0)
    s.start_background()
    yield s
    s.shutdown()


def _request(server, path, body: bytes | None, token: str | None, method="POST"):
    host, port = server.address
    req = urllib.request.Request(f"http://{host}:{port}{path}", data=body, method=method)
    req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


HOOK_BODY = json.dumps({"adapter": {"name": "claude-code", "version": "0.2.0"},
                        "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                    "tool_input": {"command": "ls"}}}).encode()


def test_api_401_unchanged_and_recorded(server, daemon):
    daemon.operator_actions = operator.OperatorActions(daemon.spool)
    daemon.tamper = tamper.TokenRejections(daemon)
    status, body = _request(server, "/interlock/v1/hooks/claude-code?format=claude-code", HOOK_BODY, "wrong")
    assert (status, body) == (401, b'{"error":"unauthorized"}')
    assert _request(server, "/interlock/v1/limits", None, None, method="GET") == (401, b'{"error":"unauthorized"}')
    recs = _control(daemon.spool, "token_rejected")
    assert [r["arguments"]["adapter"] for r in recs] == ["claude-code", "unknown"]
    host, port = server.address
    assert recs[0]["arguments"]["addr"] == f"{host}:{port}"
    assert "wrong" not in json.dumps(recs)
    assert _request(server, "/interlock/v1/hooks/claude-code?format=claude-code", HOOK_BODY, TOKEN)[0] == 200
    assert len(_control(daemon.spool, "token_rejected")) == 2


def test_api_without_tamper_behaves_as_before(server, daemon):
    assert getattr(daemon, "tamper", None) is None
    status, body = _request(server, "/interlock/v1/hooks/kiro", HOOK_BODY, "wrong")
    assert (status, body) == (401, b'{"error":"unauthorized"}')
    assert _control(daemon.spool, "token_rejected") == []


def test_api_recording_failure_keeps_the_401(server, daemon):
    class Broken:
        def token_rejected(self, **_):
            raise OSError("spool full")

    daemon.tamper = Broken()
    assert _request(server, "/interlock/v1/hooks/kiro", HOOK_BODY, "wrong") == (401, b'{"error":"unauthorized"}')
