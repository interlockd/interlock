import hashlib

import pytest
from conftest import POST_BASH, PRE_BASH, PRE_READ

from interlockd import records
from interlockd.integrity import Verification
from interlockd.normalize.kiro import normalize_kiro
from interlockd.pipeline import NoticeWindow
from interlockd.protection import ProtectionState


def test_tier0_allow_and_record(daemon):
    v = daemon.decide(normalize_kiro(PRE_READ))
    assert v.disposition == "allow" and v.tier == 0 and v.unjudged == [] and v.mode == "shadow"
    rec = daemon.repo.get_event(v.event_id)
    assert rec["tool_name"] == "read_file" and rec["tier"] == 0
    assert rec["state"]["user_messages"][-1]["text"] == "clean up the PR"  # filled from the transcript
    assert rec["permission_mode"] == "autopilot"
    assert rec["turn_no"] == 2
    assert rec["timing_ms"]["total"] > 0 and "store" not in rec["timing_ms"]  # stored before the store write
    assert v.timing_ms["store"] >= 0 and v.timing_ms["total_with_store"] >= v.timing_ms["total"]
    assert len(list(daemon.spool.iter_records())) == 1


def test_benign_shell_is_gated_but_clean(daemon):
    v = daemon.decide(normalize_kiro(PRE_BASH))  # git status --short
    assert v.tier == 2 and v.action_class == "build_or_test"
    assert v.disposition == "allow" and v.findings == [] and v.unjudged == []


def test_post_action_pass_with_result_hash(daemon):
    v = daemon.decide(normalize_kiro(POST_BASH))
    assert v.disposition == "pass"
    rec = daemon.repo.get_event(v.event_id)
    assert rec["evidence"] == {"exit_code": 0} and rec["result_sha256"] and rec["result_head"].startswith("Output:")


def test_ledger_counts(daemon):
    daemon.decide(normalize_kiro(PRE_READ))
    daemon.decide(normalize_kiro(PRE_BASH))
    daemon.decide(normalize_kiro(POST_BASH))
    s = daemon.ledger.summary("sess_test-0001")
    assert s["calls"] == 2 and s["counters"]["class:shell"] == 1 and s["counters"]["tool:read_file"] == 1
    assert daemon.repo.get_session("sess_test-0001")["calls"] == 2


# ---- compromised enforcement point (Requirements 5.3, 5.4, 5.12, 6.1, 6.2, 6.10) ---------------------------------

SHA_A, SHA_B = hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()
SHIM = "/home/dev/.interlock/adapters/kiro/interlock-hook.sh"


def _protected(daemon, mode="enforce"):
    daemon.mode = mode
    daemon.protection = ProtectionState(daemon.settings.home, daemon.spool, None, lambda: daemon.mode,
                                        harnesses=lambda: ["kiro", "claude-code"])
    return daemon


def _modified(harness="kiro", problem="shim_modified"):
    return Verification(harness, problem, SHA_A, SHA_B, SHIM, (problem,))


def _control(daemon, record):
    return [r for r in daemon.spool.iter_records(reverse=False) if r.get("arguments", {}).get("record") == record]


def _tamper_findings(v):
    return [f for f in v.findings if f.category == "control.hook_tamper"]


def test_bare_daemon_ignores_integrity(daemon):
    """No protection wiring: the Verification changes nothing (and the policy verdict stands)."""
    v = daemon.decide(normalize_kiro(PRE_READ), integrity=_modified())
    assert v.disposition == "allow" and v.notice is None and _tamper_findings(v) == []
    assert _control(daemon, "tamper_event") == []


def test_enforce_blocks_with_notice_once_per_window_and_one_event(daemon):
    _protected(daemon, "enforce")
    first = daemon.decide(normalize_kiro(PRE_READ), integrity=_modified())
    assert first.disposition == "block" and first.mode == "enforce"
    n = first.notice
    assert "kiro" in n and "shim_modified" in n and n.count("enforcement_point") == 1
    assert "interlock doctor" in n and "interlock init" in n and "interlock ack" in n and "NOT executed" in n
    [f] = _tamper_findings(first)
    assert (f.rule, f.subject, f.path) == ("control.shim_modified", "kiro", "hook")
    assert daemon.protection.harness_state("kiro") == "compromised"
    second = daemon.decide(normalize_kiro(PRE_BASH), integrity=_modified())
    assert second.disposition == "block" and second.notice is None              # windowed: no text, still blocked
    assert "shim_modified" in second.reason and len(_tamper_findings(second)) == 1
    [ev] = _control(daemon, "tamper_event")                                       # one Tamper_Event per change
    a = ev["arguments"]
    assert (a["tamper_kind"], a["harness"], a["path"]) == ("shim_modified", "kiro", SHIM)
    assert (a["expected_sha256"], a["observed_sha256"]) == (SHA_A, SHA_B)
    assert ev["tool_name"] == "interlock.verifier"
    recs = {r["event_id"]: r for r in daemon.spool.iter_records()}
    assert recs[first.event_id]["findings"][-1]["category"] == "control.hook_tamper"   # flagged decision record
    assert daemon.spool.verify()["ok"]


def test_repaired_shim_keeps_the_harness_compromised(daemon):
    """Once raised, the reason persists until ack/init: an intact Verification still gets the block."""
    _protected(daemon, "enforce")
    daemon.decide(normalize_kiro(PRE_READ), integrity=_modified())
    v = daemon.decide(normalize_kiro(PRE_READ), integrity=Verification("kiro", ""))
    assert v.disposition == "block" and _tamper_findings(v)


def test_shadow_keeps_the_policy_verdict_and_adds_the_notice(daemon):
    _protected(daemon, "shadow")
    v = daemon.decide(normalize_kiro(PRE_READ), integrity=_modified(problem="hook_removed"))
    assert v.disposition == "allow" and v.mode == "shadow"
    assert "hook_removed" in v.notice and "enforcement_point" in v.notice and "NOT executed" not in v.notice
    assert len(_tamper_findings(v)) == 1
    again = daemon.decide(normalize_kiro(PRE_READ), integrity=_modified(problem="hook_removed"))
    assert again.disposition == "allow" and again.notice is None and _tamper_findings(again)


def test_post_action_and_other_harnesses_are_not_overridden(daemon):
    _protected(daemon, "enforce")
    daemon.decide(normalize_kiro(PRE_READ), integrity=_modified())
    post = daemon.decide(normalize_kiro(POST_BASH), integrity=Verification("kiro", ""))
    assert post.disposition == "pass" and post.notice is None                    # the tool already ran
    other = daemon.decide(normalize_kiro(PRE_READ), integrity=Verification("claude-code", ""))
    assert other.disposition == "allow" and _tamper_findings(other) == []


def test_home_reasons_do_not_trigger_the_override(daemon):
    _protected(daemon, "enforce")
    daemon.protection.add_reason("home", "token_permissions", "", records.now_iso())
    v = daemon.decide(normalize_kiro(PRE_READ), integrity=Verification("kiro", ""))
    assert v.disposition == "allow" and _tamper_findings(v) == []


def test_no_baseline_is_recorded_once_per_harness(daemon):
    _protected(daemon, "enforce")
    for _ in range(3):
        v = daemon.decide(normalize_kiro(PRE_READ), integrity=Verification("kiro", "no_baseline"))
        assert v.disposition == "allow" and _tamper_findings(v) == []
    daemon.decide(normalize_kiro(PRE_READ), integrity=Verification("claude-code", "no_baseline"))
    assert [r["arguments"]["harness"] for r in _control(daemon, "no_baseline")] == ["kiro", "claude-code"]
    assert daemon.protection.reasons() == [] and _control(daemon, "protection_state") == []


def test_operator_explained_change_raises_nothing(daemon):
    class Ops:
        def explains(self, kind, now=None):
            return {"action": "init"} if kind == "enforcement_point" else None

    _protected(daemon, "enforce")
    daemon.operator_actions = Ops()
    v = daemon.decide(normalize_kiro(PRE_READ), integrity=_modified())
    assert v.disposition == "allow" and daemon.protection.reasons() == []
    assert _control(daemon, "tamper_event") == []


def test_gateway_calls_follow_any_compromised_harness(daemon):
    from interlockd.models import InterlockEvent

    _protected(daemon, "enforce")
    daemon.decide(normalize_kiro(PRE_READ), integrity=_modified(harness="claude-code"))
    ev = {"kind": "pre_action", "adapter": {"name": "mcp-proxy", "version": "t"}, "session_hint": "g1",
          "identity": {"agent_type": "mcp-proxy"}, "tool_call": {"name": "mcp__fake__echo", "arguments": {}},
          "context": {"cwd": "/ws/proj"}, "capabilities": {"ask": False, "rewrite": False, "withhold": True}}
    v = daemon.decide(InterlockEvent.model_validate(ev))
    assert v.disposition == "block" and "claude-code" in v.reason and _tamper_findings(v)
    post = daemon.decide(InterlockEvent.model_validate({**ev, "kind": "post_action", "result": {"content": "ok"}}))
    assert _tamper_findings(post) and post.notice is None        # the notice went out with the block this window


def test_policy_lockdown_keeps_its_notice(daemon):
    from interlockd.policy.pin import DENY_ALL_NOTICE

    class Guard:
        lockdown = True
        home = daemon.settings.home

        def targets_policy(self, paths):
            return False

    _protected(daemon, "enforce")
    daemon.policy_guard = Guard()
    v = daemon.decide(normalize_kiro(PRE_READ), integrity=_modified())
    assert v.disposition == "block" and v.notice == DENY_ALL_NOTICE.format(path=str(daemon.settings.home / "policy.yaml"))
    assert {f.rule for f in _tamper_findings(v)} == {"control.policy_modified", "control.shim_modified"}


def test_notice_window():
    t = [0.0]
    w = NoticeWindow(clock=lambda: t[0])
    assert w.take("kiro", "shim_modified") and not w.take("kiro", "shim_modified")
    assert w.take("kiro", "hook_removed") and w.take("cursor", "shim_modified")   # per (harness, reason)
    t[0] = 59.9
    assert not w.take("kiro", "shim_modified")
    t[0] = 60.0
    assert w.take("kiro", "shim_modified")


@pytest.fixture
def wired(daemon, settings, tmp_path):
    """A daemon wired as `interlock serve` wires it, with one installed claude-code shim."""
    from interlockd.auth import load_or_create_token
    from interlockd.cli import CLAUDE_SHIM_SRC, attach_integrity
    from interlockd.onboard import Manifest

    shim = settings.home / "adapters" / "claude-code" / "interlock-hook.sh"
    shim.parent.mkdir(parents=True)
    shim.write_text(CLAUDE_SHIM_SRC.read_text(encoding="utf-8").replace("__HARNESS__", "claude-code"),
                    encoding="utf-8")
    hooks = tmp_path / "settings.json"
    hooks.write_text(f'{{"hooks": {{"PreToolUse": [{{"hooks": [{{"command": "sh {shim}"}}]}}]}}}}', encoding="utf-8")
    Manifest(created_at="2026-10-18T00:00:00Z",
             hooks=[{"harness": "claude-code", "file": str(hooks), "marker": str(shim), "created": False}]).save(settings.home)
    load_or_create_token(settings.token_path)
    attach_integrity(daemon, settings.home, None)
    daemon.mode = "enforce"
    return daemon, shim


def test_hot_path_event_is_not_recorded_again_by_the_watch(wired, settings):
    from interlockd.normalize.claude_code import normalize_claude_code
    from interlockd.watch import HookWatch

    daemon, shim = wired
    w = HookWatch(daemon, settings.home)
    assert w.check() == []
    shim.write_text(shim.read_text(encoding="utf-8") + "\nexit 0\n", encoding="utf-8")
    pre = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": "/ws/proj", "tool_name": "Bash",
           "tool_input": {"command": "ls"}}
    v = daemon.decide(normalize_claude_code(pre, agent_type="claude-code"),
                      integrity=daemon.verifier.verify("claude-code", str(shim)))
    assert v.disposition == "block" and "enforcement_point" in v.notice
    recs = w.check()
    assert [r["arguments"]["record"] for r in recs] == ["shim_repaired"]     # repaired; no second Tamper_Event
    assert len([r for r in _control(daemon, "tamper_event") if r["arguments"]["tamper_kind"] == "shim_modified"]) == 1
    assert w.check() == []
    v = daemon.decide(normalize_claude_code(pre, agent_type="claude-code"),
                      integrity=daemon.verifier.verify("claude-code", str(shim)))
    assert v.disposition == "block"                                             # compromised until ack / init
    assert daemon.spool.verify()["ok"]
