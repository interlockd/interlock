from conftest import POST_BASH, PRE_BASH, PRE_READ

from interlockd.normalize.kiro import normalize_kiro


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
