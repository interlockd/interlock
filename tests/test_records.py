"""Control record builders: existing audit schema, allowlisted arguments, no content, tamper finding shape."""

from __future__ import annotations

import json

import pytest

from interlockd import __version__, records
from interlockd.store.spool import Spool

SHA = "a" * 64
MARK = "SECRET-MARKER-91f3"
M = {"mode": "enforce", "policy_sha256": "p" * 64, "at": "2026-10-17T10:00:00.000Z"}

SAMPLES = {
    "tamper_event": lambda: records.tamper_event("shim_modified", "claude-code", "/h/adapters/claude-code/hook.sh",
                                                 SHA, "b" * 64, **M),
    "operator_action": lambda: records.operator_action("stop", "", "stopped", grace_s=120, **M),
    "operator_ack": lambda: records.operator_ack(["claude-code:shim_modified", "home:policy_modified"], **M),
    "protection_state": lambda: records.protection_state("home", "protected", "compromised", ["home:token_modified"],
                                                         "01JD0000000000000000000000", **M),
    "daemon_started": lambda: records.daemon_started(True, "restart", **M),
    "daemon_unexpected_exit": lambda: records.daemon_unexpected_exit(4242, "0.1.8", **M),
    "calls_unjudged": lambda: records.calls_unjudged(unjudged=2, tamper_daemon_lost=1, span_from="2026-10-17T09:00:00Z",
                                                     span_to="2026-10-17T09:30:00Z", **M),
    "policy_baseline_set": lambda: records.policy_baseline_set("policy", "/h/policy.yaml", SHA, **M),
    "policy_modified": lambda: records.policy_modified("policy", "/h/policy.yaml", SHA, "c" * 64, changed=["mode"], **M),
    "policy_restored": lambda: records.policy_restored("managed", "/h/managed-policy.yaml", SHA, **M),
    "token_rejected": lambda: records.token_rejected("claude-code", "127.0.0.1:7391", **M),
    "token_rejected_summary": lambda: records.token_rejected_summary("kiro", 7, "2026-10-17T10:00:00Z",
                                                                     "2026-10-17T10:00:59Z", **M),
    "expected_after_rotate": lambda: records.expected_after_rotate("kiro", "127.0.0.1:7391", **M),
    "shim_repaired": lambda: records.shim_repaired("codex", "/h/adapters/codex/hook.sh", SHA, **M),
    "shim_repair_failed": lambda: records.shim_repair_failed("codex", "/h/adapters/codex/hook.sh", "EACCES", **M),
    "hook_restored": lambda: records.hook_restored("codex", "/u/.codex/hooks.json", "hook_removed", **M),
    "state_unreadable": lambda: records.state_unreadable("protection-state.json", "state_unreadable:nesting", **M),
    "state_permissions": lambda: records.state_permissions("stop-marker.json", "state_permissions:mode", **M),
    "state_write_failed": lambda: records.state_write_failed("integrity-baseline.json", "ENOSPC", **M),
    "identity_restored": lambda: records.identity_restored("/h/identity", **M),
    "notify_failed": lambda: records.notify_failed("osascript_failed", **M),
    "no_baseline": lambda: records.no_baseline("windsurf", **M),
    "baseline_created": lambda: records.baseline_created("/h/integrity-baseline.json", **M),
}
EMPTY_FIELDS = ("cwd", "state", "answers", "guardrails", "result_summary", "result_status", "unjudged")


def test_every_kind_has_a_sample():
    assert set(SAMPLES) == set(records.ARGUMENT_KEYS) == set(records.BUILDERS)


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_schema_and_allowlist(name):
    rec = SAMPLES[name]()
    assert rec["kind"] == "control" and rec["adapter"] == "interlock" and rec["session_id"] == "interlock-control"
    assert rec["tool_name"].startswith("interlock.") and rec["tier"] == 0
    assert rec["normalized"] == {"action_class": "control"} and rec["timing_ms"] == {}
    assert rec["mode"] == "enforce" and rec["policy_sha256"] == "p" * 64 and rec["daemon_version"] == __version__
    assert rec["received_at"] == M["at"] and rec["event_id"]
    assert not any(k in rec for k in EMPTY_FIELDS)
    assert rec["arguments"]["record"] == name
    assert set(rec["arguments"]) <= records.ARGUMENT_KEYS[name]
    tamper = rec["arguments"].get("tamper_kind")
    assert rec["disposition"] == ("flag" if tamper else "allow")
    if tamper:
        assert tamper in records.TAMPER_KINDS and rec["reason"] == tamper
    else:
        assert rec["findings"] == []


@pytest.mark.parametrize("name", sorted(n for n in SAMPLES if SAMPLES[n]()["arguments"].get("tamper_kind")))
def test_tamper_finding_shape(name):
    rec = SAMPLES[name]()
    kind = rec["arguments"]["tamper_kind"]
    [f] = rec["findings"]
    assert f == {"category": "control.hook_tamper", "severity": "high", "rule": f"control.{kind}",
                 "detector": rec["tool_name"], "path": "hook", "subject": rec["agent_type"] or "home", "score": 1.0}


def test_tamper_event_subject_is_the_harness():
    rec = SAMPLES["tamper_event"]()
    assert rec["agent_type"] == "claude-code" and rec["findings"][0]["subject"] == "claude-code"
    assert rec["tool_name"] == "interlock.watch"
    assert records.tamper_event("hook_removed", "kiro", "/x", detector="verifier")["tool_name"] == "interlock.verifier"


def test_free_text_never_reaches_the_record():
    """Reasons, codes, digests and key names that are not fixed identifiers are replaced, not copied."""
    text = f"rm -rf ~ # {MARK} with spaces"
    recs = [
        records.tamper_event("shim_modified", "claude-code", "/h/s.sh", MARK, text, reason=text),
        records.operator_action(text, via=text, caused_by=text),
        records.operator_ack([text]),
        records.protection_state("home", text, text, [text], text),
        records.daemon_started(True, text),
        records.daemon_unexpected_exit(1, text),
        records.policy_modified("policy", "/h/policy.yaml", MARK, MARK, added=[text], changed=["mode", {"x": MARK}]),
        records.shim_repair_failed("codex", "/h/s.sh", text),
        records.state_unreadable("f.json", text),
        records.notify_failed(text),
        records.calls_unjudged(span_from=MARK, span_to=text),
    ]
    for rec in recs:
        assert MARK not in json.dumps(rec), rec["arguments"]["record"]
    assert recs[0]["arguments"]["expected_sha256"] == "" and recs[0]["arguments"]["reason"] == "invalid"
    assert recs[6]["arguments"]["changed"] == ["mode", "invalid"]


def test_trailing_newline_does_not_pass_a_validator():
    """`$` matches before a final newline; every code, harness, digest, key and time check is anchored at the end."""
    nl = "MK000000000000\n"
    assert records.shim_repair_failed("codex", "/h/s.sh", nl)["arguments"]["cause"] == "invalid"
    assert records.no_baseline("kiro\n")["arguments"]["harness"] == "invalid"
    assert records.shim_repaired("codex", "/h/s.sh", SHA + "\n")["arguments"]["sha256"] == ""
    rec = records.policy_modified("policy", "/h/policy.yaml", SHA, SHA, changed=["mode\n"])
    assert rec["arguments"]["changed"] == ["invalid"]
    rec = records.calls_unjudged(unjudged=1, span_from="2026-10-17T09:00:00Z\n", span_to="2026-10-17T09:30:00Z")
    assert rec["arguments"]["span_from"] == "" and rec["arguments"]["span_to"] == "2026-10-17T09:30:00Z"


def test_invalid_kinds_and_keys_are_rejected():
    with pytest.raises(ValueError):
        records.tamper_event("not_a_kind", "kiro", "/x")
    with pytest.raises(ValueError):
        records.policy_baseline_set("other", "/x", SHA)
    with pytest.raises(ValueError):
        records._base("no_baseline", component="verifier", arguments={"harness": "kiro", "cwd": "/work"})


def test_adapter_name_is_truncated_and_defaulted():
    long = records.token_rejected("x" * 200, "127.0.0.1:7391")
    assert long["arguments"]["adapter"] == "x" * 64
    assert records.token_rejected("", "127.0.0.1:7391")["arguments"]["adapter"] == "unknown"
    assert "\n" not in records.token_rejected("a\nb", "addr")["arguments"]["adapter"]


def test_records_chain_in_the_spool(tmp_path):
    spool = Spool(tmp_path / "spool", fsync=False)
    for make in SAMPLES.values():
        spool.append(make())
    v = spool.verify()
    assert v["ok"] and v["records"] == len(SAMPLES)


def test_meta_reads_the_daemon(daemon):
    assert records.meta(daemon) == {"mode": daemon.mode, "policy_sha256": daemon.policy_sha256}
