"""ProtectionState: derivation, durable change records, persistence, restore, observing, untrusted documents."""

from __future__ import annotations

import json
import os
import random

import pytest

from interlockd import protection, statefile
from interlockd.protection import HOME, ProtectionState
from interlockd.store.spool import Spool

HARNESSES = ["claude-code", "kiro", "copilot-cli"]
AT = "2026-10-17T10:00:00Z"
EID = "01JD0000000000000000000000"


class Otel:
    def __init__(self):
        self.recs: list[dict] = []

    def submit(self, rec: dict) -> None:
        self.recs.append(rec)


def make(tmp_path, mode="enforce", *, load=False, **kw):
    spool = Spool(tmp_path / "spool", fsync=False)
    otel = Otel()
    mode_box = {"mode": mode}
    args = (tmp_path, spool, otel, lambda: mode_box["mode"])
    kw.setdefault("harnesses", lambda: HARNESSES)
    ps = ProtectionState.load(*args, **kw) if load else ProtectionState(*args, **kw)
    return ps, spool, otel, mode_box


def control(spool: Spool, record: str) -> list[dict]:
    recs = [r for r in spool.iter_records(reverse=False) if r.get("kind") == "control"]
    return [r for r in recs if r["arguments"]["record"] == record]


def test_constants_match_shared_strategies():
    from props import strategies

    assert protection.STATES == strategies.STATES
    assert protection.HARNESS_REASONS == strategies.HARNESS_REASONS
    assert protection.HOME_REASONS == strategies.HOME_REASONS
    assert protection.EP_REASONS == protection.HARNESS_REASONS


def test_change_is_recorded_persisted_and_notified_before_return(tmp_path):
    ps, spool, otel, _ = make(tmp_path)
    seen = []

    def sub(snap):
        # by the time subscribers run, the record and the document are already durable
        doc = json.loads((tmp_path / protection.FILE).read_text())
        seen.append((snap["aggregate"], doc["reasons"], len(control(spool, "protection_state"))))

    ps.subscribe(sub)
    assert ps.add_reason("claude-code", "shim_modified", EID, AT) is True

    doc = statefile.read_state(tmp_path / protection.FILE, {"reasons": dict})
    assert doc["reasons"] == {"claude_code__shim_modified": AT}
    assert doc["events"] == {"claude_code__shim_modified": EID}
    assert doc["state_claude_code"] == "compromised" and doc["state_kiro"] == "protected"
    assert doc["aggregate"] == "compromised"
    assert seen == [("compromised", {"claude_code__shim_modified": AT}, 1)]

    (rec,) = control(spool, "protection_state")
    assert rec["arguments"] == {"record": "protection_state", "subject": "claude-code", "previous": "protected",
                                "new": "compromised", "reasons": ["claude-code:shim_modified"], "caused_by": EID}
    assert [r["event_id"] for r in otel.recs] == [rec["event_id"]]
    assert ps.harness_state("claude-code") == "compromised"
    assert ps.harness_state("kiro") == "protected"
    assert ps.aggregate() == "compromised"
    assert spool.verify()["ok"]


def test_duplicate_reason_records_nothing_and_bad_reason_raises(tmp_path):
    ps, spool, _, _ = make(tmp_path)
    assert ps.add_reason(HOME, "token_modified", EID, AT)
    assert ps.add_reason(HOME, "token_modified", EID, AT) is False
    assert len(control(spool, "protection_state")) == 1
    with pytest.raises(ValueError):
        ps.add_reason(HOME, "shim_modified", EID, AT)
    with pytest.raises(ValueError):
        ps.add_reason("kiro", "token_modified", EID, AT)
    assert ps.clear(lambda r: False, caused_by="x") == []
    assert len(control(spool, "protection_state")) == 1


def test_restore_at_start_keeps_reasons(tmp_path):
    ps, spool, _, _ = make(tmp_path)
    ps.add_reason("kiro", "hook_removed", EID, AT)
    ps.add_reason(HOME, "policy_modified", EID, "2026-10-17T10:01:00Z")
    written = len(control(spool, "protection_state"))

    ps2, spool2, _, _ = make(tmp_path, load=True)
    assert ps2.harness_state("kiro") == "compromised"
    assert ps2.harness_state("claude-code") == "protected"
    assert ps2.aggregate() == "compromised"
    snap = ps2.snapshot()
    assert snap["harnesses"]["kiro"]["reasons"] == [{"reason": "hook_removed", "detected_at": AT}]
    assert snap["home_reasons"] == [{"reason": "policy_modified", "detected_at": "2026-10-17T10:01:00Z"}]
    assert snap["last_tamper_at"] == "2026-10-17T10:01:00Z"
    assert {r.event_id for r in ps2.reasons()} == {EID}
    assert len(control(spool2, "protection_state")) == written   # restoring is not a change


@pytest.mark.parametrize(("mode", "state"), [("enforce", "protected"), ("shadow", "observing")])
def test_no_document_starts_from_mode(tmp_path, mode, state):
    ps, spool, _, _ = make(tmp_path, mode, load=True)
    assert ps.aggregate() == state
    assert all(ps.harness_state(h) == state for h in HARNESSES)
    snap = ps.snapshot()
    assert snap["home_reasons"] == [] and snap["last_tamper_at"] is None
    assert set(snap["harnesses"]) == set(HARNESSES)
    assert list(spool.iter_records()) == []
    assert not (tmp_path / protection.FILE).exists()


def test_observing_interplay(tmp_path):
    ps, spool, _, _ = make(tmp_path)
    ps.add_reason("kiro", "shim_relocated", EID, AT)
    ps.set_observing(True, caused_by="op1")                   # shadow while compromised: stays compromised (11.3)
    assert ps.aggregate() == "compromised"
    assert ps.harness_state("kiro") == "compromised"
    assert ps.harness_state("claude-code") == "observing"
    ps.set_observing(True, caused_by="op1")                   # no change, no record
    assert len(control(spool, "protection_state")) == 2

    cleared = ps.clear(lambda r: r.reason in protection.EP_REASONS, caused_by="op2")
    assert [r.code for r in cleared] == ["kiro:shim_relocated"]
    assert ps.aggregate() == "observing"                      # the retained observing reason takes effect (11.11)
    last = control(spool, "protection_state")[-1]["arguments"]
    assert (last["subject"], last["previous"], last["new"], last["reasons"]) == ("kiro", "compromised",
                                                                                   "observing", [])

    ps2, _, _, _ = make(tmp_path, load=True)                  # the observing flag survives a restart
    assert ps2.aggregate() == "observing"
    ps2.set_observing(False, caused_by="op3")
    assert ps2.aggregate() == "protected"


def test_unreadable_document_is_compromised_and_left_in_place(tmp_path):
    path = tmp_path / protection.FILE
    path.write_text("{not json")
    os.chmod(path, 0o600)
    ps, spool, _, _ = make(tmp_path, load=True)

    assert ps.aggregate() == "compromised"
    assert [r.code for r in ps.reasons()] == ["home:state_unreadable"]
    (rec,) = control(spool, "state_unreadable")
    assert rec["arguments"]["file"] == str(path) and rec["arguments"]["reason"] == "state_unreadable:invalid_json"
    assert ps.reasons()[0].event_id == rec["event_id"]
    assert len(control(spool, "protection_state")) == 1
    assert path.read_text() == "{not json"

    ps.add_reason("kiro", "hook_removed", EID, AT)            # still held: file untouched
    assert path.read_text() == "{not json"

    ps.clear(lambda r: r.reason == "state_unreadable", caused_by="ack")   # ack lifts the hold
    doc = statefile.read_state(path, {"reasons": dict})
    assert doc["reasons"] == {"kiro__hook_removed": AT}


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_widened_document_mode_is_untrusted(tmp_path):
    ps, _, _, _ = make(tmp_path)
    ps.add_reason("kiro", "hook_removed", EID, AT)
    path = tmp_path / protection.FILE
    before = path.read_bytes()
    os.chmod(path, 0o644)

    ps2, spool2, _, _ = make(tmp_path, load=True)
    assert [r.code for r in ps2.reasons()] == ["home:state_unreadable"]
    assert control(spool2, "state_permissions")[0]["arguments"]["check"] == "state_permissions:mode"
    assert path.read_bytes() == before


def test_malformed_reason_entry_is_unreadable(tmp_path):
    path = tmp_path / protection.FILE
    statefile.write_state(path, {"observing": False, "reasons": {"kiro__token_modified": AT}, "events": {}})
    ps, spool, _, _ = make(tmp_path, load=True)
    assert [r.code for r in ps.reasons()] == ["home:state_unreadable"]
    assert control(spool, "state_unreadable")[0]["arguments"]["reason"] == "state_unreadable:bad_reason"


def test_write_failure_is_recorded_and_memory_stays_authoritative(tmp_path):
    (tmp_path / protection.FILE).mkdir()                      # rename over a directory fails
    ps, spool, _, _ = make(tmp_path)
    assert ps.add_reason(HOME, "token_missing", EID, AT)
    assert ps.aggregate() == "compromised"
    (rec,) = control(spool, "state_write_failed")
    assert rec["arguments"]["file"].endswith(protection.FILE)
    assert not (tmp_path / (protection.FILE + ".tmp")).exists()


def test_subscriber_errors_do_not_break_changes_and_unsubscribe(tmp_path):
    ps, _, _, _ = make(tmp_path)
    calls = []

    def boom(_snap):
        raise RuntimeError("x")

    ps.subscribe(boom)
    unsub = ps.subscribe(lambda s: calls.append(s["aggregate"]))
    assert ps.add_reason(HOME, "identity_missing", EID, AT)
    unsub()
    ps.clear(lambda r: True, caused_by="ack")
    assert calls == ["compromised"]


def test_records_carry_no_content(tmp_path):
    ps, spool, _, _ = make(tmp_path)
    ps.add_reason("kiro", "shim_modified", "not an id; rm -rf /", "garbage time")
    (rec,) = control(spool, "protection_state")
    assert rec["arguments"]["caused_by"] == ""
    assert "rm -rf" not in json.dumps(rec)
    assert rec.get("cwd") in (None, "") and "state" not in rec


def _model_states(reasons: set[tuple[str, str]], shadow: bool) -> tuple[dict[str, str], str]:
    base = "observing" if shadow else "protected"
    per = {h: ("compromised" if any(s == h for s, _ in reasons) else base) for h in HARNESSES}
    return per, ("compromised" if reasons else base)


def test_sequence_matches_dict_model(tmp_path):
    rng = random.Random(20261017)
    ps, spool, _, mode_box = make(tmp_path)
    model: set[tuple[str, str]] = set()
    expected_records = 0
    subjects = [*HARNESSES, HOME]
    for i in range(300):
        if i % 50 == 0:
            mode_box["mode"] = rng.choice(["enforce", "shadow"])
        subject = rng.choice(subjects)
        pool = sorted(protection.HOME_REASONS if subject == HOME else protection.HARNESS_REASONS)
        if rng.random() < 0.6:
            reason = rng.choice(pool)
            added = ps.add_reason(subject, reason, EID, AT)
            assert added == ((subject, reason) not in model)
            if added:
                model.add((subject, reason))
                expected_records += 1
        else:
            reason = rng.choice(pool)
            gone = ps.clear(lambda r, s=subject, x=reason: (r.subject, r.reason) == (s, x), caused_by="op")
            assert bool(gone) == ((subject, reason) in model)
            if gone:
                model.discard((subject, reason))
                expected_records += 1
        per, agg = _model_states(model, mode_box["mode"] == "shadow")
        assert {h: ps.harness_state(h) for h in HARNESSES} == per
        assert ps.aggregate() == agg
        recs = control(spool, "protection_state")
        assert len(recs) == expected_records
        if recs:
            assert sorted(recs[-1]["arguments"]["reasons"]) == sorted(f"{s}:{r}" for s, r in model)

    ps2, _, _, _ = make(tmp_path, mode_box["mode"], load=True)
    assert {(r.subject, r.reason) for r in ps2.reasons()} == model
    assert ps2.snapshot()["aggregate"] == ps.snapshot()["aggregate"]
    assert spool.verify()["ok"]
