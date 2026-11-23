"""Property 20: control records keep the audit chain and break it when altered (Spool.verify).

A spool holding a mix of ordinary decision records and every ``records.*`` control kind verifies intact; editing
or removing the record at position ``i`` makes ``verify()`` report the break at that position (the record that
follows a removed one, for a removal).

Removing the newest record is excluded: the spool documents that truncating the tail is only detectable against an
anchored head (``interlock audit head``), not by ``verify()`` alone. Stripping ``hash`` from the very first record
makes it indistinguishable from a pre-chaining (legacy) record, so that break is reported at the next record.
"""

from __future__ import annotations

import json
from pathlib import Path

from hypothesis import example, given
from hypothesis import strategies as st

from interlockd import records
from interlockd.store.spool import Spool, split_lines

from .strategies import PROPS, harnesses, iso_timestamps, sha256_hex

# --- record generators --------------------------------------------------------------------------------------------

_SHA = "a" * 64


def _meta() -> st.SearchStrategy[dict]:
    return st.fixed_dictionaries({
        "mode": st.sampled_from(("shadow", "enforce")),
        "policy_sha256": sha256_hex(),
        "at": iso_timestamps(),
    })


# One call per builder kind (mirrors tests/test_records.py::SAMPLES); `m` is the generated record metadata.
CONTROL = {
    "tamper_event": lambda m, h: records.tamper_event("shim_modified", h, f"/h/adapters/{h}/hook.sh", _SHA,
                                                      "b" * 64, **m),
    "operator_action": lambda m, h: records.operator_action("stop", "", "stopped", grace_s=120, **m),
    "operator_ack": lambda m, h: records.operator_ack([f"{h}:shim_modified", "home:policy_modified"], **m),
    "protection_state": lambda m, h: records.protection_state("home", "protected", "compromised",
                                                              ["home:token_modified"], "01JD0000000000000000000000",
                                                              **m),
    "daemon_started": lambda m, h: records.daemon_started(True, "restart", **m),
    "daemon_unexpected_exit": lambda m, h: records.daemon_unexpected_exit(4242, "0.1.8", **m),
    "calls_unjudged": lambda m, h: records.calls_unjudged(unjudged=2, tamper_daemon_lost=1,
                                                          span_from="2026-10-17T09:00:00Z",
                                                          span_to="2026-10-17T09:30:00Z", **m),
    "policy_baseline_set": lambda m, h: records.policy_baseline_set("policy", "/h/policy.yaml", _SHA, **m),
    "policy_modified": lambda m, h: records.policy_modified("policy", "/h/policy.yaml", _SHA, "c" * 64,
                                                            changed=["mode"], **m),
    "policy_restored": lambda m, h: records.policy_restored("managed", "/h/managed-policy.yaml", _SHA, **m),
    "token_rejected": lambda m, h: records.token_rejected(h, "127.0.0.1:7391", **m),
    "token_rejected_summary": lambda m, h: records.token_rejected_summary(h, 7, "2026-10-17T10:00:00Z",
                                                                          "2026-10-17T10:00:59Z", **m),
    "expected_after_rotate": lambda m, h: records.expected_after_rotate(h, "127.0.0.1:7391", **m),
    "shim_repaired": lambda m, h: records.shim_repaired(h, f"/h/adapters/{h}/hook.sh", _SHA, **m),
    "shim_repair_failed": lambda m, h: records.shim_repair_failed(h, f"/h/adapters/{h}/hook.sh", "EACCES", **m),
    "hook_restored": lambda m, h: records.hook_restored(h, "/u/.codex/hooks.json", "hook_removed", **m),
    "state_unreadable": lambda m, h: records.state_unreadable("protection-state.json", "state_unreadable:nesting",
                                                              **m),
    "state_permissions": lambda m, h: records.state_permissions("stop-marker.json", "state_permissions:mode", **m),
    "state_write_failed": lambda m, h: records.state_write_failed("integrity-baseline.json", "ENOSPC", **m),
    "identity_restored": lambda m, h: records.identity_restored("/h/identity", **m),
    "notify_failed": lambda m, h: records.notify_failed("osascript_failed", **m),
    "no_baseline": lambda m, h: records.no_baseline(h, **m),
    "baseline_created": lambda m, h: records.baseline_created("/h/integrity-baseline.json", **m),
}


def control_records() -> st.SearchStrategy[dict]:
    return st.builds(lambda kind, m, h: CONTROL[kind](m, h), st.sampled_from(sorted(CONTROL)), _meta(), harnesses())


def decision_records() -> st.SearchStrategy[dict]:
    """Ordinary pre/post-action decision records in the existing spool schema."""
    return st.fixed_dictionaries({
        "event_id": st.text(alphabet="0123456789ABCDEFGHJKMNPQRSTVWXYZ", min_size=26, max_size=26),
        "received_at": iso_timestamps(),
        "kind": st.sampled_from(("pre_action", "post_action")),
        "adapter": harnesses(),
        "agent_type": harnesses(),
        "session_id": st.text(min_size=1, max_size=20),
        "tool_name": st.sampled_from(("Bash", "execute_bash", "Write", "Read", "mcp__fs__read")),
        "arguments": st.fixed_dictionaries({"command": st.text(max_size=60)}),
        "cwd": st.text(max_size=30),
        "tier": st.integers(0, 2),
        "disposition": st.sampled_from(("allow", "ask", "block", "flag")),
        "mode": st.sampled_from(("shadow", "enforce")),
        "reason": st.text(max_size=40),
        "findings": st.just([]),
        "timing_ms": st.fixed_dictionaries({"total": st.floats(0, 50, allow_nan=False)}),
    })


@st.composite
def mixed_sequences(draw) -> list[dict]:
    """Every control kind at least once, interleaved with decision records in a random order."""
    every_kind = [draw(st.builds(CONTROL[k], _meta(), harnesses())) for k in sorted(CONTROL)]
    extra = draw(st.lists(st.one_of(decision_records(), control_records()), min_size=1, max_size=15))
    return draw(st.permutations(every_kind + extra))


# --- pinned counterexamples ---------------------------------------------------------------------------------------

_PIN_META = {"mode": "enforce", "policy_sha256": "0" * 64, "at": "2026-10-17T10:00:00Z"}


def _pinned_decision(command: str) -> dict:
    return {"event_id": "0" * 26, "received_at": "2026-10-17T10:00:00Z", "kind": "pre_action",
            "adapter": "claude-code", "agent_type": "claude-code", "session_id": "0", "tool_name": "Bash",
            "arguments": {"command": command}, "cwd": "", "tier": 0, "disposition": "allow", "mode": "shadow",
            "reason": "", "findings": [], "timing_ms": {"total": 0.0}}


# A decision whose argument holds U+0085: str.splitlines() split the line in two, so the intact spool failed with
# "not valid JSON". U+2028 / U+2029 are the other non-"\n" breaks splitlines honours.
PIN_NEL = [_pinned_decision("\x85")] + [CONTROL[k](_PIN_META, "claude-code") for k in sorted(CONTROL)]
PIN_LS_PS = [CONTROL[k](_PIN_META, "kiro") for k in sorted(CONTROL)] + [_pinned_decision("a\u2028b\u2029c")]


# --- spool helpers ------------------------------------------------------------------------------------------------

def _fresh_spool(base: Path, recs: list[dict]) -> Spool:
    d = base / "spool"
    if d.exists():
        for f in d.iterdir():
            f.unlink()
    spool = Spool(d, fsync=False)
    for r in recs:
        spool.append(r)
    return spool


def _lines(spool: Spool) -> list[tuple[Path, int]]:
    """(segment, 1-based line) for every record, in chain order (the chain spans segments)."""
    out = []
    for seg in spool.segments():
        n = len(split_lines(seg.read_text(encoding="utf-8")))
        out.extend((seg, i) for i in range(1, n + 1))
    return out


def _rewrite(seg: Path, line: int, new: str | None) -> None:
    lines = split_lines(seg.read_text(encoding="utf-8"))
    if new is None:
        del lines[line - 1]
    else:
        lines[line - 1] = new
    seg.write_text("".join(x + "\n" for x in lines), encoding="utf-8")


def _alter(raw: str, how: str, key_pick: int, value: str) -> str:
    """Return an altered line for record ``raw``; the parsed result always differs from the original."""
    if how == "not_json":
        return raw[: len(raw) // 2]
    rec = json.loads(raw)
    keys = sorted(rec)
    if how == "drop_hash":
        del rec["hash"]
    elif how == "drop_key":
        del rec[keys[key_pick % len(keys)]]
    elif how == "add_key":
        rec["x_injected"] = value
    elif how == "edit_value":
        k = keys[key_pick % len(keys)]
        rec[k] = value if rec[k] != value else value + "!"
    elif how == "edit_argument":
        args = rec.get("arguments") or {}
        k = sorted(args)[key_pick % len(args)] if args else "record"
        args[k] = value if args.get(k) != value else value + "!"
        rec["arguments"] = args
    return json.dumps(rec, separators=(",", ":"), ensure_ascii=False)


ALTERATIONS = ("drop_hash", "drop_key", "add_key", "edit_value", "edit_argument", "not_json")


# --- properties ---------------------------------------------------------------------------------------------------

# Feature: hook-tamper-detection, Property 20: Control records keep the audit chain and break it when altered
@PROPS
@given(mixed_sequences())
@example(PIN_NEL)
@example(PIN_LS_PS)
def test_mixed_control_and_decision_records_verify(tmp_path, recs):
    """**Validates: Requirements 11.7, 13.1**"""
    spool = _fresh_spool(tmp_path, recs)
    v = spool.verify()
    assert v["ok"], v["break"]
    assert v["records"] == len(recs) and v["legacy"] == 0 and v["break"] is None
    assert v["head"] == spool.head()
    kinds = {r["arguments"]["record"] for r in spool.iter_records() if r.get("kind") == "control"}
    assert kinds == set(records.BUILDERS)


# Feature: hook-tamper-detection, Property 20: Control records keep the audit chain and break it when altered
@PROPS
@given(mixed_sequences(), st.integers(0, 2**16), st.sampled_from(ALTERATIONS), st.integers(0, 64),
       st.text(min_size=1, max_size=20))
@example(PIN_NEL, 0, "drop_hash", 0, "x")            # first chained record turned legacy-looking: caught at the next
@example(PIN_NEL, 1, "drop_hash", 0, "x")
@example(PIN_NEL, 0, "edit_argument", 0, "\x85")     # the U+0085 record itself, edited
@example(PIN_LS_PS, len(PIN_LS_PS) - 1, "edit_argument", 0, "\u2028")
def test_altering_a_record_breaks_the_chain_at_its_position(tmp_path, recs, pick, how, key_pick, value):
    """**Validates: Requirements 11.7, 13.1**"""
    spool = _fresh_spool(tmp_path, recs)
    where = _lines(spool)
    assert len(where) == len(recs)
    i = pick % len(where)

    seg, line = where[i]
    raw = split_lines(seg.read_text(encoding="utf-8"))[line - 1]
    altered = _alter(raw, how, key_pick, value)
    _rewrite(seg, line, altered)
    expected = (seg.name, line)
    try:
        looks_legacy = i == 0 and "hash" not in json.loads(altered)
    except ValueError:
        looks_legacy = False
    if looks_legacy:              # nothing chained before it, so verify() cannot tell it from a pre-chaining record
        nseg, nline = where[1]
        expected = (nseg.name, nline)

    v = Spool(spool.dir, fsync=False).verify()
    assert not v["ok"], (how, i)
    assert (v["break"]["segment"], v["break"]["line"]) == expected, (how, i, v["break"])
    assert v["records"] == i


# Feature: hook-tamper-detection, Property 20: Control records keep the audit chain and break it when altered
@PROPS
@given(mixed_sequences(), st.integers(0, 2**16))
@example(PIN_NEL, 0)                                  # removes the U+0085 record
@example(PIN_NEL, 1)
@example(PIN_LS_PS, len(PIN_LS_PS) - 2)               # the U+2028/U+2029 record becomes the break position
def test_removing_a_record_breaks_the_chain_at_the_next_position(tmp_path, recs, pick):
    """**Validates: Requirements 11.7, 13.1**"""
    spool = _fresh_spool(tmp_path, recs)
    where = _lines(spool)
    assert len(where) == len(recs)
    i = pick % (len(where) - 1)              # not the newest: tail truncation needs an anchored head

    seg, line = where[i]
    _rewrite(seg, line, None)
    # after removal the record that followed `i` sits at `i`; in the same segment that is the same line number
    nseg, nline = where[i + 1]
    expected = (nseg.name, nline - 1 if nseg == seg else nline)

    v = Spool(spool.dir, fsync=False).verify()
    assert not v["ok"], i
    assert (v["break"]["segment"], v["break"]["line"]) == expected, (i, v["break"])
    assert v["records"] == i
