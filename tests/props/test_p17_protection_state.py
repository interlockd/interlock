"""Property 17: Protection_State derivation and change records (Requirements 9.1, 9.2, 9.3, 11.11).

A random sequence of operations (`add_reason`, `clear` with assorted predicates, `set_observing`, and changes of
the daemon mode behind `mode_provider`) runs against a real `ProtectionState` and a plain set-of-reasons model.
After every operation:

- each harness is `compromised` iff it has a reason, else `observing` when shadow (mode or the Operator's
  observing flag), else `protected`; the aggregate is `compromised` iff any reason exists, else the same rule;
- an operation that changed the state records exactly one `control.protection_state` record, carrying the complete
  reason set after the change and the subject's state before and after; an operation that changed nothing (a
  duplicate add, a clear that matches nothing, a repeated `set_observing`, a mode change) records nothing.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from interlockd import protection
from interlockd.onboard import HARNESSES
from interlockd.protection import HOME, ProtectionState
from interlockd.store.spool import Spool

from .strategies import PROPS, harnesses, modes, reasons

AT = "2026-10-17T10:00:00Z"
EID = "01JD0000000000000000000000"

Pair = tuple[str, str]


class Otel:
    def __init__(self) -> None:
        self.recs: list[dict] = []

    def submit(self, rec: dict) -> None:
        self.recs.append(rec)


# --- operations ---------------------------------------------------------------------------------------------------

def _selectors() -> st.SearchStrategy[tuple]:
    """Clear predicates as data, so the model can apply the same selection."""
    return st.one_of(
        st.tuples(st.just("exact"), reasons()),
        st.tuples(st.just("subject"), st.one_of(harnesses(), st.just(HOME))),
        st.tuples(st.just("reason_in"), st.frozensets(st.sampled_from(
            sorted(protection.HARNESS_REASONS | protection.HOME_REASONS)), max_size=4)),
        st.tuples(st.just("ep"),),            # what `interlock init` clears (11.6)
        st.tuples(st.just("all"),),           # what a full `interlock ack` clears
        st.tuples(st.just("none"),),
    )


def _selects(sel: tuple, pair: Pair) -> bool:
    kind = sel[0]
    if kind == "exact":
        return pair == sel[1]
    if kind == "subject":
        return pair[0] == sel[1]
    if kind == "reason_in":
        return pair[1] in sel[1]
    if kind == "ep":
        return pair[1] in protection.EP_REASONS
    return kind == "all"


def ops() -> st.SearchStrategy[list[tuple]]:
    op = st.one_of(
        st.tuples(st.just("add"), reasons()),
        st.tuples(st.just("add"), reasons()),        # weight adds so clears have something to remove
        st.tuples(st.just("clear"), _selectors()),
        st.tuples(st.just("observe"), st.booleans()),
        st.tuples(st.just("mode"), modes()),
    )
    return st.lists(op, max_size=30)


# --- model --------------------------------------------------------------------------------------------------------

def _base(shadow: bool) -> str:
    return "observing" if shadow else "protected"


def _harness_state(model: set[Pair], h: str, shadow: bool) -> str:
    return "compromised" if any(s == h for s, _ in model) else _base(shadow)


def _aggregate(model: set[Pair], shadow: bool) -> str:
    return "compromised" if model else _base(shadow)


def _subject_state(model: set[Pair], subject: str, shadow: bool) -> str:
    return _aggregate(model, shadow) if subject == HOME else _harness_state(model, subject, shadow)


def _codes(model: set[Pair]) -> list[str]:
    return sorted(f"{s}:{r}" for s, r in model)


# Feature: hook-tamper-detection, Property 17: Protection state derivation and change records
@PROPS
@given(initial_mode=modes(), sequence=ops())
def test_protection_state_matches_model(initial_mode: str, sequence: list[tuple]) -> None:
    """**Validates: Requirements 9.1, 9.2, 9.3, 11.11**"""
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        spool = Spool(home / "spool", fsync=False)
        otel = Otel()
        mode_box = {"mode": initial_mode}
        ps = ProtectionState(home, spool, otel, lambda: mode_box["mode"], harnesses=lambda: list(HARNESSES))

        model: set[Pair] = set()
        observing = False
        expected = 0

        for op in sequence:
            shadow_before = observing or mode_box["mode"] == "shadow"
            before_model = set(model)
            want: tuple[str, str, str] | None = None        # (subject, previous, new) of the expected record

            if op[0] == "add":
                subject, reason = op[1]
                added = ps.add_reason(subject, reason, EID, AT)
                assert added == ((subject, reason) not in model)
                if added:
                    model.add((subject, reason))
                    want = (subject, _subject_state(before_model, subject, shadow_before),
                            _subject_state(model, subject, shadow_before))
            elif op[0] == "clear":
                sel = op[1]
                gone = ps.clear(lambda r, sel=sel: _selects(sel, (r.subject, r.reason)), caused_by="op")
                selected = {p for p in model if _selects(sel, p)}
                assert {(r.subject, r.reason) for r in gone} == selected
                if selected:
                    model -= selected
                    subjects = {s for s, _ in selected}
                    subject = subjects.pop() if len(subjects) == 1 else HOME
                    want = (subject, _subject_state(before_model, subject, shadow_before),
                            _subject_state(model, subject, shadow_before))
            elif op[0] == "observe":
                on = op[1]
                ps.set_observing(on, caused_by="op")
                if on != observing:
                    observing = on
                    shadow_after = observing or mode_box["mode"] == "shadow"
                    want = (HOME, _aggregate(model, shadow_before), _aggregate(model, shadow_after))
            else:                                           # daemon mode change: derived, never recorded
                mode_box["mode"] = op[1]

            if want is not None:
                expected += 1
            assert len(otel.recs) == expected, op
            if want is not None:
                args = otel.recs[-1]["arguments"]
                assert args["record"] == "protection_state"
                assert (args["subject"], args["previous"], args["new"]) == want, op
                assert sorted(args["reasons"]) == _codes(model)

            shadow = observing or mode_box["mode"] == "shadow"
            assert {h: ps.harness_state(h) for h in HARNESSES} == {
                h: _harness_state(model, h, shadow) for h in HARNESSES}
            assert ps.aggregate() == _aggregate(model, shadow)
            assert {(r.subject, r.reason) for r in ps.reasons()} == model
            snap = ps.snapshot()
            assert snap["aggregate"] == ps.aggregate()
            assert snap["observing"] is observing

        spooled = [r for r in spool.iter_records(reverse=False) if r.get("kind") == "control"]
        assert [r["event_id"] for r in spooled] == [r["event_id"] for r in otel.recs]
        assert all(r["arguments"]["record"] == "protection_state" for r in spooled)
        assert spool.verify()["ok"]
