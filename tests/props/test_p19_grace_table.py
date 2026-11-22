"""Property 19: Grace table.

For any change kind, action name and elapsed time `dt`, `OperatorActions.explains(kind, now)` returns the action iff
the action is in `EXPLAINS[kind]` and `0 <= dt < GRACE_S`. Over a set of recorded actions, the result is the newest
such action; a failed action starts no grace period (Req 2.6) and an unknown kind is explained by nothing.

**Validates: Requirements 11.2**
"""

from __future__ import annotations

import time

from hypothesis import given
from hypothesis import strategies as st

from interlockd import operator, records
from interlockd.store.spool import Spool

from .strategies import PROPS, epochs

# Times are generated on a 1/8 s grid. Every grid point is exactly representable as a float and as an ISO timestamp
# with millisecond precision (`.000`, `.125`, ... `.875`), so `now - at` is computed exactly and the 120 s boundary is
# tested at the boundary itself rather than one rounding error away from it.
_TICKS_PER_S = 8
_GRACE_TICKS = int(operator.GRACE_S) * _TICKS_PER_S
_SPAN_TICKS = 3 * _GRACE_TICKS
_KINDS = (*sorted(operator.EXPLAINS), "no_such_kind")


def _iso(sec: int, ticks: int) -> str:
    whole, frac = divmod(ticks, _TICKS_PER_S)
    ms = frac * 1000 // _TICKS_PER_S
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec + whole)) + f".{ms:03d}Z"


def _offsets() -> st.SearchStrategy[int]:
    """Ticks after t0, spanning three grace periods."""
    return st.integers(min_value=0, max_value=_SPAN_TICKS)


_actions = st.lists(
    st.tuples(st.sampled_from(sorted(operator.ACTIONS)), _offsets(), st.booleans()),   # (action, at, failed)
    max_size=20,
)


@st.composite
def _queries(draw, actions):
    """(kind, now) pairs: arbitrary times plus times exactly at, just inside and exactly at the end of an action's
    grace window, and one tick before it was recorded."""
    kind = st.sampled_from(_KINDS)
    free = st.tuples(kind, _offsets())
    if not actions:
        return draw(st.lists(free, min_size=1, max_size=8))
    at = st.sampled_from([a[1] for a in actions])
    edge = st.tuples(kind, st.builds(lambda t, d: t + d, at, st.sampled_from((-1, 0, 1, _GRACE_TICKS - 1, _GRACE_TICKS))))
    return draw(st.lists(st.one_of(free, edge), min_size=1, max_size=8))


def _model(actions, kind, now_ticks):
    """Candidates the grace table admits: mapped to `kind`, not failed, and `0 <= now - at < GRACE_S` (exact ticks)."""
    names = operator.EXPLAINS.get(kind, frozenset())
    return [(i, a) for i, a in enumerate(actions)
            if a[0] in names and not a[2] and 0 <= now_ticks - a[1] < _GRACE_TICKS]


# Feature: hook-tamper-detection, Property 19: Grace table
@PROPS
@given(epochs(), _actions.flatmap(lambda acts: st.tuples(st.just(acts), _queries(acts))))
def test_explains_follows_the_grace_table(tmp_path, t0, generated):
    actions, queries = generated
    clock = [0.0]
    ops = operator.OperatorActions(Spool(tmp_path / "spool"), now=lambda: clock[0])
    recs = []
    for action, at, failed in actions:          # added in generation order: times arrive out of order
        rec = records.operator_action(action, failed=failed, at=_iso(t0, at))
        recs.append(rec)
        ops.add(rec)

    for kind, now_ticks in queries:
        now = t0 + now_ticks / _TICKS_PER_S
        clock[0] = now
        candidates = _model(actions, kind, now_ticks)
        for got in (ops.explains(kind, now), ops.explains(kind)):   # explicit time and the injected clock agree
            if not candidates:
                assert got is None, (kind, now_ticks, got)
                continue
            assert got is not None, (kind, now_ticks, candidates)
            newest = max(a[1] for _, a in candidates)
            # the newest admitted action; among actions recorded at the same instant any one of them
            tied = {recs[i]["event_id"] for i, a in candidates if a[1] == newest}
            assert got["event_id"] in tied
            assert got["action"] in operator.EXPLAINS[kind]
            assert got["at"] == t0 + newest / _TICKS_PER_S
