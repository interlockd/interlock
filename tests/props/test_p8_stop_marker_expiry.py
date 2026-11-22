"""Property 8: Stop_Marker expiry rule (lifecycle.stop_marker_doc / write_stop_marker / read_stop_marker).

Restarting actions get `expires_at` and `expires_epoch` (written time + 120 s); stopping actions get neither.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta, timezone

from hypothesis import given
from hypothesis import strategies as st

from interlockd import lifecycle

from .strategies import GRACE_S, PROPS, RESTARTING, STOPPING, epochs, iso


@st.composite
def write_times(draw) -> tuple[datetime, int]:
    """(the `now` passed to the writer, the whole-second epoch it denotes). Covers sub-second times, non-UTC
    offsets and naive datetimes (treated as UTC)."""
    epoch = draw(epochs())
    micro = draw(st.integers(0, 999_999))
    t = datetime.fromtimestamp(epoch, UTC) + timedelta(microseconds=micro)
    kind = draw(st.sampled_from(("utc", "offset", "naive")))
    if kind == "offset":
        t = t.astimezone(timezone(timedelta(minutes=draw(st.integers(-14 * 60, 14 * 60)))))
    elif kind == "naive":
        t = t.replace(tzinfo=None)
    return t, epoch


def test_action_sets_match_design():
    assert lifecycle.RESTARTING == frozenset(RESTARTING)
    assert lifecycle.STOPPING == frozenset(STOPPING)
    assert lifecycle.GRACE_S == GRACE_S


# Feature: hook-tamper-detection, Property 8: Stop_Marker expiry rule
@PROPS
@given(st.sampled_from(sorted(lifecycle.RESTARTING | lifecycle.STOPPING)), write_times())
def test_stop_marker_expiry_rule(tmp_path, action, when):
    """**Validates: Requirements 3.2**"""
    now, epoch = when
    doc = lifecycle.write_stop_marker(tmp_path, action, now=now)

    assert doc["action"] == action
    assert doc["written_at"] == iso(epoch)
    assert doc["pid"] == os.getpid()
    restarting = action in lifecycle.RESTARTING
    assert ("expires_at" in doc) is restarting
    assert ("expires_epoch" in doc) is restarting
    if restarting:
        assert doc["expires_epoch"] == epoch + lifecycle.GRACE_S
        assert doc["expires_at"] == iso(doc["expires_epoch"])
        assert lifecycle.parse_iso(doc["expires_at"]) - lifecycle.parse_iso(doc["written_at"]) == timedelta(
            seconds=lifecycle.GRACE_S)

    assert lifecycle.stop_marker_doc(action, now=now, pid=os.getpid()) == doc

    errors: list[tuple[str, str]] = []
    assert lifecycle.read_stop_marker(tmp_path, on_error=lambda f, r: errors.append((f, r))) == doc
    assert errors == []
