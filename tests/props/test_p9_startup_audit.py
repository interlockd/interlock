"""Property 9: Startup audit (lifecycle.startup_audit / summarize_hook_log).

For any previous `daemon.json` (absent, with the clean-exit mark, without it, unreadable) and Stop_Marker (absent,
present), the audit emits exactly one `control.daemon_started`, a `control.daemon_unexpected_exit` iff the previous
file exists without `exited_at` and no marker was present, and, for a generated `hook.log` with lines on both sides
of the cutoff (`exited_at`, else `started_at`), one `control.calls_unjudged` with exact per-classification counts and
span iff at least one line after the cutoff is `unjudged` or `tamper <shim cause>`.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from interlockd import lifecycle

from .strategies import PROPS, epochs, iso, stop_marker_docs

DAY_S = 86_400
SHIM_CAUSES = ("token_rejected", "daemon_identity", "daemon_lost")      # what a shim writes to hook.log
COUNT_KEYS = ("unjudged", *(f"tamper_{c}" for c in SHIM_CAUSES))
_TAIL = st.sampled_from((
    "", " harness=claude-code tool=Bash kind=pre addr=http://127.0.0.1:7391 status=- fail_mode=closed",
    " why=curl_rc_7 harness=kiro tool=? kind=post addr=unix:/h/interlockd.sock fail_mode=open",
))


@st.composite
def classified(draw) -> tuple[str, str | None]:
    """(classification text after the timestamp, the count key it adds to or None when it is not counted)."""
    counted = st.one_of(
        st.just(("unjudged", "unjudged")),
        st.sampled_from(SHIM_CAUSES).map(lambda c: (f"tamper {c}", f"tamper_{c}")),
    )
    other = st.sampled_from((
        ("tamper enforcement_point", None),            # daemon-side cause; shims never log it
        ("tamper bogus_cause", None),
        ("tamper", None),                              # no cause word
        ("inert: no token at /Users/dev/.interlock/token", None),
        ("unjudgedx why=timeout", None),
        ("allow harness=claude-code", None),
    ))
    text, key = draw(st.one_of(counted, other))
    return text + draw(_TAIL), key


@st.composite
def stamped_lines(draw, cutoff: int) -> tuple[str, datetime | None, str | None]:
    """(hook.log line, its time when it has a parseable one, count key or None). Times span a day either side of
    the cutoff and may carry fractional seconds or a `+00:00` offset."""
    secs = draw(st.integers(-DAY_S, DAY_S) | st.sampled_from((-1, 0, 1)))
    fmt = draw(st.sampled_from(("whole", "millis", "micros", "offset")))
    micro = 0 if fmt in ("whole", "offset") else draw(st.integers(0, 999_999) | st.sampled_from((0, 1, 999_999)))
    if fmt == "millis":
        micro -= micro % 1000
    t = datetime.fromtimestamp(cutoff + secs, UTC) + timedelta(microseconds=micro)
    stamp = {
        "whole": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "millis": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{micro // 1000:03d}Z",
        "micros": t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "offset": t.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    }[fmt]
    text, key = draw(classified())
    return f"{stamp} {text}", t, key


NOISE = st.sampled_from((
    "", "   ", "garbage", "not-a-time unjudged why=timeout", "2026-13-45T99:99:99Z unjudged why=timeout",
    "unjudged why=timeout harness=claude-code", "tamper daemon_lost harness=kiro",
))


@st.composite
def scenarios(draw):
    cutoff = draw(epochs())
    variant = draw(st.sampled_from(("absent", "clean", "unclean", "unreadable")))
    pid = draw(st.integers(1, 2**22))
    version = draw(st.sampled_from(("0.1.8", "0.2.0")))
    previous: dict | None
    if variant == "absent":
        previous = None
    elif variant == "clean":
        ran = draw(st.integers(1, DAY_S))
        previous = {"listen": "127.0.0.1:7391", "pid": pid, "version": version, "started_at": iso(cutoff - ran),
                    "exited_at": iso(cutoff), "exit_reason": draw(st.sampled_from(("sigterm", "sigint", "stop")))}
    elif variant == "unclean":
        previous = {"listen": "127.0.0.1:7391", "pid": pid, "version": version, "started_at": iso(cutoff)}
    else:
        previous = {}                                  # read_daemon_json's "present but unreadable"
    marker = draw(st.none() | stop_marker_docs())
    entries = draw(st.lists(st.one_of(stamped_lines(cutoff), NOISE.map(lambda s: (s, None, None))), max_size=40))
    trailing_newline = draw(st.booleans())
    return cutoff, variant, previous, marker, entries, trailing_newline


def _expected_summary(cutoff: int, entries) -> dict | None:
    since = datetime.fromtimestamp(cutoff, UTC)
    counts = dict.fromkeys(COUNT_KEYS, 0)
    times = []
    for _line, t, key in entries:
        if key is not None and t is not None and t > since:
            counts[key] += 1
            times.append(t)
    if not times:
        return None
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return {**counts, "span_from": min(times).strftime(fmt), "span_to": max(times).strftime(fmt)}


def test_tamper_causes_match_design():
    assert lifecycle.TAMPER_CAUSES == SHIM_CAUSES


# Feature: hook-tamper-detection, Property 9: Startup audit
@PROPS
@given(scenarios())
def test_startup_audit(scenario):
    """**Validates: Requirements 3.5, 3.12**"""
    cutoff, variant, previous, marker, entries, trailing_newline = scenario
    now = datetime.fromtimestamp(cutoff + 2 * DAY_S, UTC)
    text = "\n".join(line for line, _t, _k in entries) + ("\n" if trailing_newline and entries else "")

    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        (home / "hook.log").write_text(text, encoding="utf-8")
        recs = lifecycle.startup_audit(home, None, previous, marker, now, mode="enforce")
        assert (home / "hook.log").read_text(encoding="utf-8") == text     # the audit only reads

    by_kind: dict[str, list[dict]] = {}
    for r in recs:
        assert r["kind"] == "control"
        by_kind.setdefault(r["arguments"]["record"], []).append(r["arguments"])
    assert set(by_kind) <= {"daemon_started", "daemon_unexpected_exit", "calls_unjudged"}

    [started] = by_kind["daemon_started"]
    assert started["marker_present"] is (marker is not None)
    assert started["marker_action"] == (marker["action"] if marker is not None else "")

    unexpected = previous is not None and "exited_at" not in previous and marker is None
    exits = by_kind.get("daemon_unexpected_exit", [])
    assert len(exits) == (1 if unexpected else 0)
    if unexpected:
        assert exits[0]["prev_pid"] == (pid if isinstance(pid := previous.get("pid"), int) else 0)
        assert exits[0]["prev_version"] == previous.get("version", "")

    # no cutoff when there is no previous daemon.json or it was unreadable: nothing to bound the gap by
    expected = _expected_summary(cutoff, entries) if variant in ("clean", "unclean") else None
    summaries = by_kind.get("calls_unjudged", [])
    if expected is None:
        assert summaries == []
    else:
        [summary] = summaries
        assert {k: v for k, v in summary.items() if k != "record"} == expected
        assert any(summary[k] > 0 for k in COUNT_KEYS)
        assert summary["span_from"] <= summary["span_to"]

    assert len(recs) == 1 + len(exits) + len(summaries)
