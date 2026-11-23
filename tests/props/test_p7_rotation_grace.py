"""Property 7: Rotation grace classification.

For any presented token, previous token, rotation time and now, a rejection is `expected_after_rotate` iff a digest of
the previous token file exists, the presented token equals the previous token and `0 <= now - rotated_at < 120 s`;
otherwise it is `token_rejected`. The previous digest is of the token *file* bytes (`token_sha256_previous` in the
baseline), so the file is written with each line ending a token file can have: `\\n` (`rotate_token` and
`load_or_create_token` on POSIX), `\\r\\n` (text mode on Windows) and none (hand-written).

Token domain: the daemon reads the token with `.strip()` and the presented value is `Authorization[7:].strip()`, so
neither ever carries leading or trailing whitespace; the generators respect that (a presented `X\\r` would otherwise
digest like a previous `X` written with `\\r\\n`, which no real request can produce).

**Validates: Requirements 2.7**
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

from hypothesis import given
from hypothesis import strategies as st

from interlockd import integrity, operator, records, tamper
from interlockd.store.spool import Spool

from .strategies import PROPS, epochs, tokens

# Times on a 1/8 s grid: exact as floats and as millisecond ISO timestamps, so the 120 s boundary is tested exactly.
_TICKS_PER_S = 8
_GRACE_TICKS = int(tamper.GRACE_S) * _TICKS_PER_S
_ENDINGS = ("\n", "\r\n", "")


def _clean_tokens() -> st.SearchStrategy[str]:
    return tokens().filter(lambda t: t == t.strip() and t != "")


def _dt_ticks() -> st.SearchStrategy[int]:
    """now - rotated_at in ticks: around both edges of the window, plus anywhere in [-grace, 3 * grace]."""
    edges = st.sampled_from((-_TICKS_PER_S, -1, 0, 1, _GRACE_TICKS - 1, _GRACE_TICKS, _GRACE_TICKS + 1))
    return st.one_of(edges, st.integers(min_value=-_GRACE_TICKS, max_value=3 * _GRACE_TICKS))


@st.composite
def _cases(draw):
    """(previous token, presented token, file line ending, previous digest present, rotated_at ticks or None,
    dt ticks)."""
    previous = draw(_clean_tokens())
    presented = draw(st.one_of(st.just(previous), st.just(""),
                               _clean_tokens().filter(lambda t: t != previous)))
    ending = draw(st.sampled_from(_ENDINGS))
    has_digest = draw(st.sampled_from((True, True, True, False)))      # mostly present
    rotated = draw(st.one_of(st.none(), epochs(), epochs()))
    dt = draw(_dt_ticks())
    return previous, presented, ending, has_digest, rotated, dt


def _previous_digest(home: Path, previous: str, ending: str) -> str:
    path = home / "token"
    path.write_bytes((previous + ending).encode())
    return integrity.file_sha256(path)


def _expected(previous, presented, has_digest, rotated, dt) -> str:
    within = rotated is not None and 0 <= dt < _GRACE_TICKS
    return "expected_after_rotate" if has_digest and within and presented == previous else "token_rejected"


# Feature: hook-tamper-detection, Property 7: Rotation grace classification
@PROPS
@given(_cases(), st.sampled_from((None, "")))
def test_classify_rejection_follows_the_grace_rule(case, absent):
    previous, presented, ending, has_digest, rotated, dt = case
    with tempfile.TemporaryDirectory() as d:
        digest = _previous_digest(Path(d), previous, ending) if has_digest else absent
    rotated_at = None if rotated is None else float(rotated)
    now = (float(rotated) if rotated is not None else 1_800_000_000.0) + dt / _TICKS_PER_S

    got = tamper.classify_rejection(presented, digest, rotated_at, now)

    assert got == _expected(previous, presented, has_digest, rotated, dt), (got, presented == previous, dt, ending)


# Feature: hook-tamper-detection, Property 7: Rotation grace classification
@PROPS
@given(_cases())
def test_token_rejections_record_kind_follows_the_grace_rule(case):
    """End to end: a `token_rotate` Operator_Action (or none) in OperatorActions, the baseline's previous digest, one
    rejection through `TokenRejections.token_rejected`: the record written is the classified kind, and no digest of
    the presented token appears in the spool."""
    previous, presented, ending, has_digest, rotated, dt = case
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        digest = _previous_digest(home, previous, ending) if has_digest else ""
        t0 = float(rotated) if rotated is not None else 1_800_000_000.0
        clock = [t0 + dt / _TICKS_PER_S]
        daemon = SimpleNamespace(spool=Spool(home / "spool"), mode="enforce", policy_sha256="", otel=None,
                                 baseline=integrity.Baseline(token_sha256_previous=digest))
        daemon.operator_actions = operator.OperatorActions(daemon.spool, now=lambda: clock[0])
        if rotated is not None:
            daemon.operator_actions.add(records.operator_action("token_rotate", at=tamper.iso(t0)))
        rejections = tamper.TokenRejections(daemon, now=lambda: clock[0])

        rec = rejections.token_rejected("claude-code", "127.0.0.1:7391", presented)

        want = _expected(previous, presented, has_digest, rotated, dt)
        assert rec is not None
        assert rec["arguments"]["record"] == want, (rec["arguments"], presented == previous, dt)
        stored = [r for r in daemon.spool.iter_records(reverse=False) if r.get("kind") == "control"]
        assert [r["arguments"]["record"] for r in stored] == [want]
        text = repr(stored)
        assert all(h not in text for h in tamper._token_digests(presented))
