"""Property 6: Token-rejection recording is content-free and rate-limited.

For any sequence of rejected requests (adapter names of any length including absent/unparseable bodies, presented
tokens, timestamps), each individual `control.token_rejected` record carries the adapter name truncated to 64
characters or `unknown`, the address and the time, and contains no 8-character substring of the presented token;
per adapter name and rolling 60 s window at most 5 individual records are written, and each summary record's `count`
equals the number of rejections collapsed in that window with `first_at <= last_at`.

The rejections go through the request path's two steps: `tamper.adapter_name(body)` on the request body, then
`TokenRejections.token_rejected(name, addr, presented)`. HookWatch passes (`pending_summaries`) are interleaved at
arbitrary times, and a final pass after the last window flushes every pending summary.

**Validates: Requirements 2.4, 2.5**
"""

from __future__ import annotations

import json
import string
import tempfile
from collections import defaultdict
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from interlockd import operator, records, tamper
from interlockd.config import Settings
from interlockd.pipeline import Daemon
from interlockd.store.memory import MemoryRepository
from interlockd.store.spool import Spool

from .strategies import PROPS, addresses, harnesses, tokens

T0 = 1_800_000_000
# Times on a 1/8 s grid: exact as floats, so the 60 s window boundary is hit exactly rather than one rounding error off.
_TICKS_PER_S = 8
_WINDOW_TICKS = int(tamper.WINDOW_S) * _TICKS_PER_S

# ---- generators -------------------------------------------------------------------------------------------------

_raw_names = st.one_of(
    harnesses(),
    st.text(max_size=200),                                                       # unicode, long, empty
    st.text(alphabet=st.characters(codec="utf-8", categories=("Cc", "Cf", "Zl", "Zp", "Zs", "L")), max_size=100),
    st.builds(lambda h, n: h * n, harnesses(), st.integers(5, 20)),              # > 64 printable chars
)

# A body spec: ("name", raw) -> {"adapter": {"name": raw}, ...}; ("none",) -> no body; ("garbage", bytes);
# ("nonstr", value) -> {"adapter": {"name": value}}; ("noadapter",) -> a body without an adapter block.
_garbage = st.one_of(st.binary(max_size=64), st.just(b"[" * 3000), st.just(b"\xff\xfe"), st.just(b"[1]"))


def _secret_tokens() -> st.SearchStrategy[str]:
    alnum = string.ascii_letters + string.digits
    return st.one_of(
        tokens(),
        st.builds(lambda s: "sk-" + s, st.text(alphabet=alnum, min_size=32, max_size=48)),
        st.builds(lambda s: "ghp_" + s, st.text(alphabet=alnum, min_size=36, max_size=36)),
        st.builds(lambda s: "AKIA" + s, st.text(alphabet=string.ascii_uppercase + string.digits, min_size=16,
                                                max_size=16)),
        st.builds(lambda a, b, c: f"eyJ{a}.eyJ{b}.{c}", *(st.text(alphabet=alnum + "-_", min_size=10, max_size=30)
                                                          for _ in range(3))),
    )


# Mostly bursts (the limiter only acts when an adapter sends 6+ rejections within 60 s), with occasional long gaps
# and gaps at the window boundary.
_dt_ticks = st.one_of(
    st.just(0),
    st.integers(0, 2 * _TICKS_PER_S),
    st.integers(0, 10 * _TICKS_PER_S),
    st.integers(0, 90 * _TICKS_PER_S),
    st.sampled_from((_WINDOW_TICKS - 1, _WINDOW_TICKS, _WINDOW_TICKS + 1)),
).flatmap(lambda dt: st.sampled_from((0, dt)) if dt > 10 * _TICKS_PER_S else st.just(dt))


@st.composite
def _scenarios(draw):
    """(name pool, ops). Ops: ("reject", dt, body_spec, token, addr) | ("watch", dt). Pools mostly have a few names
    so that buckets fill; sometimes more than MAX_ADAPTERS so that the overflow bucket is used."""
    many = draw(st.booleans())
    pool_size = draw(st.integers(tamper.MAX_ADAPTERS + 1, tamper.MAX_ADAPTERS + 10) if many else st.integers(1, 4))
    pool = draw(st.lists(_raw_names, min_size=pool_size, max_size=pool_size,
                         unique_by=lambda n: _expected_name(("name", n))))
    body = st.one_of(
        st.sampled_from(pool).map(lambda n: ("name", n)),
        st.just(("none",)),
        st.just(("noadapter",)),
        _garbage.map(lambda b: ("garbage", b)),
        st.sampled_from((7, None, ["x"], {"a": 1})).map(lambda v: ("nonstr", v)),
    )
    reject = st.tuples(st.just("reject"), _dt_ticks, body, _secret_tokens(), addresses())
    watch = st.tuples(st.just("watch"), _dt_ticks)
    ops = draw(st.lists(st.one_of(reject, reject, reject, reject, watch), min_size=1, max_size=60))
    # A burst from one name: enough rejections in one window that the limiter must collapse some of them.
    burst_body = draw(body)
    burst_at = draw(st.integers(0, len(ops)))
    burst = [("reject", draw(st.integers(0, 3 * _TICKS_PER_S)), burst_body, draw(_secret_tokens()), draw(addresses()))
             for _ in range(draw(st.integers(0, 3 * tamper.MAX_PER_WINDOW)))]
    ops[burst_at:burst_at] = burst
    if many and draw(st.booleans()):
        # A spray: every name in the pool within a few seconds, so names past MAX_ADAPTERS share the overflow bucket.
        spray_at = draw(st.integers(0, len(ops)))
        ops[spray_at:spray_at] = [("reject", draw(st.integers(0, 1)), ("name", n), draw(_secret_tokens()),
                                   draw(addresses())) for n in pool]
    return pool, ops


# ---- oracle helpers ---------------------------------------------------------------------------------------------

def _body(spec) -> bytes | None:
    kind = spec[0]
    if kind == "name":
        return json.dumps({"adapter": {"name": spec[1], "version": "0.2.0"}, "payload": {}}).encode()
    if kind == "none":
        return None
    if kind == "noadapter":
        return b'{"payload": {}}'
    if kind == "garbage":
        return spec[1]
    return json.dumps({"adapter": {"name": spec[1]}}).encode()


def _expected_name(spec) -> str:
    """The self-reported name as Requirement 2.4 defines it, computed independently of `tamper.adapter_name`."""
    if spec[0] == "name":
        cleaned = "".join(c for c in spec[1] if c.isprintable())[:64]
        return cleaned or "unknown"
    if spec[0] == "garbage":
        try:
            doc = json.loads(spec[1])
        except (ValueError, RecursionError):
            return "unknown"
        adapter = doc.get("adapter") if isinstance(doc, dict) else None
        name = adapter.get("name") if isinstance(adapter, dict) else None
        if isinstance(name, str):
            return "".join(c for c in name if c.isprintable())[:64] or "unknown"
    return "unknown"


def _windows(s: str, n: int = 8) -> set[str]:
    return {s[i:i + n] for i in range(len(s) - n + 1)}


def _new_daemon(root: Path, clock) -> Daemon:
    settings = Settings(home=root / "home")
    settings.home.mkdir()
    settings.kiro_sessions_dir = root / "kiro-sessions"
    daemon = Daemon(settings, spool=Spool(root / "spool", fsync=False), repo=MemoryRepository())
    daemon.operator_actions = operator.OperatorActions(daemon.spool, now=clock)
    daemon.tamper = tamper.TokenRejections(daemon, now=clock)
    return daemon


# ---- the property -----------------------------------------------------------------------------------------------

# Feature: hook-tamper-detection, Property 6: Token-rejection recording is content-free and rate-limited
@PROPS
@given(_scenarios())
def test_token_rejection_records_are_content_free_and_rate_limited(scenario):
    _pool, ops = scenario
    clock = [float(T0)]
    with tempfile.TemporaryDirectory() as tmp:
        daemon = _new_daemon(Path(tmp), lambda: clock[0])
        rej = daemon.tamper

        buckets: list[str] = []                     # the limiter's bucket name for each rejection, in order
        original_observe = rej.limiter.observe

        def observe(adapter, now, at_iso):
            out = original_observe(adapter, now, at_iso)
            buckets.append(out[0])
            return out

        rej.limiter.observe = observe

        ticks = 0
        rejections = []                             # (time, expected name, bucket, token, addr, returned record)
        presented_tokens: list[str] = []
        innocent_text: list[str] = []               # inputs that legitimately appear in records
        for op in ops:
            ticks += op[1]
            clock[0] = T0 + ticks / _TICKS_PER_S
            innocent_text.append(tamper.iso(clock[0]))
            if op[0] == "watch":
                rej.pending_summaries(clock[0])
                continue
            _, _, spec, token, addr = op
            name = tamper.adapter_name(_body(spec))
            expected = _expected_name(spec)
            assert name == expected, (spec, name)
            rec = rej.token_rejected(name, addr, token)
            rejections.append((clock[0], expected, buckets[-1], token, addr, rec))
            presented_tokens.append(token)
            innocent_text += [expected, addr]

        final = clock[0] + tamper.WINDOW_S + 1
        rej.pending_summaries(final)                # every summary is due by now
        assert rej.pending_summaries(final + tamper.WINDOW_S) == []

        stored = list(daemon.spool.iter_records(reverse=False))
        assert daemon.spool.verify()["ok"]

    individual = [r for r in stored if r["arguments"].get("record") == "token_rejected"]
    summaries = [r for r in stored if r["arguments"].get("record") == "token_rejected_summary"]
    assert len(individual) + len(summaries) == len(stored)          # nothing else is recorded without a rotation

    # Each individual record: the self-reported name (or the overflow bucket), the address and the time.
    written = [(t, exp, b, addr, rec) for t, exp, b, _, addr, rec in rejections if rec is not None]
    assert [r["event_id"] for r in individual] == [rec["event_id"] for *_, rec in written]
    for (t, exp, bucket, addr, _), r in zip(written, individual, strict=True):
        assert bucket in (exp, tamper.OVERFLOW)
        args = r["arguments"]
        assert set(args) <= records.ARGUMENT_KEYS["token_rejected"]
        assert args["adapter"] == bucket
        assert args["addr"] == "".join(c for c in addr if c.isprintable())[:128]
        assert r["received_at"] == tamper.iso(t)
        assert r["disposition"] == "flag" and r["findings"][0]["rule"] == "control.token_rejected"

    for r in individual + summaries:
        adapter = r["arguments"]["adapter"]
        assert 0 < len(adapter) <= 64 and adapter.isprintable()

    # Rate limit: per bucket, at most MAX_PER_WINDOW individual records in any rolling WINDOW_S.
    times_by_bucket: dict[str, list[float]] = defaultdict(list)
    for t, _, bucket, _, _ in written:
        times_by_bucket[bucket].append(t)
    n = tamper.MAX_PER_WINDOW
    for bucket, times in times_by_bucket.items():
        for i in range(len(times) - n):
            assert times[i + n] - times[i] >= tamper.WINDOW_S, (bucket, times[i:i + n + 1])

    # Summaries: per bucket, consecutive slices of the collapsed rejections, in order.
    collapsed: dict[str, list[float]] = defaultdict(list)
    for t, _, bucket, _, _, rec in rejections:
        if rec is None:
            collapsed[bucket].append(t)
    summaries_by_bucket: dict[str, list[dict]] = defaultdict(list)
    for r in summaries:
        assert set(r["arguments"]) <= records.ARGUMENT_KEYS["token_rejected_summary"]
        summaries_by_bucket[r["arguments"]["adapter"]].append(r["arguments"])
    assert set(summaries_by_bucket) == set(collapsed)
    for bucket, times in collapsed.items():
        pos = 0
        for s in summaries_by_bucket[bucket]:
            assert s["count"] >= 1
            part = times[pos:pos + s["count"]]
            assert len(part) == s["count"], (bucket, s, times)
            assert s["first_at"] == tamper.iso(part[0]) and s["last_at"] == tamper.iso(part[-1])
            assert s["first_at"] <= s["last_at"]
            assert part[-1] - part[0] < tamper.WINDOW_S                 # one summary covers one window
            pos += s["count"]
        assert pos == len(times), (bucket, pos, len(times))

    # Conservation: per bucket, individual records plus summarized counts equal the rejections counted there.
    per_bucket: dict[str, int] = defaultdict(int)
    for _, _, bucket, _, _, _ in rejections:
        per_bucket[bucket] += 1
    for bucket, total in per_bucket.items():
        summed = sum(s["count"] for s in summaries_by_bucket.get(bucket, []))
        assert len(times_by_bucket.get(bucket, [])) + summed == total, bucket
    assert sum(per_bucket.values()) == len(rejections)

    # Content-free: no presented token, 8-character substring of it, or token-file digest of it in any record.
    text = json.dumps(stored, ensure_ascii=False)
    # Text a record carries whatever the token: the inputs, the times, and the schema (keys and fixed values, e.g.
    # a token "agent_ty" matches the key "agent_type"). A token window found only there is not a leak.
    schema = json.dumps([records.token_rejected("", ""), records.token_rejected_summary("", 0, "", ""),
                         {"prev_hash": "", "hash": ""}], ensure_ascii=False)
    innocent_text += [schema, tamper.iso(final)]
    innocent = set().union(*(_windows(s) for s in innocent_text))
    for token in presented_tokens:
        for d in tamper._token_digests(token):
            assert d not in text
        for w in _windows(token) - innocent:                            # a window the inputs carry is not a leak
            assert w not in text, (token, w)
