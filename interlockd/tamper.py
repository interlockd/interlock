"""Token rejection as a tamper signal (Requirement 2.4, 2.5, 2.7, 14.7).

When a request's bearer token does not match, `api.Handler._authed` calls `daemon.tamper.token_rejected(...)` before
it sends the unchanged 401. The rejection is recorded synchronously in the spool (so it is in the Audit_Log before the
reply leaves) as one of:

- `control.token_rejected`: a Tamper_Event carrying the self-reported adapter name, the daemon address and the time;
- `control.expected_after_rotate`: the token in effect before a `token --rotate` recorded within the grace period
  (compared by digest against the baseline's `token_sha256_previous`); recorded, not a Tamper_Event;
- nothing, when the adapter has had 5 individual records in the last 60 s: the rejection is collapsed into one
  `control.token_rejected_summary` per 60 s (count, first and last time), flushed by the next rejection from that
  adapter after the summary is due or by HookWatch's `pending_summaries` pass.

Rejections inside the grace period of a `selftest` are still recorded as `control.token_rejected` (selftest checks for
exactly that record, 14.3); the Doctor attributes them to the selftest by the operator-action time (14.7).

The presented token is hashed transiently for the rotation comparison only when a rotation is within grace, and is
never stored, logged or recorded, not even as a digest. The adapter name is attacker-controlled, so the limiter
bounds both the records per name and the number of names it tracks; past `MAX_ADAPTERS` names, rejections share one
overflow bucket. Every step on the rejection path is bounded by constants (body prefix, bucket count, deque size).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from . import records

log = logging.getLogger("interlockd.tamper")

WINDOW_S, MAX_PER_WINDOW = 60.0, 5
GRACE_S = 120.0
MAX_ADAPTERS = 32                 # distinct self-reported names tracked; the rest share OVERFLOW
OVERFLOW = "(other)"
ADAPTER_MAX = 64
UNKNOWN = "unknown"
PARSE_LIMIT = 16 * 1024           # bodies up to this size are parsed as JSON; larger ones are scanned by prefix
PREFIX_SCAN = 4096
# Every shim writes the adapter block first: {"adapter":{"name":"<harness>",...},"payload":...}
_PREFIX = re.compile(r'^\s*\{\s*"adapter"\s*:\s*\{\s*"name"\s*:\s*"((?:[^"\\]|\\.){0,256})"')


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _clean(name: Any) -> str:
    if not isinstance(name, str):
        return UNKNOWN
    s = "".join(c for c in name if c.isprintable())[:ADAPTER_MAX]
    return s or UNKNOWN


def adapter_name(body_bytes: bytes | None) -> str:
    """The self-reported `adapter.name` of a request body, printable characters only, truncated to 64; `unknown`
    when the body is absent, unparseable or names no adapter. Bounded work: bodies over PARSE_LIMIT are not parsed,
    only their first PREFIX_SCAN bytes are matched against the shims' fixed body layout."""
    if not body_bytes:
        return UNKNOWN
    if len(body_bytes) <= PARSE_LIMIT:
        try:
            doc = json.loads(body_bytes)
        except (ValueError, RecursionError):
            return UNKNOWN
        adapter = doc.get("adapter") if isinstance(doc, dict) else None
        return _clean(adapter.get("name") if isinstance(adapter, dict) else None)
    m = _PREFIX.match(body_bytes[:PREFIX_SCAN].decode("utf-8", errors="replace"))
    if m is None:
        return UNKNOWN
    try:
        return _clean(json.loads('"' + m.group(1) + '"'))
    except ValueError:
        return UNKNOWN


def format_addr(server_address: Any) -> str:
    """`host:port` for TCP, the socket path for the Unix socket (an Interlock-owned file)."""
    if isinstance(server_address, tuple) and len(server_address) >= 2:
        return f"{server_address[0]}:{server_address[1]}"
    if isinstance(server_address, bytes):
        return server_address.decode("utf-8", errors="replace")
    return str(server_address or "")


def _token_digests(presented: str) -> tuple[str, ...]:
    """sha256 of the token file bytes this token would have: `rotate_token` writes `token + "\\n"` in text mode
    (`\\r\\n` on Windows), and a hand-written file may have no newline."""
    return tuple(hashlib.sha256((presented + end).encode()).hexdigest() for end in ("\n", "\r\n", ""))


def classify_rejection(presented: str, previous_sha256: str | None, rotated_at: float | None, now: float,
                       grace_s: float = GRACE_S) -> Literal["token_rejected", "expected_after_rotate"]:
    """`expected_after_rotate` iff a rotation was recorded `0 <= now - rotated_at < grace_s` ago and the presented
    token is the one in effect before it (its token-file digest equals `previous_sha256`); else `token_rejected`."""
    if not previous_sha256 or rotated_at is None or not 0 <= now - rotated_at < grace_s:
        return "token_rejected"
    match = False
    for d in _token_digests(presented or ""):
        match |= hmac.compare_digest(d, previous_sha256)
    return "expected_after_rotate" if match else "token_rejected"


# ---- rate limit ---------------------------------------------------------------------------------------------------

@dataclass
class _Bucket:
    recent: deque[float] = field(default_factory=lambda: deque(maxlen=MAX_PER_WINDOW))   # individual record times
    count: int = 0                # rejections collapsed into the pending summary
    first_epoch: float = 0.0
    first_at: str = ""
    last_at: str = ""


class RejectionLimiter:
    """At most `max_per_window` individual records per adapter name in any rolling `window_s`; further rejections
    collapse into one summary per adapter, due `window_s` after its first collapsed rejection. Thread-safe."""

    def __init__(self, window_s: float = WINDOW_S, max_per_window: int = MAX_PER_WINDOW,
                 max_adapters: int = MAX_ADAPTERS):
        self.window_s, self.max_per_window, self.max_adapters = window_s, max_per_window, max_adapters
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()

    def __len__(self) -> int:
        return len(self._buckets)

    def _idle(self, b: _Bucket, now: float) -> bool:
        return b.count == 0 and (not b.recent or now - b.recent[-1] >= self.window_s)

    def _bucket(self, adapter: str, now: float) -> tuple[str, _Bucket]:
        b = self._buckets.get(adapter)
        if b is not None:
            return adapter, b
        if adapter != OVERFLOW and sum(1 for k in self._buckets if k != OVERFLOW) >= self.max_adapters:
            for k in [k for k, v in self._buckets.items() if k != OVERFLOW and self._idle(v, now)]:
                del self._buckets[k]
            if sum(1 for k in self._buckets if k != OVERFLOW) >= self.max_adapters:
                adapter = OVERFLOW
        b = self._buckets.get(adapter)
        if b is None:
            b = self._buckets[adapter] = _Bucket(recent=deque(maxlen=self.max_per_window))
        return adapter, b

    def _take(self, adapter: str, b: _Bucket) -> dict[str, Any]:
        s = {"adapter": adapter, "count": b.count, "first_at": b.first_at, "last_at": b.last_at}
        b.count, b.first_epoch, b.first_at, b.last_at = 0, 0.0, "", ""
        return s

    def observe(self, adapter: str, now: float, at_iso: str) -> tuple[str, bool, list[dict[str, Any]]]:
        """Account one rejection. Returns (the bucket name it was counted under, whether to write an individual
        record, summaries now due for that bucket)."""
        with self._lock:
            name, b = self._bucket(adapter, now)
            due = [self._take(name, b)] if b.count and now - b.first_epoch >= self.window_s else []
            while b.recent and now - b.recent[0] >= self.window_s:
                b.recent.popleft()
            if len(b.recent) < self.max_per_window:
                b.recent.append(now)
                return name, True, due
            if b.count == 0:
                b.first_epoch, b.first_at = now, at_iso
            b.count += 1
            b.last_at = at_iso
            return name, False, due

    def pending_summaries(self, now: float) -> list[dict[str, Any]]:
        """Take every summary that is due, and forget idle names (bounded by max_adapters + 1)."""
        with self._lock:
            out = [self._take(k, b) for k, b in self._buckets.items()
                   if b.count and now - b.first_epoch >= self.window_s]
            for k in [k for k, b in self._buckets.items() if self._idle(b, now)]:
                del self._buckets[k]
            return out


# ---- the daemon's recorder --------------------------------------------------------------------------------------

class TokenRejections:
    """`daemon.tamper`: records rejected bearer tokens. Never raises into the request path for a recording problem
    (the caller still guards it); never keeps the presented token."""

    def __init__(self, daemon: Any, *, now: Callable[[], float] = time.time):
        self.daemon = daemon
        self._now = now
        self.limiter = RejectionLimiter()
        self.expected = RejectionLimiter()      # same bound for previous-token rejections; no summary is written

    def _grace(self, now: float) -> tuple[float | None, str]:
        """(time of a `token_rotate` within grace or None, the newest grace action name or "")."""
        actions = getattr(self.daemon, "operator_actions", None)
        if actions is None:
            return None, ""
        hit = actions.explains("token_rejected", now)
        if hit is None:
            return None, ""
        if hit["action"] == "token_rotate":
            return hit["at"], hit["action"]
        for e in reversed(actions.recent()):        # a rotation followed by a selftest (bounded deque)
            if e["action"] == "token_rotate" and 0 <= now - e["at"] < GRACE_S:
                return e["at"], hit["action"]
        return None, hit["action"]

    def _previous_sha256(self) -> str:
        provider = getattr(self.daemon, "baseline_provider", None)
        try:
            baseline = provider() if provider is not None else getattr(self.daemon, "baseline", None)
        except Exception:  # an unreadable baseline must not break the 401
            log.exception("cannot read the integrity baseline for a token rejection")
            baseline = getattr(self.daemon, "baseline", None)
        return str(getattr(baseline, "token_sha256_previous", "") or "")

    def _write(self, rec: dict[str, Any]) -> dict[str, Any]:
        self.daemon.spool.append(rec)
        otel = getattr(self.daemon, "otel", None)
        if otel is not None:
            otel.submit(rec)
        return rec

    def _summaries(self, due: list[dict[str, Any]], at: str) -> list[dict[str, Any]]:
        m = {**records.meta(self.daemon), "at": at}
        return [self._write(records.token_rejected_summary(s["adapter"], s["count"], s["first_at"], s["last_at"], **m))
                for s in due]

    def token_rejected(self, adapter: str, addr: str, presented: str) -> dict[str, Any] | None:
        """Record one rejection. Returns the individual record written, or None when it was collapsed."""
        now = self._now()
        at = iso(now)
        rotated_at, grace_action = self._grace(now)
        kind = (classify_rejection(presented, self._previous_sha256(), rotated_at, now)
                if rotated_at is not None else "token_rejected")
        m = {**records.meta(self.daemon), "at": at}
        if kind == "expected_after_rotate":
            _, write, _ = self.expected.observe(adapter, now, at)
            return self._write(records.expected_after_rotate(adapter, addr, **m)) if write else None
        name, write, due = self.limiter.observe(adapter, now, at)
        self._summaries(due, at)
        if grace_action == "selftest":
            log.debug("token rejection for %s within a selftest grace period", name)
        return self._write(records.token_rejected(name, addr, **m)) if write else None

    def pending_summaries(self, now: float | None = None) -> list[dict[str, Any]]:
        """HookWatch's pass: write every summary that is due and return the records written."""
        t = self._now() if now is None else now
        self.expected.pending_summaries(t)          # previous-token collapses are dropped, not summarised
        return self._summaries(self.limiter.pending_summaries(t), iso(t))
