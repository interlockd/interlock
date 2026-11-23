"""Protection_State: the daemon's one answer to "am I protected right now?" (Requirements 9 and 11.3, 11.11).

One in-memory object holds the unresolved reasons, per harness (`shim_modified`, `hook_removed`, ...) and for the
Home (`token_modified`, `policy_modified`, `state_unreadable`, ...), plus the Operator's `shadow` choice. States
are derived, never stored as truth:

- a harness is `compromised` when it has a reason, else `observing` in shadow mode, else `protected`;
- the aggregate is `compromised` when any reason exists, else `observing` in shadow mode, else `protected`.

`stopped` and `unknown` are never produced here: `interlock status` prints `stopped` when the daemon is down and a
Stop_Marker exists, the Console prints `unknown` when heartbeats stop.

Every change runs, under one lock and before the call returns: build a `control.protection_state` record
(`records.protection_state`), `spool.append`, `otel.submit`, write `protection-state.json` through `statefile`,
then call the subscribers. A verdict that caused the change therefore leaves after the record and the document are
durable, and a restart restores every `compromised` reason until the Operator clears it.

Persisted document (flat, one level of nesting, escape-free; harness names with "-" replaced by "_")::

    {"aggregate": "compromised", "events": {"claude_code__shim_modified": "01JD..."}, "last_tamper_at": "...",
     "observing": false, "reasons": {"claude_code__shim_modified": "2026-10-17T10:00:00Z"},
     "state_claude_code": "compromised", "updated_at": "...", "version": "0.2.0"}

`reasons` maps `<subject>__<reason>` to the detection time and `events` maps the same key to the Tamper_Event id.
`state_*` and `aggregate` are written for readers; on load they are recomputed from `reasons` and the mode.

A document that is present but cannot be trusted (unparseable, wrong type, wrong owner or mode) adds the Home
reason `state_unreadable` and is left in place: while that reason is unresolved the daemon keeps its state in
memory only and does not overwrite the file, so a restart finds it unreadable again and stays `compromised`.
Clearing `state_unreadable` (`interlock ack`) lifts the hold and the next write replaces the file.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__, records, statefile
from .onboard import HARNESSES, Manifest

STATES = records.STATES
HARNESS_REASONS = frozenset({"shim_modified", "shim_missing", "shim_relocated", "hook_removed"})
HOME_REASONS = frozenset({"token_modified", "token_missing", "token_permissions", "policy_modified",
                          "managed_policy_modified", "identity_missing", "state_unreadable"})
EP_REASONS = HARNESS_REASONS     # cleared by `interlock init` (Requirement 11.6)
FILE = "protection-state.json"
HOME = "home"
SEP = "__"

_REQUIRED = {"observing": bool, "reasons": dict, "events": dict}
_ISO = re.compile(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z?\Z")
_EVENT_ID = re.compile(r"^[0-9A-Za-z]{1,32}\Z")
_SUBJECTS = {h.replace("-", "_"): h for h in HARNESSES}

Subscriber = Callable[[dict[str, Any]], None]
log = logging.getLogger("interlockd.protection")


@dataclass(frozen=True)
class Reason:
    subject: str          # harness name or "home"
    reason: str
    detected_at: str      # ISO
    event_id: str         # the Tamper_Event's event_id ("" when unknown)

    @property
    def code(self) -> str:
        """The `subject:reason` code used in control records."""
        return f"{self.subject}:{self.reason}"


def key(subject: str) -> str:
    """A subject as it appears in document keys: harness names with "-" replaced by "_"."""
    return subject.replace("-", "_")


def _doc_key(r: Reason) -> str:
    return f"{key(r.subject)}{SEP}{r.reason}"


def _parse_key(k: str) -> tuple[str, str] | None:
    subject, sep, reason = k.partition(SEP)
    if not sep:
        return None
    if subject == HOME:
        return (HOME, reason) if reason in HOME_REASONS else None
    if reason not in HARNESS_REASONS or not re.match(r"^[a-z0-9][a-z0-9_]{0,31}\Z", subject):
        return None
    return _SUBJECTS.get(subject, subject.replace("_", "-")), reason


def _manifest_harnesses(home: Path) -> Callable[[], list[str]]:
    def provider() -> list[str]:
        try:
            m = Manifest.load(home)
        except (OSError, ValueError, TypeError):
            return []
        if m is None:
            return []
        return [h["harness"] for h in m.hooks if isinstance(h, dict) and isinstance(h.get("harness"), str)]
    return provider


class ProtectionState:
    """Per-harness and aggregate Protection_State. Thread-safe; every mutation is durable before it returns."""

    def __init__(self, home: Path, spool: Any, otel: Any, mode_provider: Callable[[], str], *,
                 notifier: Subscriber | None = None,
                 harnesses: Callable[[], Iterable[str]] | None = None,
                 meta_provider: Callable[[], records.Meta] | None = None):
        self.home = Path(home)
        self.path = self.home / FILE
        self.spool, self.otel = spool, otel
        self._mode = mode_provider
        self._harnesses = harnesses or _manifest_harnesses(self.home)
        self._meta = meta_provider or (lambda: {"mode": str(self._mode() or "")})
        self._lock = threading.RLock()
        self._reasons: dict[tuple[str, str], Reason] = {}
        self._observing = False
        self._last_tamper_at: str | None = None
        self._hold_file = False          # True while an untrusted document must stay in place (9.12)
        self._subscribers: list[Subscriber] = []
        if notifier is not None:
            self._subscribers.append(notifier)

    # ---- derivation -------------------------------------------------------------------------------------------

    def _shadow(self) -> bool:
        return self._observing or self._mode() == "shadow"

    def _subject_state(self, subject: str) -> str:
        if subject == HOME:
            return self._aggregate()
        if any(s == subject for s, _ in self._reasons):
            return "compromised"
        return "observing" if self._shadow() else "protected"

    def _aggregate(self) -> str:
        if self._reasons:
            return "compromised"
        return "observing" if self._shadow() else "protected"

    def harness_state(self, h: str) -> str:
        with self._lock:
            return self._subject_state(h)

    def aggregate(self) -> str:
        with self._lock:
            return self._aggregate()

    def reasons(self) -> list[Reason]:
        with self._lock:
            return sorted(self._reasons.values(), key=lambda r: (r.subject, r.reason))

    def _all_harnesses(self) -> list[str]:
        try:
            listed = list(self._harnesses())
        except Exception:  # a broken manifest must not stop the daemon from reporting state
            log.exception("cannot list harnesses from the manifest")
            listed = []
        extra = [s for s, _ in self._reasons if s != HOME]
        return sorted(set(listed) | set(extra))

    def snapshot(self) -> dict[str, Any]:
        """The view health, status, doctor and the Console heartbeat read (one source of truth, 9.10)."""
        with self._lock:
            harnesses = {}
            for h in self._all_harnesses():
                rs = sorted((r for r in self._reasons.values() if r.subject == h), key=lambda r: r.reason)
                harnesses[h] = {"state": self._subject_state(h),
                                "reasons": [{"reason": r.reason, "detected_at": r.detected_at} for r in rs]}
            home = sorted((r for r in self._reasons.values() if r.subject == HOME), key=lambda r: r.reason)
            return {"aggregate": self._aggregate(), "harnesses": harnesses,
                    "home_reasons": [{"reason": r.reason, "detected_at": r.detected_at} for r in home],
                    "last_tamper_at": self._last_tamper_at, "observing": self._observing}

    # ---- mutation ---------------------------------------------------------------------------------------------

    def add_reason(self, subject: str, reason: str, event_id: str, detected_at: str) -> bool:
        """Attach an unresolved reason. False (and nothing recorded) when the same reason is already unresolved."""
        if subject == HOME:
            if reason not in HOME_REASONS:
                raise ValueError(f"{reason!r} is not a Home reason")
        elif reason not in HARNESS_REASONS:
            raise ValueError(f"{reason!r} is not a harness reason")
        at = detected_at if isinstance(detected_at, str) and _ISO.match(detected_at) else records.now_iso()
        eid = event_id if isinstance(event_id, str) and _EVENT_ID.match(event_id) else ""
        with self._lock:
            if (subject, reason) in self._reasons:
                return False
            before = self._subject_state(subject)
            self._reasons[(subject, reason)] = Reason(subject, reason, at, eid)
            if self._last_tamper_at is None or at > self._last_tamper_at:
                self._last_tamper_at = at
            self._changed(subject, before, caused_by=eid)
            return True

    def clear(self, predicate: Callable[[Reason], bool], *, caused_by: str) -> list[Reason]:
        """Resolve every reason the predicate selects; returns them. Nothing is recorded when none matched."""
        with self._lock:
            gone = [r for r in self._reasons.values() if predicate(r)]
            if not gone:
                return []
            subjects = {r.subject for r in gone}
            subject = subjects.pop() if len(subjects) == 1 else HOME
            before = self._subject_state(subject)
            for r in gone:
                del self._reasons[(r.subject, r.reason)]
            if any(r.subject == HOME and r.reason == "state_unreadable" for r in gone):
                self._hold_file = False      # acknowledged: the next write replaces the unreadable document
            self._changed(subject, before, caused_by=caused_by)
            return sorted(gone, key=lambda r: (r.subject, r.reason))

    def set_observing(self, on: bool, *, caused_by: str) -> None:
        """The Operator's `shadow` (True) or `enforce` (False). Kept while `compromised` so it takes effect once
        the last reason clears (11.3)."""
        with self._lock:
            if bool(on) == self._observing:
                return
            before = self._aggregate()
            self._observing = bool(on)
            self._changed(HOME, before, caused_by=caused_by)

    def subscribe(self, cb: Subscriber) -> Callable[[], None]:
        """Call `cb(snapshot)` after every change. Returns a function that unsubscribes."""
        with self._lock:
            self._subscribers.append(cb)

        def unsubscribe() -> None:
            with self._lock:
                if cb in self._subscribers:
                    self._subscribers.remove(cb)
        return unsubscribe

    def _changed(self, subject: str, before: str, *, caused_by: str) -> None:
        """Called under the lock after a mutation: record, export, persist, notify, in that order."""
        rec = records.protection_state(subject, before, self._subject_state(subject),
                                       [r.code for r in self.reasons()], caused_by, **self._meta())
        self.spool.append(rec)
        if self.otel is not None:
            self.otel.submit(rec)
        self.save()
        snap = self.snapshot()
        for cb in list(self._subscribers):
            try:
                cb(snap)
            except Exception:  # a subscriber (notifier, heartbeat) must never break a verdict
                log.exception("protection-state subscriber failed")

    # ---- persistence ------------------------------------------------------------------------------------------

    def document(self) -> dict[str, Any]:
        with self._lock:
            doc: dict[str, Any] = {
                "aggregate": self._aggregate(),
                "events": {_doc_key(r): r.event_id for r in self._reasons.values()},
                "observing": self._observing,
                "reasons": {_doc_key(r): r.detected_at for r in self._reasons.values()},
                "updated_at": records.now_iso(),
                "version": __version__,
            }
            if self._last_tamper_at is not None:
                doc["last_tamper_at"] = self._last_tamper_at
            for h in self._all_harnesses():
                doc[f"state_{key(h)}"] = self._subject_state(h)
            return doc

    def save(self) -> bool:
        """Write `protection-state.json`. False when held (untrusted document left in place) or the write failed
        (recorded as `control.state_write_failed`; the in-memory state stays authoritative)."""
        with self._lock:
            if self._hold_file:
                return False
            return statefile.write_state(self.path, self.document(), on_error=self._write_failed)

    def _write_failed(self, file: str, reason: str) -> None:
        rec = records.state_write_failed(file, reason, **self._meta())
        try:
            self.spool.append(rec)
        except OSError:
            return
        if self.otel is not None:
            self.otel.submit(rec)

    @classmethod
    def load(cls, home: Path, spool: Any, otel: Any, mode_provider: Callable[[], str], **kw: Any) -> ProtectionState:
        """Restore from `protection-state.json` (9.5); start clean from the mode when absent (9.6); an untrusted
        document makes the Home `compromised` with `state_unreadable` and is left in place (9.12)."""
        ps = cls(home, spool, otel, mode_provider, **kw)
        problems: list[tuple[str, str]] = []
        doc = statefile.read_state(ps.path, _REQUIRED, on_error=lambda f, r: problems.append((f, r)))
        if doc is not None and not ps._restore(doc):
            problems.append((str(ps.path), "state_unreadable:bad_reason"))
        if problems:
            file, reason = problems[0]
            m = ps._meta()
            if reason.startswith("state_permissions:"):
                rec = records.state_permissions(file, reason, **m)
            else:
                rec = records.state_unreadable(file, reason, **m)
            spool.append(rec)
            if otel is not None:
                otel.submit(rec)
            with ps._lock:
                ps._hold_file = True
                ps.add_reason(HOME, "state_unreadable", rec["event_id"], rec["received_at"])
        return ps

    def _restore(self, doc: dict[str, Any]) -> bool:
        """Load reasons and the observing flag from a schema-valid document. False when an entry is malformed."""
        reasons, events = doc["reasons"], doc["events"]
        restored: dict[tuple[str, str], Reason] = {}
        for k, at in reasons.items():
            parsed = _parse_key(k)
            if parsed is None or not isinstance(at, str) or not _ISO.match(at):
                return False
            eid = events.get(k, "")
            if not isinstance(eid, str) or (eid and not _EVENT_ID.match(eid)):
                return False
            restored[parsed] = Reason(parsed[0], parsed[1], at, eid)
        last = doc.get("last_tamper_at")
        if last is not None and not (isinstance(last, str) and _ISO.match(last)):
            return False
        with self._lock:
            self._reasons = restored
            self._observing = doc["observing"]
            self._last_tamper_at = last
        return True
