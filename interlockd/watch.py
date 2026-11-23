"""Hook watch: the daemon re-checks its enforcement points, token, policy and identity file every 10 seconds.

Each pass (Requirements 5.5-5.9, 5.14, 8.3-8.11):

1. Shims an upgrade left behind (only their version line differs) are refreshed in place, but only when the
   installed package's shims carry the running daemon's version; a daemon older than the installed package leaves
   them alone ("upgrade pending: run interlock restart"), because a newer shim refuses an older daemon.
2. Every harness in the install manifest is checked through `daemon.verifier` (stat-cached, so an unchanged
   enforcement point costs two `os.stat` calls). A modified shim is a Tamper_Event and is rewritten from the
   installed package (`control.shim_repaired`; a failed rewrite is `control.shim_repair_failed` with an errno code,
   recorded once per cause and retried every pass); the harness stays `compromised` until `interlock ack` or
   `interlock init`. A hook config that no longer runs the shim is one Tamper_Event and is never edited: changing an
   agent's own settings without the Operator is the behaviour Interlock refuses.
3. The token: owner-only mode (restored at once; `control.token_permissions` notes a failed restore, which is retried
   each pass), digest against the baseline (`control.token_modified`), presence (`control.token_missing`; no
   replacement is created).
4. `daemon.policy_guard.check()` (policy and managed-policy pins, Requirement 7).
5. `<Home>/identity`: rewritten from the daemon's in-memory value when missing or altered (`control.identity_restored`,
   Home reason `identity_missing`), since every new shim refuses every call without it.
6. Token-rejection summaries that are due (`daemon.tamper.pending_summaries`).

One event per distinct observed condition (8.10): every problem is keyed `(subject, reason)` with a fingerprint (a
digest, a mode, or a fixed code). A Tamper_Event is written when the fingerprint differs from the previous pass's
observation; an unchanged condition writes nothing further. A reason that is already unresolved when this watch first
observes it (restored from `protection-state.json`, or raised on the hot path since the last pass) already has its
event, so it is not recorded twice. A change an Operator_Action explains (`operator.EXPLAINS`, 120 s grace) raises no
Tamper_Event; the baseline moves to what is on disk instead.

Without the integrity wiring (`daemon.protection` and `daemon.verifier`, absent on bare daemons in tests and embedded
uses) the watch does what it did before this feature: hook and shim changes and repairs become control records,
nothing is rewritten except upgrade leftovers. Every step is isolated: an exception is logged and the pass and the
loop continue.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Protocol

from . import __version__, records
from .insights import expected_shim

INTERVAL_S = 10.0
_OWN_EVENTS_MAX = 4096
log = logging.getLogger("interlockd.watch")
_PACKAGED_VERSION = re.compile(r'^(?:const )?VERSION\s*=\s*"([^"]*)";?$', re.MULTILINE)


def _read(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _sha256(data: str | bytes | None) -> str:
    if data is None:
        return ""
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def _errno(e: OSError) -> str:
    from .statefile import _errno_name

    return _errno_name(e)


def packaged_shims_current() -> bool:
    """True when every packaged shim source names the running daemon's version (`__version__`, read at call time,
    so a package upgraded under a running daemon is noticed)."""
    from .cli import CLAUDE_SHIM_SRC, HOOK_SHIMS, PY_SHIM_SRC

    for src in {CLAUDE_SHIM_SRC, PY_SHIM_SRC, *HOOK_SHIMS.values()}:
        try:
            m = _PACKAGED_VERSION.search(Path(src).read_text(encoding="utf-8"))
        except OSError:
            return False
        if m is None or m.group(1) != __version__:
            return False
    return True


def rewrite_shim(path: Path, text: str) -> str | None:
    """Replace `path` with `text` atomically: a temp file in the same directory, mode 0755 as `interlock init`
    writes shims, then `os.replace` (which replaces a planted symlink instead of writing through it). Returns an
    errno code on failure (never an exception message), None on success."""
    tmp = path.with_name(path.name + ".interlock-repair")
    try:
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o755)
        os.replace(tmp, path)
    except OSError as e:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return _errno(e)
    return None


class Notifier(Protocol):
    """Wakes the watch loop early when a watched file changes. The 10 s pass runs whatever the notifier does, so a
    failed or lost subscription degrades detection to the 10 s bound, never to none (5.6)."""

    def start(self, wake: Callable[[], None]) -> None: ...

    def stop(self) -> None: ...

    def changed(self) -> bool:
        """After an early wake: whether a pass should run now."""
        ...


class PollingNotifier:
    """The default: no subscription; the loop runs a pass every interval."""

    def start(self, wake: Callable[[], None]) -> None:
        return None

    def stop(self) -> None:
        return None

    def changed(self) -> bool:
        return True


WATCH_ENV = "INTERLOCK_WATCH"        # "watchfiles" opts in to the interlockd[watch] notifier


def watched_paths(home: Path) -> list[Path]:
    """The files whose change should wake the watch: the install manifest (so `init` re-targets), token, policy,
    managed policy, identity, and every shim and hook config the manifest names."""
    from . import identity, integrity
    from .onboard import MANIFEST, Manifest

    home = Path(home)
    paths = [home / name for name in (MANIFEST, integrity.TOKEN_FILE, integrity.POLICY_FILE,
                                      integrity.MANAGED_POLICY_FILE, identity.FILE)]
    try:
        man = Manifest.load(home)
    except Exception:
        log.exception("cannot read the install manifest for the file watcher")
        man = None
    for hk in (man.hooks if man else []):
        if isinstance(hk, dict):
            paths += [Path(hk[k]) for k in ("marker", "file") if isinstance(hk.get(k), str) and hk[k]]
    return paths


def _canonical(path: str) -> str:
    return os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))


class WatchfilesNotifier:
    """The `interlockd[watch]` extra: a `watchfiles` subscription on the directories holding the watched files
    (non-recursive) wakes the loop as soon as one of those files changes. Events for other entries in the same
    directories (`hook.log`, the spool, temp files) are filtered out; bursts are coalesced by `debounce_ms`.

    Constructing it imports `watchfiles`; ImportError means the extra is absent and the caller uses PollingNotifier.
    The subscription runs in a daemon thread and re-reads `paths_provider` every `refresh_ms` (an `init` or
    `uninstall` changes what to watch). A watcher error is logged and ends the subscription; the 10 s pass keeps
    running, so detection degrades to the polling bound (5.6)."""

    def __init__(self, paths_provider: Callable[[], Iterable[Path | str]], *, debounce_ms: int = 250,
                 refresh_ms: int = 5000):
        # ImportError: the extra is not installed
        import watchfiles

        self._watch = watchfiles.watch
        self._paths = paths_provider
        self.debounce_ms, self.refresh_ms = debounce_ms, refresh_ms
        self._stop = threading.Event()
        self._pending = threading.Event()
        self._thread: threading.Thread | None = None
        self.failed = False                     # True after a watcher error ended the subscription

    def _targets(self) -> tuple[frozenset[str], tuple[str, ...]]:
        """(canonical watched file paths, existing directories to subscribe to)."""
        files: set[str] = set()
        dirs: set[str] = set()
        for p in self._paths():
            p = Path(p).expanduser()
            parent = os.path.realpath(p.parent)
            if os.path.isdir(parent):
                files.add(os.path.join(parent, p.name))
                dirs.add(parent)
        return frozenset(files), tuple(sorted(dirs))

    def start(self, wake: Callable[[], None]) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self.failed = False
        self._thread = threading.Thread(target=self._run, args=(wake,), name="interlock-hook-watch-files",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t, self._thread = self._thread, None
        if t is not None and t is not threading.current_thread():
            t.join(timeout=2.0)

    def changed(self) -> bool:
        """True once per batch of changes to a watched file; a wake from elsewhere does not force a pass."""
        if self._pending.is_set():
            self._pending.clear()
            return True
        return False

    def _run(self, wake: Callable[[], None]) -> None:
        try:
            while not self._stop.is_set():
                files, dirs = self._targets()
                if not dirs:
                    self._stop.wait(self.refresh_ms / 1000)
                    continue

                def keep(_change: Any, path: str, files: frozenset[str] = files) -> bool:
                    return _canonical(path) in files

                for changes in self._watch(*dirs, watch_filter=keep, debounce=self.debounce_ms,
                                           stop_event=self._stop, recursive=False, yield_on_timeout=True,
                                           rust_timeout=self.refresh_ms, raise_interrupt=False):
                    if changes:
                        self._pending.set()
                        wake()
                    if self._stop.is_set() or self._targets() != (files, dirs):
                        break                   # stopping, or re-subscribe to the new set of directories
                else:
                    self._stop.wait(self.refresh_ms / 1000)   # the watcher ended on its own: do not spin
        except Exception:
            self.failed = True
            log.exception("file watcher failed; the hook watch keeps polling every %.0f s", INTERVAL_S)


def make_notifier(home: Path, *, enabled: bool | None = None) -> Notifier:
    """WatchfilesNotifier when enabled (`INTERLOCK_WATCH=watchfiles` unless `enabled` is given) and the
    `interlockd[watch]` extra is installed; PollingNotifier otherwise."""
    if enabled is None:
        enabled = os.environ.get(WATCH_ENV, "").strip().lower() == "watchfiles"
    if not enabled:
        return PollingNotifier()
    try:
        return WatchfilesNotifier(partial(watched_paths, Path(home)))
    except ImportError:
        log.warning("%s=watchfiles but the interlockd[watch] extra is not installed; polling every %.0f s",
                    WATCH_ENV, INTERVAL_S)
        return PollingNotifier()


@dataclass
class _Pass:
    at: str
    rows: list[dict[str, str]] = field(default_factory=list)          # install manifest entries, read once
    out: list[dict[str, Any]] = field(default_factory=list)
    seen: dict[tuple[str, str], str] = field(default_factory=dict)   # (subject, reason) -> fingerprint
    subjects: set[str] = field(default_factory=set)                   # observed this pass (absent key == intact)
    settled: set[str] = field(default_factory=set)    # harnesses whose modified shim this pass rewrote or re-baselined


class HookWatch:
    def __init__(self, daemon: Any, home: Path, *, interval: float = INTERVAL_S, notifier: Notifier | None = None):
        self.daemon, self.home, self.interval = daemon, Path(home), interval
        self.notifier: Notifier = notifier or PollingNotifier()
        self.state: dict[str, str] | None = None     # harness -> primary problem ("" intact); None before a pass
        self._seen: dict[tuple[str, str], str] = {}   # the last pass's fingerprints
        self._subjects: set[str] = set()              # the subjects the last pass observed
        self._own: set[str] = set()                   # event ids of the Tamper_Events this watch wrote
        self._last_pass_at = ""
        self._repair_failed: dict[str, str] = {}      # shim path -> cause last recorded
        self._upgrade_pending_logged = False
        self._refresh_sigs: tuple | None = None       # stat signatures at the last upgrade-leftover refresh
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()                 # one pass at a time (loop thread vs. an explicit check())

    # ---- wiring -------------------------------------------------------------------------------------------------

    @property
    def _protection(self) -> Any:
        return getattr(self.daemon, "protection", None)

    def _wired(self) -> bool:
        return self._protection is not None and getattr(self.daemon, "verifier", None) is not None

    def _baseline(self) -> Any:
        provider = getattr(self.daemon, "baseline_provider", None)
        b = provider() if callable(provider) else None
        return b if b is not None else getattr(self.daemon, "baseline", None)

    def _rebaseline(self, base: Any, change: Callable[[Any], None]) -> None:
        """Move the baseline to what is on disk after an explained change (11.2), in memory and in the file."""
        change(base)
        mem = getattr(self.daemon, "baseline", None)
        if mem is not None and mem is not base:
            change(mem)
        base.save(self.home, on_error=self._state_write_failed)

    def _explains(self, change_kind: str) -> bool:
        ops = getattr(self.daemon, "operator_actions", None)
        return ops is not None and ops.explains(change_kind) is not None

    def _meta(self, p: _Pass) -> dict[str, Any]:
        return {**records.meta(self.daemon), "at": p.at}

    def _emit(self, rec: dict[str, Any], p: _Pass) -> None:
        self.daemon.spool.append(rec)
        if getattr(self.daemon, "otel", None) is not None:
            self.daemon.otel.submit(rec)
        p.out.append(rec)

    def _state_write_failed(self, file: str, reason: str) -> None:
        self.daemon.spool.append(records.state_write_failed(file, reason, **records.meta(self.daemon)))

    # ---- the pass -----------------------------------------------------------------------------------------------

    def check(self) -> list[dict[str, Any]]:
        """One pass. Returns the control records it wrote (protection-state changes are recorded by
        ProtectionState and are not included). The first pass records only problems."""
        with self._lock:
            p = _Pass(at=records.now_iso())
            try:
                p.rows = self._manifest_rows()
            except Exception:
                log.exception("cannot read the install manifest")
            steps = [self._refresh_outdated, self._enforcement_points]
            if self._wired():
                steps += [self._token, self._policy, self._identity, self._summaries]
            for step in steps:
                try:
                    step(p)
                except Exception:
                    log.exception("hook watch step %s failed", step.__name__)
            self._seen, self._subjects, self._last_pass_at = p.seen, p.subjects, p.at
            return p.out

    def _changed(self, p: _Pass, subject: str, reason: str, fp: str) -> bool:
        """Note this pass's fingerprint for `(subject, reason)`; True when it differs from the last pass's."""
        p.seen[(subject, reason)] = fp
        p.subjects.add(subject)
        return fp != self._prev(subject, reason)

    def _prev(self, subject: str, reason: str) -> str | None:
        """The last pass's fingerprint: "" when the subject was observed intact, None when never observed."""
        return self._seen.get((subject, reason), "" if subject in self._subjects else None)

    def _carry(self, p: _Pass, subject: str, reasons: Iterable[str]) -> None:
        """Keep the last pass's fingerprints for items of an observed subject that this pass could not observe, so
        `_prev` does not read them as intact next pass and an unchanged condition is not recorded again (8.10)."""
        for reason in reasons:
            fp = self._seen.get((subject, reason))
            if fp is not None:
                p.seen[(subject, reason)] = fp

    def _record(self, p: _Pass, subject: str, reason: str, build: Callable[[], dict[str, Any]]) -> dict | None:
        """Write the Tamper_Event for a changed condition and attach the reason, unless the reason is already
        unresolved with an event this watch has not seen superseded (restored, or raised on the hot path)."""
        ps = self._protection
        if ps is None:                                   # unwired: every change is recorded, as before
            rec = build()
            self._emit(rec, p)
            return rec
        open_reason = next((r for r in ps.reasons() if r.subject == subject and r.reason == reason), None)
        if open_reason is not None:
            ours = open_reason.event_id in self._own
            older = open_reason.detected_at[:19] < self._last_pass_at[:19]
            if self._prev(subject, reason) is None or not (ours or older):
                return None
        rec = build()
        self._emit(rec, p)
        if len(self._own) >= _OWN_EVENTS_MAX:
            self._own.clear()
        self._own.add(rec["event_id"])
        if open_reason is None:
            ps.add_reason(subject, reason, rec["event_id"], rec["received_at"])
        return rec

    def _observe(self, p: _Pass, subject: str, reason: str, fp: str, build: Callable[[], dict[str, Any]], *,
                 explained: Callable[[], bool] | None = None) -> None:
        if self._changed(p, subject, reason, fp) and not (explained is not None and explained()):
            self._record(p, subject, reason, build)

    # ---- 1. upgrade leftovers ------------------------------------------------------------------------------------

    def _refresh_outdated(self, p: _Pass) -> None:
        from .insights import refresh_outdated_shims

        if not packaged_shims_current():
            if not self._upgrade_pending_logged:
                log.warning("upgrade pending: the installed package's shims are not interlock %s; "
                            "run `interlock restart`", __version__)
                self._upgrade_pending_logged = True
            self._refresh_sigs = None
            return
        self._upgrade_pending_logged = False
        # Reading every shim and hook config is most of a pass's cost: skip it while the manifest and every shim
        # keep their stat signature (size, mtime, ctime, inode) since the last refresh.
        from .integrity import _sig
        from .onboard import MANIFEST

        def sigs() -> tuple:
            return _sig(self.home / MANIFEST), tuple(_sig(Path(hk["marker"])) for hk in p.rows)

        if sigs() == self._refresh_sigs:
            return
        for shim in refresh_outdated_shims(self.home):      # left by an upgrade: not tampering, so just refresh them
            log.info("refreshed %s for interlock %s", shim, __version__)
        self._refresh_sigs = sigs()

    # ---- 2. enforcement points -----------------------------------------------------------------------------------

    def _enforcement_points(self, p: _Pass) -> None:
        rows = p.rows
        current = self._verify_all(p, rows) if self._wired() else self._legacy(p)
        if self.state is not None:
            for name, problem in current.items():
                before = self.state.get(name, "")
                if before and not problem and name not in p.settled:
                    f = next((hk["file"] for hk in rows if hk["harness"] == name), "")
                    self._emit(records.hook_restored(name, f, before, **self._meta(p)), p)
        self.state = current

    def _manifest_rows(self) -> list[dict[str, str]]:
        from .onboard import Manifest

        man = Manifest.load(self.home)
        return [hk for hk in (man.hooks if man else [])
                if isinstance(hk, dict) and all(isinstance(hk.get(x), str) for x in ("harness", "file", "marker"))]

    def _legacy(self, p: _Pass) -> dict[str, str]:
        """insights.hook_integrity, one problem per harness: the behaviour before the integrity wiring."""
        from .insights import hook_integrity

        current: dict[str, str] = {}
        m = self._meta(p)
        for h in hook_integrity(self.home):
            name = h["harness"]
            problem = h["problem"] if h["problem"] in records.TAMPER_KINDS else ""   # shim_outdated: retried
            current[name] = problem
            p.subjects.add(name)
            if problem == "hook_removed":
                self._observe(p, name, problem, "removed",
                              partial(records.tamper_event, "hook_removed", name, h["file"], **m))
            elif problem:
                shim = Path(h["shim"])
                observed = _sha256(_read(shim))
                self._observe(p, name, problem, observed or "missing",
                              partial(records.tamper_event, problem, name, str(shim),
                                      _sha256(expected_shim(name, shim)), observed, **m))
        return current

    def _verify_all(self, p: _Pass, rows: list[dict[str, str]]) -> dict[str, str]:
        from . import integrity

        base = self._baseline()
        current: dict[str, str] = {}
        m = self._meta(p)
        if integrity._WINDOWS:
            # st_ctime is the creation time on Windows, so the Verifier's stat signature cannot see an in-place
            # edit that restores size and mtime; each pass re-reads every shim and hook config instead.
            self.daemon.verifier.invalidate()
        for name in dict.fromkeys(hk["harness"] for hk in rows):
            entries = [hk for hk in rows if hk["harness"] == name]
            p.subjects.add(name)
            v = self.daemon.verifier.verify(name, None)
            problems = [x for x in (v.problems or ((v.problem,) if v.problem else ())) if x != "no_baseline"]
            pinned = base.shims.get(integrity.key(name), "") if base is not None else ""
            for problem in problems:
                if problem == "hook_removed":
                    path = v.path if v.problem == problem else entries[0]["file"]
                    self._observe(p, name, problem, "removed",
                                  partial(records.tamper_event, "hook_removed", name, path, **m),
                                  explained=partial(self._explains, "enforcement_point"))
                elif problem == "shim_missing":
                    path = v.path if v.problem == problem else entries[0]["marker"]
                    self._observe(p, name, problem, "missing",
                                  partial(records.tamper_event, "shim_missing", name, path, pinned, **m),
                                  explained=partial(self._explains, "enforcement_point"))
                elif problem == "shim_modified":
                    self._shim_modified(p, name, entries, v, pinned, base, m)
            if name in p.settled:
                problems.remove("shim_modified")
                p.seen.pop((name, "shim_modified"), None)      # intact again: a later edit is a new event
            current[name] = problems[0] if problems else ""
        return current

    def _shim_modified(self, p: _Pass, name: str, entries: list[dict[str, str]], v: Any, pinned: str, base: Any,
                       m: dict[str, Any]) -> None:
        from . import integrity
        from .insights import shim_state

        markers = list(dict.fromkeys(hk["marker"] for hk in entries))
        modified = [mk for mk in markers if integrity.file_sha256(Path(mk)) != pinned
                    and shim_state(Path(mk), name) == "shim_modified"] or [v.path or markers[0]]
        path = modified[0]
        observed = v.observed_sha256 if v.problem == "shim_modified" else integrity.file_sha256(Path(path))
        k = integrity.key(name)
        if self._changed(p, name, "shim_modified", observed or "unreadable"):
            if base is not None and observed and self._explains("enforcement_point"):
                # the Operator changed it (init, ack, uninstall within the grace period): the baseline follows
                self._rebaseline(base, lambda b: b.shims.__setitem__(k, observed))
                self.daemon.verifier.invalidate()
                p.settled.add(name)
                return
            self._record(p, name, "shim_modified",
                         lambda: records.tamper_event("shim_modified", name, path, pinned, observed, **m))
        if base is not None and observed and base.shims.get(k) == observed:
            return                                          # re-baselined in memory (the file save failed)
        if self._repair(p, name, modified, m):
            p.settled.add(name)

    def _repair(self, p: _Pass, name: str, shims: list[str], m: dict[str, Any]) -> bool:
        """Rewrite each modified shim from the installed package (5.8). False when any rewrite failed (5.14)."""
        ok = True
        current = packaged_shims_current()
        for mk in shims:
            path = Path(mk)
            text = expected_shim(name, path) if current else None
            cause = "upgrade_pending" if not current else ("no_packaged_shim" if text is None else None)
            if cause is None and text is not None:
                cause = rewrite_shim(path, text)
            if cause is None:
                self._repair_failed.pop(mk, None)
                self._emit(records.shim_repaired(name, mk, _sha256(_read(path)), **m), p)
                log.warning("rewrote the modified shim %s for %s from the installed package", mk, name)
                continue
            ok = False
            if self._repair_failed.get(mk) != cause:       # one record per distinct cause; retried every pass
                self._repair_failed[mk] = cause
                self._emit(records.shim_repair_failed(name, mk, cause, **m), p)
                log.warning("cannot rewrite the modified shim %s (%s); retrying every pass", mk, cause)
        if ok:
            self.daemon.verifier.invalidate()
        return ok

    # ---- 3. token ------------------------------------------------------------------------------------------------

    def _token(self, p: _Pass) -> None:
        from . import integrity
        from .protection import HOME

        base = self._baseline()
        problem, detail = integrity.token_check(self.home, base)   # restores a widened mode itself
        p.subjects.add(HOME)
        if not problem:
            return
        path = str(self.home / integrity.TOKEN_FILE)
        m = self._meta(p)
        pinned = base.token_sha256 if base is not None else ""
        if problem == "token_permissions":
            err = str(detail.get("restore_error") or "")
            if err:
                log.warning("cannot restore owner-only access to %s (%s); retrying every pass", path, err)
            observed = detail.get("observed_mode", -1)
            self._observe(p, HOME, problem, f"mode:{observed}",
                          lambda: records.tamper_event(problem, "", path, observed_mode=observed,
                                                       restored_mode=detail.get("restored_mode", -1),
                                                       restore_error=err, **m))
            if not err:
                p.seen.pop((HOME, problem), None)          # restored: owner-only again, a later widening is new
            # token_check stops at the mode, so the digest and presence were not observed. With the mode restored,
            # look again; otherwise keep the last pass's fingerprints (not observed is not intact, 8.10).
            if not err:
                problem, detail = integrity.token_check(self.home, base)
            if err or problem == "token_permissions":
                self._carry(p, HOME, ("token_modified", "token_missing"))
                return
            if not problem:
                return
        if problem == "token_modified":
            observed = str(detail.get("observed_sha256") or "")

            def explained() -> bool:
                if base is None or not self._explains("token"):
                    return False
                mode = integrity._token_mode(self.home / integrity.TOKEN_FILE)

                def change(b: Any) -> None:
                    b.token_sha256_previous, b.token_sha256, b.token_mode = b.token_sha256, observed, mode
                self._rebaseline(base, change)
                return True

            self._observe(p, HOME, problem, observed,
                          lambda: records.tamper_event(problem, "", path, pinned, observed, **m), explained=explained)
        else:
            self._carry(p, HOME, ("token_modified",))             # no digest to observe while it is missing
            fp = "unreadable" if detail.get("unreadable") else "missing"
            self._observe(p, HOME, "token_missing", fp,
                          lambda: records.tamper_event("token_missing", "", path, pinned, reason=f"token_{fp}", **m),
                          explained=lambda: self._explains("token"))

    # ---- 4. policy -----------------------------------------------------------------------------------------------

    def _policy(self, p: _Pass) -> None:
        guard = getattr(self.daemon, "policy_guard", None)
        if guard is not None:
            guard.check()

    # ---- 5. identity ---------------------------------------------------------------------------------------------

    def _identity(self, p: _Pass) -> None:
        from . import identity
        from .protection import HOME

        expected = getattr(self.daemon, "identity", None)
        if not isinstance(expected, str) or not expected:
            return
        p.subjects.add(HOME)
        if identity.read(self.home) == expected:
            return
        path = str(self.home / identity.FILE)
        try:
            identity.write(self.home, expected)
            outcome = "restored"
        except OSError as e:
            outcome = "restore_failed:" + _errno(e)
        except ValueError:
            outcome = "restore_failed:invalid"
        m = self._meta(p)
        if outcome == "restored":
            log.warning("rewrote the missing or altered %s", path)
            self._observe(p, HOME, "identity_missing", outcome, lambda: records.identity_restored(path, **m))
            p.seen.pop((HOME, "identity_missing"), None)   # intact again: a later deletion is a new event
        else:
            log.warning("cannot rewrite %s (%s); retrying every pass", path, outcome)
            self._observe(p, HOME, "identity_missing", outcome,
                          lambda: records.tamper_event("identity_missing", "", path, reason=outcome, **m))

    # ---- 6. token-rejection summaries ----------------------------------------------------------------------------

    def _summaries(self, p: _Pass) -> None:
        tamper = getattr(self.daemon, "tamper", None)
        if tamper is not None:
            p.out.extend(tamper.pending_summaries())

    # ---- loop ----------------------------------------------------------------------------------------------------

    def _safe_check(self) -> None:
        try:
            self.check()
        except Exception:
            log.exception("hook watch check failed")

    def wake(self) -> None:
        """For a Notifier: run a pass now instead of at the end of the interval."""
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            woken = self._wake.wait(self.interval)
            self._wake.clear()
            if self._stop.is_set():
                return
            try:
                due = not woken or self.notifier.changed()
            except Exception:
                log.exception("hook watch notifier failed")
                due = True
            if due:
                self._safe_check()

    def start(self) -> HookWatch:
        self._safe_check()                       # the first pass runs before the daemon serves (5.5, 8.11)
        try:
            self.notifier.start(self.wake)
        except Exception:
            log.exception("hook watch notifier did not start; polling every %.0f s", self.interval)
        threading.Thread(target=self._loop, name="interlock-hook-watch", daemon=True).start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        try:
            self.notifier.stop()
        except Exception:
            log.exception("hook watch notifier did not stop")
