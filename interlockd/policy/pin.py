"""Policy pinning: the policy and the managed policy are enforced as last pinned, never as last written (Req. 7).

The Integrity_Baseline holds the sha256 of each file's bytes (`policy_file_sha256`, `managed_policy_file_sha256`)
and `<Home>/pinned/` holds a byte-identical copy of what was pinned (directory 0700, files 0600). Only an
Operator_Action moves a pin: `interlock init|shadow|enforce|policy accept|policy revert`, `interlock ack`, an
in-session write the Operator approved (`ask` answered `allow`, 7.8), and for the managed file the Console sync.

`PolicyGuard.check` compares the on-disk digests with the pins (HookWatch calls it every pass; the daemon once at
start):

- no pin yet: pin what is on disk, record `control.policy_baseline_set` (7.3);
- equal: make sure the pinned copy exists; when a `policy_modified` reason was open, clear it and record
  `control.policy_restored` (7.13);
- different but explained by a recent Operator_Action (`operator.EXPLAINS`): pin the new file (11.2);
- different and unexplained: once per distinct on-disk digest, record `control.policy_modified` with the two digests
  and the top-level key names that changed (never values, 7.9) and set the Home reason `policy_modified` (or
  `managed_policy_modified`) (7.4).

`load_for_daemon` decides what the daemon enforces at start: the on-disk policy when it matches its pin, else the
pinned copy, else (no usable pinned copy) a deny-all lockdown in which every pre-tool call is refused with reason
`policy_modified` until the file is accepted or restored (7.12). While the daemon runs it keeps the policy it loaded;
a later unexplained edit is reported and not applied. The managed file is re-read without a restart, so
`ManagedPolicy` asks `PolicyGuard.managed_for` which document to apply (7.10).

Repository policies (`<repo>/.interlock/policy.yaml`) are not pinned: they are tighten-only unless the repository is
trusted, and a trusted repository loosening the policy is an accepted, documented gap.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import secrets
import stat
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from .. import records
from ..integrity import MANAGED_POLICY_FILE, POLICY_FILE, Baseline
from . import Policy, load_policy

log = logging.getLogger("interlockd.policy.pin")

PINNED_DIR = "pinned"
Kind = Literal["policy", "managed"]
KINDS: dict[str, str] = {"policy": POLICY_FILE, "managed": MANAGED_POLICY_FILE}
_FIELD = {"policy": "policy_file_sha256", "managed": "managed_policy_file_sha256"}
_REASON = {"policy": "policy_modified", "managed": "managed_policy_modified"}
_CHANGE = {"policy": "policy", "managed": "managed_policy"}       # operator.EXPLAINS keys
HOME_SUBJECT = "home"
PENDING_WRITE_S = 30.0          # an approved in-session write is pinned by its post hook; wait this long for it
MAX_PINNED_BYTES = 1024 * 1024
DENY_ALL_SHA256 = hashlib.sha256(b"interlock:policy_modified:deny_all").hexdigest()
DENY_ALL_NOTICE = ("[interlock] This action was NOT executed: the Interlock policy file was changed outside "
                   "Interlock and no pinned copy is available to enforce instead (policy_modified). Review {path}, "
                   "then run `interlock policy accept`.")

Source = Literal["disk", "pinned", "deny_all"]


def source_path(home: Path, kind: str) -> Path:
    return Path(home) / KINDS[kind]


def pinned_path(home: Path, kind: str) -> Path:
    return Path(home) / PINNED_DIR / KINDS[kind]


def file_sha256(path: Path) -> str | None:
    """sha256 hex of the file's bytes; None when absent or unreadable."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _read_regular(path: Path) -> bytes | None:
    """The bytes of a regular file (not a symlink, at most MAX_PINNED_BYTES), else None."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_PINNED_BYTES:
            return None
        with open(path, "rb") as f:
            return f.read(MAX_PINNED_BYTES + 1)
    except OSError:
        return None


def pinned_copy(home: Path, kind: str, expected_sha256: str | None = None) -> bytes | None:
    """The retained pinned copy; None when absent, not a regular file, or (with `expected_sha256`) when its digest
    is not the pinned digest, so a tampered copy is never enforced."""
    data = _read_regular(pinned_path(home, kind))
    if data is None or (expected_sha256 is not None and hashlib.sha256(data).hexdigest() != expected_sha256):
        return None
    return data


def _write_temp(dst: Path, data: bytes) -> Path:
    """A fsynced 0600 temp file next to `dst` (directory created 0700). Raises OSError."""
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(dst.parent, 0o700)
    tmp = dst.with_name(f".{dst.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except OSError:
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    os.close(fd)
    return tmp


def _copy_baseline(b: Baseline) -> Baseline:
    return dataclasses.replace(b, shims=dict(b.shims), hooks=dict(b.hooks))


def pin(home: Path, kind: str, *, baseline: Baseline) -> str:
    """Pin the file on disk now: copy it byte-for-byte to `pinned/`, store its digest in the baseline and save the
    baseline. An absent file pins as "" (no pin) and removes the copy. Returns the digest.

    All or nothing (7.11): the copy is staged in a temp file, the baseline is saved, then the copy is renamed into
    place; if a step fails the previous digest and the previous copy stay in effect and OSError is raised. Other
    baseline fields are taken from the file when it is readable, so a concurrent token update is not overwritten.
    `baseline` (the caller's in-memory object) gets the new digest on success."""
    home = Path(home)
    field = _FIELD[kind]
    try:
        data: bytes | None = source_path(home, kind).read_bytes()
    except FileNotFoundError:
        data = None
    digest = hashlib.sha256(data).hexdigest() if data is not None else ""
    fresh = Baseline.load(home) or _copy_baseline(baseline)
    old = getattr(fresh, field)
    dst = pinned_path(home, kind)
    tmp = _write_temp(dst, data) if data is not None else None
    try:
        setattr(fresh, field, digest)
        if not fresh.save(home):
            raise OSError(f"cannot save {home / 'integrity-baseline.json'}")
        try:
            if tmp is not None:
                os.replace(tmp, dst)
                tmp = None
            else:
                dst.unlink(missing_ok=True)
        except OSError:
            setattr(fresh, field, old)
            fresh.save(home)                    # best effort: put the previous digest back
            raise
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
    setattr(baseline, field, digest)
    return digest


def _top_level(raw: bytes | None) -> tuple[dict[str, Any] | None, bool]:
    """(mapping, parsed). None bytes (absent file) is an empty mapping that parsed."""
    if raw is None:
        return {}, True
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError, ValueError, RecursionError):
        return None, False
    if data is None:
        return {}, True
    if not isinstance(data, dict):
        return None, False
    return {str(k): v for k, v in data.items()}, True


def top_level_diff(pinned: bytes | None, on_disk: bytes | None) -> dict[str, Any]:
    """{"added", "removed", "changed", "unparseable"} over the top-level keys of the two YAML documents. Key names
    only (7.9). `unparseable` is True when the on-disk file is present but is not a YAML mapping; the key lists are
    then empty. A pinned copy that cannot be read or parsed compares as an empty mapping."""
    a, _ = _top_level(pinned)
    b, ok = _top_level(on_disk)
    if not ok or b is None:
        return {"added": [], "removed": [], "changed": [], "unparseable": True}
    a = a or {}
    return {"added": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)),
            "changed": sorted(k for k in set(a) & set(b) if a[k] != b[k]), "unparseable": False}


# ------------------------------------------------------------------------------------------------ start-up load


@dataclass(frozen=True)
class PolicyLoad:
    policy: Policy
    source: Source               # what the daemon enforces: the on-disk file, the pinned copy, or deny-all
    pinned_sha256: str
    on_disk_sha256: str          # "" when the file is absent


def _rehash(pol: Policy) -> None:
    """Policy.sha256 exactly as load_policy computes it."""
    h = hashlib.sha256()
    h.update(pol.model_dump_json(exclude={"source_paths", "sha256"}).encode())
    if pol.mandate.cedar and Path(pol.mandate.cedar).exists():
        h.update(Path(pol.mandate.cedar).read_bytes())
    pol.sha256 = h.hexdigest()


def _load_pinned(workspace: str | None, home: Path) -> Policy:
    """The policy with the pinned copy as the home layer (repository layer unchanged). A relative `mandate.cedar` in
    the home layer still resolves against the Home, not against `pinned/`."""
    pdir = home / PINNED_DIR
    pol = load_policy(workspace, home=pdir)
    if pol.mandate.cedar:
        cedar = Path(pol.mandate.cedar)
        for root in {pdir.resolve(), pdir}:
            try:
                rel = cedar.relative_to(root)
            except ValueError:
                continue
            pol.mandate.cedar = str((home / rel).resolve())
            _rehash(pol)
            break
    return pol


def deny_all_policy() -> Policy:
    """What the daemon serves when the policy was modified and no pinned copy can be enforced (7.12). The refusal
    itself is applied by the pipeline (`PolicyGuard.lockdown`), so it covers tier-0 calls too."""
    pol = Policy(mode="enforce")
    pol.sha256 = DENY_ALL_SHA256
    return pol


def load_for_daemon(settings: Any, baseline: Baseline | None) -> PolicyLoad:
    """The policy the daemon enforces at start. Without a baseline, the pinned copy's own digest is the pin (a deleted
    baseline must not turn an edited policy into the accepted one). Errors loading the on-disk policy when it matches
    its pin propagate as before (the daemon does not start on an invalid policy)."""
    home = Path(settings.home)
    roots = list(getattr(settings, "workspace_roots", None) or [])
    ws = roots[0] if roots else None
    on_disk = file_sha256(home / POLICY_FILE) or ""
    if baseline is not None:
        pinned = baseline.policy_file_sha256
    else:
        copy = pinned_copy(home, "policy")
        pinned = hashlib.sha256(copy).hexdigest() if copy is not None else ""
    if not pinned or on_disk == pinned:
        return PolicyLoad(load_policy(ws, home=home), "disk", pinned, on_disk)
    if pinned_copy(home, "policy", pinned) is not None:
        try:
            return PolicyLoad(_load_pinned(ws, home), "pinned", pinned, on_disk)
        except (OSError, ValueError, TypeError, yaml.YAMLError) as e:
            log.warning("pinned policy copy does not load (%s); serving deny-all", type(e).__name__)
    return PolicyLoad(deny_all_policy(), "deny_all", pinned, on_disk)


# ------------------------------------------------------------------------------------------------ guard


class PolicyGuard:
    """Compares the on-disk policy files with their pins and owns the `policy_modified` and
    `managed_policy_modified` Home reasons. Thread-safe (one re-entrant lock: HookWatch, hook requests and the
    managed-policy reader all come through here)."""

    def __init__(self, home: Path, baseline_provider: Callable[[], Baseline | None], protection: Any = None,
                 operator: Any = None, *, spool: Any, otel: Any = None,
                 meta: Callable[[], records.Meta] | None = None,
                 on_pinned: Callable[[str, str], None] | None = None,
                 reload: Callable[[], None] | None = None, clock: Callable[[], float] = time.time):
        self.home = Path(home)
        self._baseline = baseline_provider
        self.protection = protection
        self.operator = operator
        self.spool, self.otel = spool, otel
        self._meta = meta or dict
        self._on_pinned = on_pinned
        self._reload = reload
        self._clock = clock
        self._lock = threading.RLock()
        self._reported: dict[str, str] = {}            # kind -> on-disk digest already recorded as modified
        self._last_diff: dict[str, dict[str, Any]] = {}
        self._source: Source = "disk"
        self._writes: deque[dict[str, Any]] = deque(maxlen=64)   # pre-tool writes to the policy file

    # ---- state ---------------------------------------------------------------------------------------------------

    @property
    def source(self) -> Source:
        return self._source

    @property
    def lockdown(self) -> bool:
        """True while the daemon serves deny-all because no pinned copy could be enforced (7.12)."""
        return self._source == "deny_all"

    def adopt(self, load: PolicyLoad) -> None:
        with self._lock:
            self._source = load.source

    def pinned_sha256(self, kind: str) -> str:
        b = self._baseline()
        return getattr(b, _FIELD[kind]) if b is not None else ""

    def status(self) -> dict[str, Any]:
        """For health / status / doctor: digests, changed key names, and what is being enforced."""
        out: dict[str, Any] = {"source": self._source, "lockdown": self.lockdown}
        for kind in KINDS:
            out[kind] = {"pinned_sha256": self.pinned_sha256(kind),
                         "on_disk_sha256": file_sha256(source_path(self.home, kind)) or "",
                         "changed_keys": dict(self._last_diff.get(kind) or {})}
        return out

    def policy_realpath(self) -> str:
        return os.path.normcase(os.path.realpath(source_path(self.home, "policy")))

    # ---- checks --------------------------------------------------------------------------------------------------

    def check(self, now: float | None = None) -> None:
        """One comparison of both files with their pins (HookWatch pass, daemon start)."""
        for kind in KINDS:
            try:
                self._evaluate(kind, now)
            except Exception:  # a broken check must not stop the watch loop
                log.exception("policy pin check failed for %s", kind)

    def managed_for(self, on_disk: Any, previous: Any = None) -> Any:
        """The managed document to apply (`policy.managed.Managed` or None) given what was read from disk: the
        on-disk document when it is pinned or explained by the Console sync, else the pinned copy, else the
        document applied before (or, with nothing applied yet, the on-disk one: the managed layer only tightens)."""
        from .managed import parse_managed

        if self._evaluate("managed"):
            return on_disk
        pinned = self.pinned_sha256("managed")
        copy = pinned_copy(self.home, "managed", pinned) if pinned else None
        if copy is not None:
            return parse_managed(str(pinned_path(self.home, "managed")), copy)
        return previous if previous is not None else on_disk

    def _evaluate(self, kind: str, now: float | None = None) -> bool:
        """True when the on-disk file may be applied; False when the pin stays in effect."""
        t = self._clock() if now is None else now
        with self._lock:
            b = self._baseline()
            if b is None:
                return True
            on_disk = file_sha256(source_path(self.home, kind)) or ""
            pinned = getattr(b, _FIELD[kind])
            if not pinned:
                if on_disk:
                    self._pin(kind)                                # 7.3: first sight of the file
                return True
            if on_disk == pinned:
                self._ensure_copy(kind, pinned)
                self._resolved(kind, restored_sha256=pinned)       # 7.13 when a reason was open
                return True
            hit = self.operator.explains(_CHANGE[kind], t) if self.operator is not None else None
            if hit is not None:
                if self._pin(kind):
                    self._resolved(kind, caused_by=str(hit.get("event_id") or ""))
                    return True
                return False
            if kind == "policy" and self._write_pending(t):
                return False                    # an approved in-session write: its post hook pins it (7.8)
            if self._reported.get(kind) != on_disk:
                self._report(kind, pinned, on_disk)
            return False

    def _ensure_copy(self, kind: str, pinned: str) -> None:
        """The file matches its pin: (re)create a missing or altered pinned copy from it (first start of this
        version seeds the baseline without copies)."""
        if pinned_copy(self.home, kind, pinned) is not None:
            return
        try:
            data = source_path(self.home, kind).read_bytes()
            if hashlib.sha256(data).hexdigest() != pinned:
                return
            dst = pinned_path(self.home, kind)
            os.replace(_write_temp(dst, data), dst)
        except OSError as e:
            log.warning("cannot write the pinned copy of %s: %s", KINDS[kind], type(e).__name__)

    def _has_reason(self, reason: str) -> bool:
        if self.protection is None:
            return False
        return any(r.subject == HOME_SUBJECT and r.reason == reason for r in self.protection.reasons())

    def _resolved(self, kind: str, *, restored_sha256: str = "", caused_by: str = "") -> None:
        reason = _REASON[kind]
        was = self._reported.pop(kind, None) is not None
        open_reason = self._has_reason(reason)
        if (was or open_reason) and restored_sha256:
            rec = records.policy_restored(kind, str(source_path(self.home, kind)), restored_sha256, **self._meta())
            self._append(rec)
            caused_by = caused_by or rec["event_id"]
        if open_reason:
            self.protection.clear(lambda r: r.subject == HOME_SUBJECT and r.reason == reason, caused_by=caused_by)
        self._last_diff.pop(kind, None)
        if kind == "policy" and self._source != "disk":
            self._apply_disk()

    def _apply_disk(self) -> None:
        """Switch the daemon from the pinned copy or deny-all to the (now pinned) on-disk policy."""
        if self._reload is None:
            return
        try:
            self._reload()
        except Exception as e:  # noqa: BLE001 - keep enforcing what is loaded when the file does not load
            log.warning("pinned policy does not load (%s); keeping the policy in effect", type(e).__name__)
            return
        self._source = "disk"

    def _report(self, kind: str, pinned: str, on_disk: str) -> None:
        src = source_path(self.home, kind)
        diff = top_level_diff(pinned_copy(self.home, kind, pinned), _read_regular(src) if on_disk else None)
        rec = records.policy_modified(kind, str(src), pinned, on_disk, added=diff["added"], removed=diff["removed"],
                                      changed=diff["changed"], unparseable=diff["unparseable"], **self._meta())
        self._append(rec)
        self._reported[kind] = on_disk
        self._last_diff[kind] = diff
        if self.protection is not None:
            self.protection.add_reason(HOME_SUBJECT, _REASON[kind], rec["event_id"], rec["received_at"])

    def pin(self, kind: str) -> bool:
        """Daemon-side pin of the file on disk now (records `control.policy_baseline_set`; on failure the same
        record with `failed: true`, and the previous pin stays, 7.11)."""
        with self._lock:
            return self._pin(kind)

    def _pin(self, kind: str) -> bool:
        src = source_path(self.home, kind)
        b = self._baseline()
        if b is None:
            return False
        try:
            digest = pin(self.home, kind, baseline=b)
        except OSError as e:
            log.warning("policy pin for %s not updated: %s", KINDS[kind], type(e).__name__)
            self._append(records.policy_baseline_set(kind, str(src), file_sha256(src) or "", failed=True,
                                                     **self._meta()))
            return False
        if self._on_pinned is not None:
            self._on_pinned(kind, digest)
        self._append(records.policy_baseline_set(kind, str(src), digest, **self._meta()))
        return True

    def _append(self, rec: dict[str, Any]) -> None:
        self.spool.append(rec)
        if self.otel is not None:
            self.otel.submit(rec)

    # ---- in-session accept (7.8) ---------------------------------------------------------------------------------

    def _write_pending(self, now: float) -> bool:
        return any(w["asked"] and 0 <= now - w["at"] < PENDING_WRITE_S for w in self._writes)

    def targets_policy(self, paths: list[str]) -> bool:
        target = self.policy_realpath()
        for p in paths:
            try:
                if os.path.normcase(os.path.realpath(p)) == target:
                    return True
            except (OSError, ValueError):
                continue
        return False

    def observe_write(self, *, kind: str, session_id: str, call_id: str | None, tool: str, event_id: str,
                      disposition: str, mode: str, now: float | None = None) -> dict[str, Any] | None:
        """Called by the pipeline for a write tool whose path is the Home policy file. A pre-tool call is remembered;
        a post-tool call whose matching pre-tool call (same tool-call id, else the newest pre call with the same tool
        in the session) was `ask` in enforce mode means the Operator approved the write: pin the result and record
        `control.operator_action {policy_accept, via: hook_session, caused_by: <pre event id>}`. Returns that
        record, or None."""
        t = self._clock() if now is None else now
        with self._lock:
            if kind == "pre_action":
                self._writes.append({"session": session_id, "call_id": call_id or "", "tool": tool,
                                     "event_id": event_id, "asked": disposition == "ask" and mode == "enforce",
                                     "at": t})
                return None
            if kind != "post_action":
                return None
            match = None
            for w in reversed(self._writes):
                if w["session"] != session_id or w["tool"] != tool:
                    continue
                if call_id and w["call_id"] and w["call_id"] != call_id:
                    continue
                match = w
                break
            if match is None:
                return None
            self._writes.remove(match)
            if not match["asked"]:
                return None
            ok = self._pin("policy")
            state = self.protection.aggregate() if self.protection is not None else ""
            rec = records.operator_action("policy_accept", "", state, via="hook_session",
                                          caused_by=match["event_id"], confirmed=True, grace_s=0, failed=not ok,
                                          **self._meta())
            self._append(rec)
            if self.operator is not None:
                self.operator.add(rec)
            if ok:
                self._resolved("policy", caused_by=rec["event_id"])
            return rec
