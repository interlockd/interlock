"""Integrity_Baseline and hot-path verification of enforcement points (Requirements 5 and 8).

`Baseline` pins what `interlock init` (or `interlock ack`, or the first start of this version) found on disk: each
shim's sha256, the policy and managed-policy file digests, the token's digest and access mode. It is a flat
`statefile` document (`integrity-baseline.json`, 0600).

`Verifier` checks one harness's enforcement point (shim content and hook config) on every hook request. It keeps a
stat signature per file and re-reads and re-hashes a file only when the signature changes, so an unchanged
enforcement point costs one `os.stat` for the shim, one for the hook config, and a few dictionary lookups. The
signature includes `st_ctime_ns`, which a process cannot set back, so an in-place edit that restores the size and
mtime (`touch -r`) is still noticed. On Windows `st_ctime` is the creation time, so there the hot path can miss
such an edit and HookWatch re-reads every enforcement point on each pass (within 10 s) instead.

`token_check` and `restore_token_mode` are the token half (Requirement 8): owner-only mode on POSIX, the file ACL
through `icacls` on Windows.

Paths in the baseline: the statefile format only carries strings that JSON writes without escapes. Shim and token
digests are hex and always fit. Hook-config paths (`hook_<harness>`) are informational (the Verifier reads paths from
the install manifest), so on Windows they are stored with forward slashes, and a path that would still need an escape
(a quote, a control character, a non-ASCII character, a backslash on POSIX) is left out of the document rather than
failing the whole save.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, statefile
from .onboard import Manifest, mentions

BASELINE = "integrity-baseline.json"
POLICY_FILE = "policy.yaml"
MANAGED_POLICY_FILE = "managed-policy.yaml"
TOKEN_FILE = "token"
STAT_TTL_S = 2.0                 # how long cached_loader reuses a stat of the manifest / baseline file
_REALPATH_CACHE_MAX = 1024       # reported shim paths come from requests: bound the cache
_WINDOWS = sys.platform == "win32"

_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_REQUIRED: dict[str, type] = {
    "created_at": str, "version": str, "policy_file_sha256": str, "managed_policy_file_sha256": str,
    "token_sha256": str, "token_sha256_previous": str, "token_mode": int,
}
# One problem is reported per verification; when several hold, the most fundamental comes first.
_PRIORITY = ("hook_removed", "shim_missing", "shim_modified", "shim_relocated")

ErrorCallback = statefile.ErrorCallback


def key(harness: str) -> str:
    """The harness name as used in state-file keys: "-" becomes "_" ("claude-code" -> "claude_code")."""
    return harness.replace("-", "_")


def file_sha256(path: Path) -> str:
    """sha256 hex of the file's bytes, "" when the file is absent or unreadable."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def _storable_path(p: str) -> str | None:
    s = p.replace("\\", "/") if _WINDOWS else p
    return s if s and json.dumps(s) == '"' + s + '"' else None


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _token_mode(path: Path) -> int:
    if _WINDOWS:
        return -1
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return -1


def _hooks(manifest: Manifest | None) -> list[dict]:
    return [hk for hk in (manifest.hooks if manifest else [])
            if isinstance(hk, dict) and isinstance(hk.get("harness"), str)
            and isinstance(hk.get("file"), str) and isinstance(hk.get("marker"), str)]


# ------------------------------------------------------------------------------------------------ baseline


@dataclass
class Baseline:
    created_at: str = ""
    version: str = ""
    policy_file_sha256: str = ""            # "" when the file is absent
    managed_policy_file_sha256: str = ""    # "" when the file is absent
    token_sha256: str = ""
    token_sha256_previous: str = ""
    token_mode: int = -1                    # POSIX mode as an int (0o600 == 384); -1 on Windows (ACL check applies)
    shims: dict[str, str] = field(default_factory=dict)   # key(harness) -> sha256 of the shim's bytes
    hooks: dict[str, str] = field(default_factory=dict)   # key(harness) -> Hook_Config path (informational)

    def document(self) -> dict[str, Any]:
        doc: dict[str, Any] = {k: getattr(self, k) for k in _REQUIRED}
        for k, v in self.shims.items():
            if statefile.KEY_RE.match(f"shim_{k}"):
                doc[f"shim_{k}"] = v
        for k, v in self.hooks.items():
            if statefile.KEY_RE.match(f"hook_{k}") and (p := _storable_path(v)) is not None:
                doc[f"hook_{k}"] = p
        return doc

    def save(self, home: Path, *, on_error: ErrorCallback | None = None) -> bool:
        """Atomic 0600 write of `<home>/integrity-baseline.json`; False (and on_error) on failure. Never raises."""
        return statefile.write_state(Path(home) / BASELINE, self.document(), on_error=on_error)

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> Baseline | None:
        """None when a digest field is not "" or 64 lowercase hex (shim digests must be 64 hex)."""
        b = cls(**{k: doc[k] for k in _REQUIRED})
        for k in ("policy_file_sha256", "managed_policy_file_sha256", "token_sha256", "token_sha256_previous"):
            if getattr(b, k) and not _HEX64.match(getattr(b, k)):
                return None
        for k, v in doc.items():
            if k.startswith("shim_") and k not in _REQUIRED:
                if not isinstance(v, str) or not _HEX64.match(v):
                    return None
                b.shims[k[5:]] = v
            elif k.startswith("hook_") and isinstance(v, str):
                b.hooks[k[5:]] = v
        return b

    @classmethod
    def load(cls, home: Path, on_error: ErrorCallback | None = None) -> Baseline | None:
        """The baseline, or None when absent or unreadable (on_error is told which, as in statefile.read_state)."""
        path = Path(home) / BASELINE
        doc = statefile.read_state(path, _REQUIRED, on_error=on_error)
        if doc is None:
            return None
        b = cls.from_document(doc)
        if b is None and on_error is not None:
            on_error(str(path), "state_unreadable:bad_digest")
        return b

    @classmethod
    def from_disk(cls, home: Path, manifest: Manifest | None, *, previous: Baseline | None = None) -> Baseline:
        """Digests of what is on disk now (init, ack, first start). With `previous`, a changed token digest moves the
        previous one into `token_sha256_previous` (kept only for the rotation grace check)."""
        home = Path(home)
        b = cls(created_at=_now_iso(), version=__version__,
                policy_file_sha256=file_sha256(home / POLICY_FILE),
                managed_policy_file_sha256=file_sha256(home / MANAGED_POLICY_FILE),
                token_sha256=file_sha256(home / TOKEN_FILE), token_mode=_token_mode(home / TOKEN_FILE))
        if previous is not None:
            b.token_sha256_previous = (previous.token_sha256 if previous.token_sha256 != b.token_sha256
                                       else previous.token_sha256_previous)
        for hk in _hooks(manifest):
            k = key(hk["harness"])
            if k not in b.shims and (digest := file_sha256(Path(hk["marker"]))):
                b.shims[k] = digest            # first entry wins (Kiro may list one shim for several workspaces)
            if k not in b.hooks and (p := _storable_path(str(hk["file"]))) is not None:
                b.hooks[k] = p                 # the stored form (forward slashes on Windows), as load() returns it
        return b

    @classmethod
    def load_or_create(cls, home: Path, manifest: Manifest | None, *,
                       on_error: ErrorCallback | None = None) -> tuple[Baseline, bool]:
        """(baseline, created). When none can be loaded, seed one from disk and save it; on_error has been told
        whether the old file was absent or unreadable, so the caller can record the difference."""
        b = cls.load(home, on_error)
        if b is not None:
            return b, False
        b = cls.from_disk(home, manifest)
        b.save(home, on_error=on_error)
        return b, True


def cached_loader[T](path: Path, load: Callable[[], T | None], *, ttl_s: float = STAT_TTL_S,
                     clock: Callable[[], float] = time.monotonic) -> Callable[[], T | None]:
    """A provider for Verifier: re-runs `load` only when `path`'s stat signature changed, stats at most once per
    `ttl_s`. A load that raises or returns None after a good one keeps the last good value, so corrupting or
    deleting the manifest does not switch hot-path verification off (HookWatch reports such a file)."""
    lock = threading.Lock()
    state: dict[str, Any] = {"checked": float("-inf"), "sig": None, "value": None}

    def provider() -> T | None:
        now = clock()
        with lock:
            if now - state["checked"] < ttl_s:
                return state["value"]
            state["checked"] = now
            sig = _sig(Path(path))
            if sig != state["sig"]:
                state["sig"] = sig
                try:
                    value = load() if sig is not None else None
                except Exception:  # noqa: BLE001 - an unparseable file must not break the hot path
                    value = None
                if value is not None:
                    state["value"] = value
            return state["value"]

    return provider


# ------------------------------------------------------------------------------------------------ verifier


@dataclass(frozen=True)
class Verification:
    harness: str
    problem: str              # "" | "shim_modified" | "shim_missing" | "shim_relocated" | "hook_removed" | "no_baseline"
    expected_sha256: str = ""
    observed_sha256: str = ""
    path: str = ""            # the Interlock-owned shim or the Hook_Config concerned (never the request's string)
    problems: tuple[str, ...] = ()   # every problem found, in _PRIORITY order; `problem` is the first


def _sig(path: Path) -> tuple | None:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    except OSError:
        return ("unreadable",)
    return (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino, st.st_dev, stat.S_ISREG(st.st_mode))


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _normalize(text: str) -> str:
    """What Path.read_text sees (universal newlines), so CRLF shims written on Windows compare as insights does."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


class Verifier:
    """Hot-path check of one harness's enforcement point. One instance per daemon; thread-safe (one lock around the
    caches; files are stat'ed and read outside it)."""

    def __init__(self, home: Path, manifest_provider: Callable[[], Manifest | None],
                 baseline_provider: Callable[[], Baseline | None]):
        self.home = Path(home)
        self._manifest = manifest_provider
        self._baseline = baseline_provider
        self._lock = threading.Lock()
        self._seen_manifest: object = None
        self._shims: dict[tuple[str, str], tuple[tuple | None, str, str, str]] = {}  # -> (sig, pinned, problem, sha)
        self._configs: dict[tuple[str, str], tuple[tuple | None, bool]] = {}         # (file, marker) -> (sig, ok)
        self._real: dict[str, str | None] = {}
        self._expected: dict[tuple[str, str], tuple[str, str] | None] = {}

    def invalidate(self) -> None:
        """Forget every cached read (after init / ack rebuild the baseline)."""
        with self._lock:
            self._shims.clear()
            self._configs.clear()
            self._real.clear()
            self._expected.clear()

    def verify(self, harness: str, reported_shim: str | None = None) -> Verification:
        man = self._manifest()
        with self._lock:
            if man is not self._seen_manifest:
                self._seen_manifest = man
                self._real.clear()
        entries = [hk for hk in _hooks(man) if hk["harness"] == harness]
        if not entries:
            return Verification(harness, "no_baseline")
        base = self._baseline()
        pinned = base.shims.get(key(harness), "") if base is not None else ""
        found: list[tuple[str, str, str, str]] = []   # (problem, path, expected, observed)
        markers: list[str] = []
        for hk in entries:
            f, marker = hk["file"], hk["marker"]
            if f != marker and not self._config_ok(f, marker):   # OpenCode: the plugin file is the hook config
                found.append(("hook_removed", f, "", ""))
            if marker not in markers:
                markers.append(marker)
                problem, observed = self._shim(harness, marker, pinned)
                if problem:
                    found.append((problem, marker, pinned, observed))
        if isinstance(reported_shim, str) and reported_shim:
            real = self._realpath(reported_shim)
            if real is None or real not in {self._realpath(m) for m in markers}:
                found.append(("shim_relocated", markers[0], "", ""))
        if not found:
            return Verification(harness, "")
        found.sort(key=lambda t: _PRIORITY.index(t[0]))
        problem, path, expected, observed = found[0]
        return Verification(harness, problem, expected, observed, path, tuple(dict.fromkeys(t[0] for t in found)))

    # -------------------------------------------------------------------------------------------- pieces

    def _shim(self, harness: str, marker: str, pinned: str) -> tuple[str, str]:
        sig = _sig(Path(marker))
        ck = (harness, marker)
        with self._lock:
            hit = self._shims.get(ck)
        if hit is not None and hit[0] == sig and hit[1] == pinned:
            return hit[2], hit[3]
        if sig is None:
            problem, observed = "shim_missing", ""
        elif sig == ("unreadable",) or not sig[-1]:
            problem, observed = "shim_modified", ""          # not a readable regular file
        else:
            try:
                data = _read_bytes(marker)
            except FileNotFoundError:
                problem, observed = "shim_missing", ""
            except OSError:
                problem, observed = "shim_modified", ""
            else:
                observed = hashlib.sha256(data).hexdigest()
                problem = self._classify(harness, marker, data, observed, pinned)
        with self._lock:
            self._shims[ck] = (sig, pinned, problem, observed)
        return problem, observed

    def _classify(self, harness: str, marker: str, data: bytes, observed: str, pinned: str) -> str:
        """insights.shim_state semantics against the pinned digest: intact when the digest matches, or when the
        content is this version's packaged shim apart from its version line (what an upgrade leaves)."""
        if pinned and observed == pinned:
            return ""
        want = self._packaged(harness, marker)
        if want is None:
            return "shim_modified" if pinned else ""
        from .insights import _VERSION_LINE

        have = _normalize(data.decode("utf-8", errors="replace"))
        return "" if have == want[0] or _VERSION_LINE.sub("", have) == want[1] else "shim_modified"

    def _packaged(self, harness: str, marker: str) -> tuple[str, str] | None:
        ck = (harness, Path(marker).suffix)
        with self._lock:
            if ck in self._expected:
                return self._expected[ck]
        from .insights import _VERSION_LINE, expected_shim

        try:
            text = expected_shim(harness, Path(marker))
        except OSError:
            text = None
        want = None if text is None else (_normalize(text), _VERSION_LINE.sub("", _normalize(text)))
        with self._lock:
            self._expected[ck] = want
        return want

    def _config_ok(self, file: str, marker: str) -> bool:
        sig = _sig(Path(file))
        ck = (file, marker)
        with self._lock:
            hit = self._configs.get(ck)
        if hit is not None and hit[0] == sig:
            return hit[1]
        ok = False
        if sig is not None and sig != ("unreadable",) and sig[-1]:
            try:
                ok = mentions(_read_bytes(file).decode("utf-8", errors="replace"), marker)
            except OSError:
                ok = False
        with self._lock:
            self._configs[ck] = (sig, ok)
        return ok

    def _realpath(self, p: str) -> str | None:
        with self._lock:
            if p in self._real:
                return self._real[p]
        try:
            real = os.path.realpath(p) if len(p) <= 4096 else None
        except (OSError, ValueError):   # ValueError: embedded NUL
            real = None
        if real is not None:
            real = os.path.normcase(real)
        with self._lock:
            if len(self._real) >= _REALPATH_CACHE_MAX:
                self._real.clear()
            self._real[p] = real
        return real


# ------------------------------------------------------------------------------------------------ token


def token_check(home: Path, baseline: Baseline | None) -> tuple[str, dict[str, Any]]:
    """("", {}) when intact, else one of:
    ("token_missing", {}) - absent, or present but unreadable ({"unreadable": True});
    ("token_permissions", {observed_mode, restored_mode, restore_error}) - access wider than owner-only, already
        restored here (Windows adds "extra_principals", a count; modes are -1 there);
    ("token_modified", {observed_sha256}) - digest differs from the baseline.
    Permissions are checked before the digest so that a widened mode is restored even while a digest change is
    unresolved. Never carries the token value."""
    path = Path(home) / TOKEN_FILE
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return "token_missing", {}
    except OSError:
        return "token_missing", {"unreadable": True}
    if _WINDOWS:
        extra = _acl_extra(path)
        if extra is None or extra:
            err = restore_token_mode(path)
            return "token_permissions", {"observed_mode": -1, "restored_mode": -1, "restore_error": err or "",
                                         "extra_principals": -1 if extra is None else len(extra)}
    elif st.st_mode & 0o077:
        observed = stat.S_IMODE(st.st_mode)
        err = restore_token_mode(path)
        restored = _token_mode(path)
        return "token_permissions", {"observed_mode": observed, "restored_mode": restored, "restore_error": err or ""}
    try:
        observed_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "token_missing", {"unreadable": True}
    if baseline is not None and baseline.token_sha256 and observed_sha != baseline.token_sha256:
        return "token_modified", {"observed_sha256": observed_sha}
    return "", {}


def restore_token_mode(path: Path) -> str | None:
    """Make the token owner-only: chmod 0600 on POSIX; on Windows reset the ACL to exactly the owner, SYSTEM and
    Administrators (inheritance removed, the three granted full control, every other principal removed). Returns a
    fixed error code (never command output, which names accounts) or None on success."""
    if not _WINDOWS:
        try:
            os.chmod(path, 0o600)
        except OSError as e:
            return f"chmod_failed:{statefile._errno_name(e)}"
        return None
    user = os.environ.get("USERNAME", "")
    if not user:
        return "no_username"
    if _icacls([str(path), "/inheritance:r", "/grant:r", f"{user}:F", "*S-1-5-18:F", "*S-1-5-32-544:F"]) is None:
        return "icacls_failed:grant"
    extra = _acl_extra(path)
    if extra is None:
        return "icacls_failed:read"
    for principal in extra:
        if _icacls([str(path), "/remove:g", principal]) is None:
            return "icacls_failed:remove"
    extra = _acl_extra(path)
    if extra is None:
        return "icacls_failed:read"
    return "acl_not_owner_only" if extra else None


_ACE = re.compile(r"^(?P<who>.+?):(?:\([A-Z,]+\))+$")
_SYSTEM = {"nt authority\\system", "system", "*s-1-5-18"}
_ADMINS = {"builtin\\administrators", "administrators", "*s-1-5-32-544"}


def _icacls(args: list[str]) -> str | None:
    """stdout of `icacls <args>` (list argv, no shell), or None when it cannot run or exits non-zero."""
    try:
        r = subprocess.run(["icacls", *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _acl_extra(path: Path) -> list[str] | None:
    """Principals in the file's ACL other than the owner, SYSTEM and Administrators; None when unreadable."""
    out = _icacls([str(path)])
    if out is None:
        return None
    user = os.environ.get("USERNAME", "").lower()
    prefix = str(path)
    extra: list[str] = []
    for i, line in enumerate(out.splitlines()):
        entry = line[len(prefix):] if i == 0 and line.startswith(prefix) else line
        entry = entry.strip()
        m = _ACE.match(entry)
        if not m:
            continue        # blank lines, "Successfully processed ..."
        who = m.group("who")
        low = who.lower()
        if low in _SYSTEM or low in _ADMINS or (user and low.rsplit("\\", 1)[-1] == user):
            continue
        if who not in extra:
            extra.append(who)
    return extra
