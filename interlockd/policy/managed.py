"""Managed policy: `<interlock home>/managed-policy.yaml`, a tighten-only floor set by whoever manages the machine.

A device-management tool (MDM, configuration management, a fleet agent) can place a policy at
`~/.interlock/managed-policy.yaml`. The daemon applies it last, after your policy and any repository policy, with the
rules an untrusted repository policy follows: it can only make decisions *stricter* (enforce mode, stricter rule
actions, re-enabling a rule, more protected branches and paths, fewer allowed hosts, MCP `block` entries, a smaller
denial budget). Anything that would loosen a decision is ignored and listed by `interlock policy lint`. A file that
does not parse is ignored as a whole and reported, never half-applied.

The daemon notices a new, changed, or removed file within a couple of seconds, without a restart.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from . import Policy

FILE_NAME = "managed-policy.yaml"
STAT_TTL_S = 2.0            # how long a stat of the file is reused on the decision path


def managed_path(home: str | Path) -> Path:
    return Path(home).expanduser() / FILE_NAME


@dataclass(frozen=True)
class Managed:
    path: str
    sha256: str                         # of the file's bytes
    data: dict[str, Any] | None         # None when the file doesn't parse (see error)
    error: str | None = None


def read_managed(home: str | Path) -> Managed | None:
    """The managed policy file, or None when there isn't one."""
    p = managed_path(home)
    try:
        raw = p.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        return Managed(str(p), "", None, "(file is unreadable)")
    return parse_managed(str(p), raw)


def parse_managed(path: str, raw: bytes) -> Managed:
    """A managed document from its bytes (the file, or its pinned copy)."""
    sha = hashlib.sha256(raw).hexdigest()
    try:
        data = yaml.safe_load(raw.decode("utf-8")) or {}
        if not isinstance(data, dict):
            raise TypeError("not a mapping")
    except (UnicodeDecodeError, TypeError, ValueError, yaml.YAMLError):
        return Managed(path, sha, None, "(file does not parse)")
    return Managed(path, sha, {k: v for k, v in data.items() if k not in ("source_paths", "sha256")})


def apply_managed(base: Policy, m: Managed) -> tuple[Policy, list[str]]:
    """Layer `m` over `base`, tighten-only. Returns (policy, ignored keys); an unparseable file changes nothing."""
    if m.data is None:
        return base, [m.error or "(file does not parse)"]
    from .workspace import tighten

    pol, ignored = tighten(base, m.data)
    pol.source_paths = [*base.source_paths, m.path]
    pol.sha256 = hashlib.sha256(f"{base.sha256}managed:{m.sha256}".encode()).hexdigest()
    return pol, ignored


def provenance(m: Managed, ignored: list[str]) -> dict[str, Any]:
    """What the audit record and `policy lint` say about the managed layer."""
    return {"path": m.path, "sha256": m.sha256, "ignored": list(ignored),
            "enforce": bool(m.data) and m.data.get("mode") == "enforce"}


class ManagedPolicy:
    """Applies the managed file to each call's policy in the daemon, re-reading the file only when it changes."""

    def __init__(self, home: str | Path):
        self.home = Path(home)
        self._lock = threading.Lock()
        self._checked = float("-inf")
        self._stamp: tuple | None = None
        self._managed: Managed | None = None
        self._cache: dict[str, tuple[Policy, dict[str, Any]]] = {}
        self.guard: Any = None      # policy.pin.PolicyGuard, set by the daemon at start (Requirement 7.10)

    def set_guard(self, guard: Any) -> None:
        """Apply a changed file only when it is pinned or explained by the Console sync; otherwise serve the
        pinned copy (the guard records `managed_policy_modified`). Forces a re-read on the next call."""
        with self._lock:
            self.guard = guard
            self._checked = float("-inf")
            self._stamp = ("unset",)

    def _current(self) -> Managed | None:
        now = time.monotonic()
        with self._lock:
            if now - self._checked < STAT_TTL_S:
                return self._managed
            self._checked = now
            try:
                st = managed_path(self.home).stat()
                file_stamp: tuple | None = (st.st_mtime_ns, st.st_size, st.st_ino)
            except FileNotFoundError:
                file_stamp = None
            except OSError:
                file_stamp = ("unreadable",)
            guard = self.guard
            # with a guard, a pin moved by the Console sync (or `interlock ack`) re-evaluates an unchanged file
            stamp = file_stamp if guard is None else (file_stamp, guard.pinned_sha256("managed"))
            if stamp != self._stamp:
                had = self._managed is not None
                self._stamp = stamp
                on_disk = read_managed(self.home) if file_stamp is not None else None
                self._managed = on_disk if guard is None else guard.managed_for(on_disk, self._managed)
                self._cache.clear()
                if self._managed is not None:
                    state = self._managed.error or f"sha256 {self._managed.sha256[:12]}"
                    print(f"managed policy: {self._managed.path} ({state})", flush=True)
                elif had:
                    print("managed policy: removed", flush=True)
            return self._managed

    def resolve(self, pol: Policy) -> tuple[Policy, dict[str, Any] | None]:
        """(policy with the managed floor applied, provenance) or (pol, None) when there is no managed file."""
        m = self._current()
        if m is None:
            return pol, None
        key = pol.sha256 or f"id:{id(pol)}"
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        out, ignored = apply_managed(pol, m)
        res = (out, provenance(m, ignored))
        with self._lock:
            if len(self._cache) > 256:
                self._cache.clear()
            self._cache[key] = res
        return res
