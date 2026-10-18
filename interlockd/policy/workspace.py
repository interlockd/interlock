"""Repository policies: `<repo>/.interlock/policy.yaml`, picked up per call from the call's working directory.

Anyone who can commit to a repository writes its policy, and a poisoned repository is in the threat model, so a
repository policy can only make decisions *stricter* than yours: enforce mode, stricter rule actions, re-enabling a
rule, more protected branches and paths, fewer allowed hosts, MCP `block` entries, a smaller denial budget. Anything
that would loosen a decision (disabling or softening a rule, allowing hosts or remotes, the judge, the mandate, fail
modes) is ignored and reported by `interlock policy lint --workspace <repo>`.

Repositories you list in `trust.trusted_workspaces` (globs over the repository path, in your own policy) are merged
in full, as a configured workspace root is. `INTERLOCK_REPO_POLICIES=0` turns repository policies off.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Any

import yaml

from . import McpPolicy, Policy, RuleOverride, _merge

ORDER = {"block": 4, "ask": 3, "model": 2, "flag": 1, "allow": 0}
MAX_DEPTH = 40
LOOKUP_TTL_S = 2.0          # how long a directory's lookup is reused; a new or removed policy file shows up after this


def find_repo_policy(cwd: str | Path | None, *, stop: Path | None = None) -> Path | None:
    """The nearest `.interlock/policy.yaml` at or above `cwd`, not looking at or above `stop` (your home directory,
    whose `.interlock/` is Interlock's own state). A file owned by another user (say in a shared /tmp) is skipped,
    as git does for repositories it doesn't trust."""
    if not cwd:
        return None
    stop = (stop or Path.home()).resolve()
    try:
        p = Path(cwd).expanduser().resolve()
    except (OSError, RuntimeError):
        return None
    for _ in range(MAX_DEPTH):
        if p == stop or p.parent == p:
            return None
        f = p / ".interlock" / "policy.yaml"
        if f.is_file() and _owned(f):
            return f
        p = p.parent
    return None


def _owned(f: Path) -> bool:
    try:
        return f.stat().st_uid in (os.getuid(), 0)
    except (OSError, AttributeError):          # AttributeError: no getuid (Windows)
        return True


def tighten(base: Policy, data: dict[str, Any]) -> tuple[Policy, list[str]]:
    """Apply only the parts of a repository policy that make `base` stricter. Returns (policy, ignored keys)."""
    from ..det import RULES, flow, mcp, packs  # noqa: F401  register every rule

    p = base.model_copy(deep=True)
    ignored: list[str] = []
    for key, val in data.items():
        if key == "version" or key == "workspace":
            continue
        if key == "mode":
            if val == "enforce":
                p.mode = "enforce"
            elif val != base.mode:
                ignored.append("mode")
        elif key == "packs" and isinstance(val, dict):
            _packs(p, base, val, ignored, RULES)
        elif key == "trust" and isinstance(val, dict):
            _trust(p, base, val, ignored)
        elif key == "mcp" and isinstance(val, dict):
            _mcp(p, base, val, ignored)
        elif key == "flow" and isinstance(val, dict):
            _flow(p, base, val, ignored)
        elif key == "denial_budget" and isinstance(val, dict):
            for k, v in val.items():
                if k in ("consecutive", "total") and isinstance(v, int) and v > 0:
                    setattr(p.denial_budget, k, min(getattr(base.denial_budget, k), v))
                elif k == "then" and v == "block":
                    p.denial_budget.then = "block"
                elif not (k == "then" and v == base.denial_budget.then):
                    ignored.append(f"denial_budget.{k}")
        elif not _restates(val, base.model_dump().get(key)):     # `profile: laptop` or the default judge changes nothing
            ignored.append(key)
    return p, ignored


def _restates(val: Any, cur: Any) -> bool:
    """True when `val` only repeats what `cur` already says."""
    if isinstance(val, dict) and isinstance(cur, dict):
        return all(k in cur and _restates(v, cur[k]) for k, v in val.items())
    return val == cur


def _packs(p: Policy, base: Policy, val: dict, ignored: list[str], rules: dict) -> None:
    for k, v in val.items():
        if k == "enabled" and isinstance(v, list):
            p.packs.enabled = list(dict.fromkeys([*base.packs.enabled, *[str(x) for x in v]]))
            if set(base.packs.enabled) - set(v):
                ignored.append("packs.enabled (turning packs off)")
        elif k == "overrides" and isinstance(v, dict):
            for rid, raw in v.items():
                where = f"packs.overrides.{rid}"
                try:
                    ov = RuleOverride.model_validate(raw or {})
                except ValueError:
                    ignored.append(where); continue
                if rid not in rules or not ov.enabled or ov.action is None:
                    ignored.append(where); continue
                default = rules[rid][2]
                cur = base.rule_action(rid, default)
                if cur is None or ORDER[ov.action] > ORDER[cur]:
                    prev = base.packs.overrides.get(rid)
                    p.packs.overrides[rid] = RuleOverride(action=ov.action, questions=list(prev.questions) if prev else [])
                elif ORDER[ov.action] < ORDER[cur]:
                    ignored.append(where)
        else:
            ignored.append(f"packs.{k}")


def _trust(p: Policy, base: Policy, val: dict, ignored: list[str]) -> None:
    t, b = p.trust, base.trust
    for k, v in val.items():
        if k in ("protected_paths", "sensitive_paths", "protected_branches") and isinstance(v, list):
            setattr(t, k, list(dict.fromkeys([*getattr(b, k), *[str(x) for x in v]])))
        elif k in ("allowed_hosts", "allowed_package_indexes") and isinstance(v, list):
            keep = [h for h in getattr(b, k) if h in v]
            setattr(t, k, keep)
            if set(v) - set(keep):
                ignored.append(f"trust.{k} (hosts you have not allowed)")
        elif k == "allowed_git_remotes" and isinstance(v, list):
            if not b.allowed_git_remotes:                 # empty means unrestricted: any list narrows it
                t.allowed_git_remotes = [str(x) for x in v]
            else:
                keep = [r for r in b.allowed_git_remotes if r in v]
                if keep:
                    t.allowed_git_remotes = keep
                if not keep or set(v) - set(keep):
                    ignored.append("trust.allowed_git_remotes (remotes you have not allowed)")
        elif k == "declared_packages_only" and v is True:
            t.declared_packages_only = True
        elif not (k == "declared_packages_only" and v == b.declared_packages_only):
            ignored.append(f"trust.{k}")


def _mcp(p: Policy, base: Policy, val: dict, ignored: list[str]) -> None:
    try:
        m = McpPolicy.model_validate(val)
    except ValueError:
        ignored.append("mcp"); return
    if ORDER[m.default] > ORDER[base.mcp.default]:
        p.mcp.default = m.default
    elif "default" in val and m.default != base.mcp.default:
        ignored.append("mcp.default")
    has_block = base.mcp.default == "block" or "block" in base.mcp.tools.values()
    for pat, action in m.tools.items():
        cur = base.mcp.tools.get(pat)
        # a more specific `ask` could shadow one of your `block` patterns, so `ask` is taken only when you block nothing
        if action == "block" or (action == "ask" and not has_block and cur in (None, "allow")):
            p.mcp.tools[pat] = action
        elif cur != action:
            ignored.append(f"mcp.tools[{pat!r}]")


def _flow(p: Policy, base: Policy, val: dict, ignored: list[str]) -> None:
    for k, v in val.items():
        if k == "enabled" and v is True:
            p.flow.enabled = True
        elif k == "action" and v in ("block", "ask", "flag") and ORDER[v] >= ORDER[base.flow.action]:
            p.flow.action = v
        elif k in ("private_sources", "untrusted_sources", "sinks") and isinstance(v, list):
            setattr(p.flow, k, list(dict.fromkeys([*getattr(base.flow, k), *[str(x) for x in v]])))
        elif not (k == "enabled" and v == base.flow.enabled):
            ignored.append(f"flow.{k}")


class RepoPolicies:
    """Resolve and cache the policy for a call's working directory. Thread-safe; a changed file is re-read."""

    def __init__(self, *, interlock_home: Path | None = None, home_dir: Path | None = None):
        self.interlock_home = interlock_home.resolve() if interlock_home else None
        self.home_dir = home_dir
        self._cache: dict[tuple[str, str], tuple[tuple[int, int], Policy, list[str]]] = {}
        self._found: dict[str, tuple[float, Path | None]] = {}
        self._own: tuple[str, set[str]] = ("", set())
        self._lock = threading.Lock()

    def resolve(self, base: Policy, cwd: str | None) -> tuple[Policy, dict[str, Any] | None]:
        """(effective policy, provenance for the audit record or None when no repository policy applies)."""
        if os.environ.get("INTERLOCK_REPO_POLICIES", "1") == "0":
            return base, None
        if not cwd:
            return base, None
        now = time.monotonic()
        hit = self._found.get(cwd)
        if hit and now - hit[0] < LOOKUP_TTL_S:
            f = hit[1]
        else:
            f = find_repo_policy(cwd, stop=self.home_dir)
            if len(self._found) > 1024:
                self._found.clear()
            self._found[cwd] = (now, f)
        if self._own[0] != base.sha256:
            self._own = (base.sha256, {str(Path(s).resolve()) for s in base.source_paths})
        if f is None or f.parent == self.interlock_home or str(f) in self._own[1]:
            return base, None
        try:
            st = f.stat()
        except OSError:
            return base, None
        key, stamp = (str(f), base.sha256), (st.st_mtime_ns, st.st_size)
        with self._lock:
            hit = self._cache.get(key)
        if hit and hit[0] == stamp:
            pol, ignored = hit[1], hit[2]
        else:
            pol, ignored = load_repo_policy(base, f)
            with self._lock:
                if len(self._cache) > 256:
                    self._cache.clear()
                self._cache[key] = (stamp, pol, ignored)
        return pol, {"path": str(f), "trusted": is_trusted(base, f), "sha256": pol.sha256, "ignored": ignored}


def is_trusted(base: Policy, f: Path) -> bool:
    root = str(f.parent.parent)
    return any(fnmatch.fnmatchcase(root, str(Path(g).expanduser())) for g in base.trust.trusted_workspaces)


def load_repo_policy(base: Policy, f: Path) -> tuple[Policy, list[str]]:
    """Layer the repository policy at `f` over `base`: in full when trusted, tighten-only otherwise. A policy that
    does not parse is ignored as a whole (reported), never half-applied."""
    try:
        data = yaml.safe_load(f.read_text()) or {}
        if not isinstance(data, dict):
            raise TypeError("not a mapping")
    except (OSError, TypeError, ValueError, yaml.YAMLError):
        return base, ["(file does not parse)"]
    data = {k: v for k, v in data.items() if k not in ("source_paths", "sha256")}
    if is_trusted(base, f):
        try:
            merged = _merge(base.model_dump(exclude={"source_paths", "sha256"}), data)
            if isinstance(data.get("trust"), dict):
                merged["trust"]["trusted_workspaces"] = list(base.trust.trusted_workspaces)
            pol = Policy.model_validate(merged)
        except ValueError:
            return base, ["(does not validate)"]
        if pol.mandate.cedar and "mandate" in data:
            pol.mandate.cedar = str((f.parent / pol.mandate.cedar).resolve())
        ignored: list[str] = []
    else:
        pol, ignored = tighten(base, data)
    pol.source_paths = [*base.source_paths, str(f)]
    pol.sha256 = hashlib.sha256((base.sha256 + pol.model_dump_json(exclude={"source_paths", "sha256"})).encode()).hexdigest()
    return pol, ignored
