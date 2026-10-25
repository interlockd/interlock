"""The stable interface for interlockd plugins (plugin API version 1).

Plugins (see `interlockd.plugins`) should use only this module and `interlockd.plugins` hooks. Everything else in
`interlockd` is internal and may change in any release.

Compatibility promise: within one `API_VERSION`, names here are only added, never removed or changed incompatibly.
A breaking change bumps `API_VERSION`; the previous behaviour stays available, with a deprecation warning, for at
least one minor release. A plugin that needs a newer API declares `PLUGIN_API = <n>` in its module; an interlockd
with an older API skips it with a message instead of failing at runtime.

`tests/test_plugin_api.py` is the contract: it exercises every name below.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__ as INTERLOCKD_VERSION
from .policy import Policy

API_VERSION = 1

__all__ = ["API_VERSION", "INTERLOCKD_VERSION", "DaemonStatus", "Decision", "LintIssue", "check_managed_policy",
           "compose_policies", "daemon_status", "decisions", "effective_policy", "hook_status", "lint_policy",
           "load_policy", "managed_policy_path", "settings_from_args", "spool_dir", "tighten_policy", "validate_policy"]


# ---- settings and policy -------------------------------------------------------------------------------------

def settings_from_args(args: Any):
    """The daemon `Settings` for a parsed `interlock` command line (honours `--home` and `$INTERLOCK_HOME`)."""
    from .plugins import settings_from_args as _s

    return _s(args)


def spool_dir(home: str | Path) -> Path:
    """Where the daemon in `home` writes its audit records."""
    from .config import Settings

    return Settings(home=Path(home).expanduser()).spool_dir


def load_policy(home: str | Path) -> Policy:
    """The user-level policy for the Interlock home `home` (defaults plus `<home>/policy.yaml`), as the daemon loads
    it at startup. Repository and managed layers are applied per call, not here."""
    from .policy import load_policy as _load

    return _load(None, home=Path(home).expanduser())


def validate_policy(data: Mapping[str, Any]) -> Policy:
    """Validate a whole policy document (a parsed policy.yaml) over the defaults. Raises ValueError, naming the
    problem, when it isn't a valid policy."""
    from .policy import _merge

    if not isinstance(data, Mapping):
        raise ValueError("a policy document is a mapping")   # noqa: TRY004 - one exception type for "not a valid policy"
    doc = {k: v for k, v in data.items() if k not in ("source_paths", "sha256")}
    try:
        return Policy.model_validate(_merge(Policy().model_dump(exclude={"source_paths", "sha256"}), doc))
    except Exception as e:  # pydantic ValidationError and merge type errors
        raise ValueError(f"invalid policy: {e}") from e


def managed_policy_path(home: str | Path) -> Path:
    """The managed (tighten-only) policy file for `home`; a plugin that manages policy centrally writes it here."""
    from .policy.managed import managed_path

    return managed_path(home)


def check_managed_policy(data: Mapping[str, Any], *, base: Policy | None = None,
                         home: str | Path | None = None) -> list[str]:
    """Check a document before writing it as the managed policy: it must be a valid policy (ValueError otherwise),
    and it is applied tighten-only over `base` (or the policy loaded from `home`, or the defaults). Returns the keys
    the tighten-only rule ignores (settings that would loosen a decision), so a caller can report them."""
    from .policy.managed import Managed, apply_managed

    validate_policy(data)
    if base is None:
        base = load_policy(home) if home is not None else Policy()
    _, ignored = apply_managed(base, Managed("(candidate)", "", {k: v for k, v in data.items()
                                                                 if k not in ("source_paths", "sha256")}))
    return ignored


def tighten_policy(base: Policy, data: Mapping[str, Any]) -> tuple[Policy, list[str]]:
    """Apply only the parts of `data` that make `base` stricter, as the managed policy and repository policies are
    applied. Returns (policy, the keys that were ignored because they would loosen a decision)."""
    from .policy.workspace import tighten

    return tighten(base, {k: v for k, v in data.items() if k not in ("source_paths", "sha256")})


def compose_policies(docs: list[Mapping[str, Any]]) -> dict[str, Any]:
    """One policy document that tightens a policy as applying `docs` in order would (for layering policies centrally,
    e.g. an organization's baseline and group policies, into one managed policy). See
    `interlockd.policy.workspace.compose` for the rules, including the one exception (`trust.allowed_git_remotes`)."""
    from .policy.workspace import compose

    return compose([dict(d) for d in docs if isinstance(d, Mapping)])


@dataclass(frozen=True)
class LintIssue:
    level: str                 # "error" or "warning"
    where: str                 # e.g. "packs.overrides.shell.pipe_to_shel"
    message: str


def lint_policy(policy: Policy) -> list[LintIssue]:
    """What `interlock policy lint` reports for `policy`: unknown rule ids (an override that does nothing), unknown
    packs, weakened or disabled critical rules, catch-all allows."""
    from .policy_lint import lint

    return [LintIssue(i.level, i.where, i.message) for i in lint(policy)]


def effective_policy(policy: Policy, home: str | Path) -> Policy:
    """`policy` with the managed file in `home` applied (what decisions use); unchanged if there is none."""
    from .policy.managed import apply_managed, read_managed

    m = read_managed(home)
    return apply_managed(policy, m)[0] if m is not None else policy


# ---- the running daemon -------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class DaemonStatus:
    mode: str                  # "shadow" or "enforce"
    policy: Policy | None
    judge: str                 # "ok" (answering), "off" (none configured), "error" (configured, not reachable)
    probe: str                 # "ok" (a result probe is on) or "off"
    ledger: str                # "ok" (spool writable) or "error"
    spool_dir: Path | None


def daemon_status(daemon: Any | None) -> DaemonStatus:
    """What a plugin may report about the daemon handed to `on_serve` (or None, when no daemon runs)."""
    if daemon is None:
        return DaemonStatus("shadow", None, "off", "off", "ok", None)
    pol = getattr(daemon, "policy", None)
    jtype = getattr(getattr(getattr(pol, "judge", None), "primary", None), "type", "none")
    judge = "ok" if getattr(daemon, "backend", None) is not None else ("off" if jtype in (None, "", "none") else "error")
    probe = "ok" if (getattr(daemon, "local_probe", None) or getattr(daemon, "probe", None)) else "off"
    spool = getattr(getattr(daemon, "spool", None), "dir", None)
    ledger = "ok" if spool is None or os.access(spool, os.W_OK) else "error"
    mode = getattr(daemon, "mode", None) or getattr(pol, "mode", None) or "shadow"
    return DaemonStatus(mode, pol, judge, probe, ledger, Path(spool) if spool else None)


def hook_status(home: str | Path) -> list[dict[str, str]]:
    """For each agent hook `interlock init` installed: {"harness", "problem"}, where problem is "" (intact),
    "hook_removed", "shim_missing" or "shim_modified"."""
    from .insights import hook_integrity

    return [{"harness": h["harness"], "problem": h["problem"]} for h in hook_integrity(Path(home))]


# ---- audit records --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    """The parts of one audit record a plugin may read. Tool arguments, results and messages are never exposed."""
    received_at: datetime
    kind: str                            # "pre_action", "post_action" or "control"
    disposition: str                     # "allow", "ask", "block", "warn", "withhold", ...
    findings: tuple[tuple[str, str], ...]  # (rule id, category) per finding
    judged: bool                         # routed to the judge (answered, or recorded unjudged)
    session_id: str
    selftest: bool                       # a `interlock selftest` probe, not real agent traffic


def _parse_ts(v: Any) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(v))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def decisions(spool: str | Path, since: datetime, until: datetime) -> Iterator[Decision]:
    """Audit records received in [since, until) from the spool directory `spool` (see `spool_dir`), oldest file
    first. Unreadable lines are skipped."""
    root = Path(spool)
    if not root.exists():
        return
    first_day = since.astimezone(UTC).date().isoformat()
    for seg in sorted(root.glob("*.jsonl")):
        if seg.stem < first_day:                     # one file per UTC day
            continue
        try:
            lines = seg.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            ts = _parse_ts(rec.get("received_at"))
            if ts is None or not since <= ts < until:
                continue
            found = tuple((str(f.get("rule", "")), str(f.get("category", "")))
                          for f in rec.get("findings") or [] if isinstance(f, dict))
            sid = str(rec.get("session_id") or "")
            yield Decision(ts, str(rec.get("kind") or ""), str(rec.get("disposition") or ""), found,
                           bool(rec.get("answers") or rec.get("unjudged")), sid, sid.startswith("interlock-selftest"))
