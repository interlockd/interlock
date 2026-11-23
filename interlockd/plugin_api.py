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
import logging
import os
import threading
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__ as INTERLOCKD_VERSION
from .policy import Policy

API_VERSION = 1

__all__ = ["API_VERSION", "INTERLOCKD_VERSION", "DaemonStatus", "Decision", "HarnessProtection", "LintIssue",
           "ProtectionStatus", "StartupReport", "check_managed_policy", "compose_policies", "daemon_status",
           "decisions", "effective_policy", "hook_status", "lint_policy", "load_policy", "managed_policy_path",
           "pin_managed_policy", "protection_status", "record_operator_action", "settings_from_args", "spool_dir",
           "startup_report", "subscribe_protection", "tighten_policy", "validate_policy"]

log = logging.getLogger("interlockd.plugin_api")


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
    """The parts of one audit record a plugin may read: metadata only. Tool arguments, results, file paths, the working
    directory, transcripts, reason and notice texts (they can quote a command) and finding subjects are never exposed.
    Fields after `selftest` were added in 0.1.8 (additive); records written by older versions leave them empty.
    `tamper_kind` and `protection_state` (added in 0.2.0) are set for `control` records only, from fixed code sets;
    the file path, digests and reason of a control record are never exposed."""
    received_at: datetime
    kind: str                            # "pre_action", "post_action" or "control"
    disposition: str                     # "allow", "ask", "block", "warn", "withhold", ...
    findings: tuple[tuple[str, str], ...]  # (rule id, category) per finding
    judged: bool                         # routed to the judge (answered, or recorded unjudged)
    session_id: str
    selftest: bool                       # a `interlock selftest` probe, not real agent traffic
    event_id: str = ""                   # the record's id: stable, for idempotent forwarding
    agent: str = ""                      # the adapter that sent it: "claude-code", "codex", "strands", ...
    action_class: str = ""               # normalized class: "shell", "git", "egress", "file_write", "mcp", ...
    tier: int | None = None              # 0 read-only, 1 in-workspace, 2 gated
    mode: str = ""                       # "shadow" or "enforce" when it was decided
    tool_name: str = ""                  # e.g. "Bash", "Write", "mcp__github__create_pull_request" (names MCP servers)
    finding_severities: tuple[str, ...] = ()   # severity per entry of `findings`, same order
    policy_sha256: str = ""              # the effective policy's hash
    tamper_kind: str = ""                # control records: "shim_modified", "token_rejected", ... ("" otherwise)
    protection_state: str = ""           # control records: "protected", "observing", "compromised", ... ("" otherwise)

    def keyed_session(self, key: bytes) -> str:
        """A stable pseudonym for `session_id` under `key` (HMAC-SHA256): groups one session's decisions without
        revealing the agent's own session id. Same key, same session -> same value."""
        import hashlib
        import hmac

        return "s_" + hmac.new(key, self.session_id.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


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
    from .records import STATES, TAMPER_KINDS

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
            fs = [f for f in rec.get("findings") or [] if isinstance(f, dict)]
            found = tuple((str(f.get("rule", "")), str(f.get("category", ""))) for f in fs)
            sid = str(rec.get("session_id") or "")
            norm = rec.get("normalized") if isinstance(rec.get("normalized"), dict) else {}
            tier = rec.get("tier")
            tamper_kind, pstate = _control_fields(rec, TAMPER_KINDS, STATES)
            yield Decision(ts, str(rec.get("kind") or ""), str(rec.get("disposition") or ""), found,
                           bool(rec.get("answers") or rec.get("unjudged")), sid, sid.startswith("interlock-selftest"),
                           event_id=str(rec.get("event_id") or ""), agent=str(rec.get("adapter") or ""),
                           action_class=str(norm.get("action_class") or ""),
                           tier=tier if isinstance(tier, int) and not isinstance(tier, bool) else None,
                           mode=str(rec.get("mode") or ""), tool_name=str(rec.get("tool_name") or "")[:200],
                           finding_severities=tuple(str(f.get("severity") or "") for f in fs),
                           policy_sha256=str(rec.get("policy_sha256") or ""),
                           tamper_kind=tamper_kind, protection_state=pstate)


def _control_fields(rec: dict[str, Any], kinds: frozenset[str], states: tuple[str, ...]) -> tuple[str, str]:
    """(tamper_kind, protection_state) of a control record, each from its fixed set ("" for anything else)."""
    args = rec.get("arguments")
    if rec.get("kind") != "control" or not isinstance(args, dict):
        return "", ""
    tk = args.get("tamper_kind")
    record = args.get("record")
    ps = args.get("new") if record == "protection_state" else (
        args.get("protection_state") if record == "operator_action" else "")
    return (tk if isinstance(tk, str) and tk in kinds else "",
            ps if isinstance(ps, str) and ps in states else "")


# ---- protection state (tamper detection) -----------------------------------------------------------------------

@dataclass(frozen=True)
class HarnessProtection:
    name: str                            # harness name, e.g. "claude-code"
    state: str                           # "protected", "observing" or "compromised"
    reasons: tuple[str, ...]             # unresolved reason codes, e.g. ("shim_modified",)
    detected_at: tuple[str, ...]         # ISO detection time per entry of `reasons`, same order


@dataclass(frozen=True)
class ProtectionStatus:
    """What a plugin may report about the daemon's Protection_State: fixed codes, times, counts and the policy
    digests only (no paths, no file contents)."""
    aggregate: str                       # one of "protected", "observing", "stopped", "compromised", "unknown"
    harnesses: tuple[HarnessProtection, ...]
    home_reasons: tuple[str, ...]        # unresolved Home-level reason codes ("token_modified", "policy_modified", ...)
    last_tamper_at: str | None           # ISO time of the most recent Tamper_Event; None when there was none
    tamper_count_since: int              # Tamper_Events recorded since `since` (selftest token rejections excluded)
    pinned_policy_sha256: str | None
    on_disk_policy_sha256: str | None    # None when the file is absent
    operator_action: str | None          # the Operator_Action behind an `observing` state, when known


MAX_COUNT_DAYS = 7          # tamper counts look back at most this far (Requirement 10.10's carry-forward bound)
# operator actions that set the mode the daemon observes in (shadow mode comes from the policy they write or accept)
_MODE_ACTIONS = ("shadow", "init", "policy_accept", "policy_revert", "policy_set", "policy_edit", "ack")


def _home_of(daemon: Any) -> Path | None:
    for obj in (getattr(daemon, "protection", None), getattr(daemon, "settings", None)):
        home = getattr(obj, "home", None)
        if home is not None:
            return Path(home)
    return None


def _daemon_started(home: Path | None) -> datetime | None:
    from .lifecycle import parse_iso

    if home is None:
        return None
    try:
        doc = json.loads((home / "daemon.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return parse_iso(doc.get("started_at")) if isinstance(doc, dict) else None


def _tamper_count(spool: Any, since: datetime, until: datetime) -> int:
    """Tamper_Events in [since, until), without the `token_rejected` records an `interlock selftest` caused (14.7),
    as the Doctor counts them."""
    from .lifecycle import parse_iso
    from .operator import GRACE_S
    from .records import TAMPER_KINDS

    if spool is None or not hasattr(spool, "iter_records"):
        return 0
    grace = timedelta(seconds=GRACE_S)
    found: list[tuple[datetime, str]] = []
    selftests: list[datetime] = []
    try:
        for rec in spool.iter_records():                 # newest first
            if not isinstance(rec, dict):
                continue
            t = parse_iso(rec.get("received_at"))
            if t is None:
                continue
            if t < since - grace - timedelta(seconds=60):   # a selftest just before `since` still explains its records
                break
            if rec.get("kind") != "control" or not isinstance(rec.get("arguments"), dict):
                continue
            a = rec["arguments"]
            if a.get("record") == "operator_action" and a.get("action") == "selftest" and not a.get("failed"):
                selftests.append(t)
            elif a.get("tamper_kind") in TAMPER_KINDS and since <= t < until:
                found.append((t, a["tamper_kind"]))
    except (OSError, ValueError):
        pass
    return sum(1 for t, k in found
               if not (k == "token_rejected" and any(s <= t < s + grace for s in selftests)))


def _status(daemon: Any, since: datetime | None) -> ProtectionStatus:
    from .protection import HARNESS_REASONS, HOME_REASONS
    from .records import STATES

    protection = getattr(daemon, "protection", None) if daemon is not None else None
    if protection is None:
        return ProtectionStatus("unknown", (), (), None, 0, None, None, None)
    snap = protection.snapshot()
    harnesses = []
    for name, h in sorted((snap.get("harnesses") or {}).items()):
        rs = [r for r in h.get("reasons") or [] if r.get("reason") in HARNESS_REASONS]
        state = h.get("state") if h.get("state") in STATES else "unknown"
        harnesses.append(HarnessProtection(str(name), state, tuple(r["reason"] for r in rs),
                                           tuple(str(r.get("detected_at") or "") for r in rs)))
    home_reasons = tuple(r["reason"] for r in snap.get("home_reasons") or [] if r.get("reason") in HOME_REASONS)
    aggregate = snap.get("aggregate") if snap.get("aggregate") in STATES else "unknown"

    now = datetime.now(UTC)
    floor = now - timedelta(days=MAX_COUNT_DAYS)
    start = since if since is not None else (_daemon_started(_home_of(daemon)) or floor)
    start = max(start if start.tzinfo else start.replace(tzinfo=UTC), floor)
    count = _tamper_count(getattr(daemon, "spool", None), start, now + timedelta(seconds=1))

    pinned = on_disk = None
    guard = getattr(daemon, "policy_guard", None)
    if guard is not None:
        st = (guard.status() or {}).get("policy") or {}
        pinned, on_disk = st.get("pinned_sha256") or None, st.get("on_disk_sha256") or None

    action = None
    if aggregate == "observing":
        if snap.get("observing"):
            action = "shadow"           # the observing flag is only ever set by the Operator's `interlock shadow`
        else:
            recent = getattr(daemon, "operator_actions", None)
            for e in reversed(recent.recent() if recent is not None else []):
                if e.get("action") in _MODE_ACTIONS:
                    action = e["action"]
                    break
    last = snap.get("last_tamper_at")
    return ProtectionStatus(aggregate, tuple(harnesses), home_reasons, last if isinstance(last, str) else None,
                            count, pinned, on_disk, action)


def protection_status(daemon: Any | None, *, since: datetime | None = None) -> ProtectionStatus:
    """The Protection_State of the daemon handed to `on_serve` (or None: `unknown`). `tamper_count_since` counts the
    Tamper_Events recorded since `since` (default: the daemon's start), looking back at most MAX_COUNT_DAYS."""
    return _status(daemon, since)


CALLS_UNJUDGED_KEYS = ("unjudged", "tamper_token_rejected", "tamper_daemon_identity", "tamper_daemon_lost")


@dataclass(frozen=True)
class StartupReport:
    """What the start-up audit of the daemon handed to `on_serve` recorded (Requirement 3.5, 3.12): a flag and
    counts only. `calls_unjudged` has the keys of CALLS_UNJUDGED_KEYS when a `control.calls_unjudged` summary was
    recorded at this start, and is empty otherwise."""
    unexpected_exit: bool                # the previous daemon ended without `interlock stop` or a clean exit
    calls_unjudged: dict[str, int]       # hook calls the shims logged while no daemon judged them, per classification
    started_at: str | None               # this daemon's start time (ISO); None when unknown


def startup_report(daemon: Any | None) -> StartupReport:
    """The `control.daemon_unexpected_exit` and `control.calls_unjudged` records written at this daemon's start,
    read back from its spool. No daemon, or no start time: nothing to report."""
    from .lifecycle import parse_iso

    home = _home_of(daemon) if daemon is not None else None
    started = _daemon_started(home)
    spool = getattr(daemon, "spool", None) if daemon is not None else None
    if started is None or spool is None or not hasattr(spool, "iter_records"):
        return StartupReport(False, {}, None)
    floor = started - timedelta(seconds=5)            # the audit runs after daemon.json is written
    unexpected = False
    counts: dict[str, int] = {}
    try:
        for rec in spool.iter_records():              # newest first
            if not isinstance(rec, dict):
                continue
            t = parse_iso(rec.get("received_at"))
            if t is None:
                continue
            if t < floor:
                break
            args = rec.get("arguments")
            if rec.get("kind") != "control" or not isinstance(args, dict):
                continue
            if args.get("record") == "daemon_unexpected_exit":
                unexpected = True
            elif args.get("record") == "calls_unjudged" and not counts:
                for k in CALLS_UNJUDGED_KEYS:
                    v = args.get(k)
                    counts[k] = v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0
    except (OSError, ValueError):
        pass
    return StartupReport(unexpected, counts, started.astimezone(UTC).isoformat(timespec="seconds"))


def subscribe_protection(daemon: Any | None,
                         callback: Callable[[ProtectionStatus], None]) -> Callable[[], None]:
    """Call `callback(protection_status(daemon))` after Protection_State changes. Returns a function that unsubscribes.

    The callback runs on a worker thread of its own, never on the thread that changed the state, so a slow callback
    cannot delay a verdict; changes that arrive while it runs are coalesced into one more call with the latest
    status. A callback that raises is logged and stays subscribed. Without a protection state (no daemon, or a daemon
    without tamper detection) nothing is ever called."""
    protection = getattr(daemon, "protection", None) if daemon is not None else None
    if protection is None:
        return lambda: None
    wake, stop = threading.Event(), threading.Event()

    def run() -> None:
        while True:
            wake.wait()
            if stop.is_set():
                return
            wake.clear()
            try:
                callback(protection_status(daemon))
            except Exception:  # a plugin's callback must not end the subscription
                log.exception("protection subscriber failed")

    threading.Thread(target=run, name="interlock-protection-subscriber", daemon=True).start()
    unsub = protection.subscribe(lambda _snapshot: wake.set())

    def unsubscribe() -> None:
        unsub()
        stop.set()
        wake.set()
    return unsubscribe


def _same_home(daemon: Any, home: Path) -> bool:
    dh = _home_of(daemon)
    try:
        return dh is not None and dh.expanduser().resolve() == home.resolve()
    except OSError:
        return False


def _record_action(home: Path, action: str, harness: str, daemon: Any | None) -> str:
    """Record an Operator_Action made through a plugin (`via: console`); returns its event id. In the daemon's own
    process (`daemon` for this Home) it is handled in-process; otherwise through the daemon's control route, or
    appended to the spool directly when the daemon does not acknowledge within 2 s."""
    from . import operator
    from .config import Settings

    if daemon is not None and _same_home(daemon, home) and getattr(daemon, "spool", None) is not None:
        reply = operator.handle_operator_action(daemon, {"action": action, "harness": harness, "via": "console",
                                                         "grace_s": int(operator.GRACE_S)})
        return str(reply["event_id"])
    return str(operator.record(Settings(home=home), action, harness=harness, via="console")["event_id"])


def record_operator_action(home: str | Path, action: str, *, harness: str = "", daemon: Any | None = None) -> None:
    """Record an Operator_Action a plugin is about to perform (e.g. "console_sync" before rewriting the managed
    policy), before it changes anything, so the daemon treats the change as explained (Requirement 11.1, 11.2).
    `action` is one of the daemon's fixed action names (ValueError otherwise). Pass the daemon handed to `on_serve`
    when calling from inside it. Raises OSError when the record cannot be written at all."""
    _record_action(Path(home).expanduser(), action, harness, daemon)


def pin_managed_policy(home: str | Path, *, daemon: Any | None = None) -> str:
    """Pin `<home>/managed-policy.yaml` as just written by the Console sync (Requirement 7.10): records the
    `console_sync` Operator_Action first, then stores the file's digest in the Integrity_Baseline and a byte-identical
    pinned copy. Returns the pinned digest ("" when the file is absent, which removes the pin). Pass the daemon handed
    to `on_serve` when calling from inside it. Raises OSError when the pin was not updated; the previous pin then
    stays in effect (7.11)."""
    from . import integrity
    from .onboard import Manifest
    from .policy import pin as policy_pin

    home = Path(home).expanduser()
    _record_action(home, "console_sync", "", daemon)
    guard = getattr(daemon, "policy_guard", None) if daemon is not None and _same_home(daemon, home) else None
    if guard is not None:
        guard.check()                   # explained by console_sync: pins, records and clears the reason
        digest = policy_pin.file_sha256(policy_pin.source_path(home, "managed")) or ""
        if guard.pinned_sha256("managed") != digest:
            raise OSError(f"the pin of {policy_pin.source_path(home, 'managed')} was not updated")
        return digest
    base = integrity.Baseline.load(home)
    if base is None:
        if (home / integrity.BASELINE).exists():
            raise OSError(f"{home / integrity.BASELINE} cannot be read; the managed policy pin was not updated")
        base = integrity.Baseline.from_disk(home, Manifest.load(home))
    return policy_pin.pin(home, "managed", baseline=base)
