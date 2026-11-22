"""Content-free `control` record builders: the only way Interlock writes a record about itself.

Every record uses the existing audit schema (so `Spool.append` chains it and `interlock audit verify` checks it) with
the per-call fields left empty: no `cwd`, `state`, `answers`, `guardrails` or `result_*`. `arguments` holds only the
keys allowlisted for the record kind in `ARGUMENT_KEYS`, and every value is a fixed code, a count, a timestamp, a
digest, a harness name or the path of an Interlock-owned or hook-config file. Tool arguments, file contents,
transcripts, token values, policy text and the working directory never reach these builders' output.

Codes that come from the caller are checked: a reason or name that is not a short identifier is replaced by
`invalid`, a digest that is not 64 hex characters by "", so a mistake upstream cannot copy free text into the audit log.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, TypedDict, Unpack

from . import __version__
from .ids import ulid

TAMPER_KINDS = frozenset({
    "shim_modified", "shim_missing", "shim_relocated", "hook_removed", "token_rejected", "token_modified",
    "token_missing", "token_permissions", "policy_modified", "managed_policy_modified", "daemon_unexpected_exit",
    "identity_missing", "state_unreadable",
})
STATES = ("protected", "observing", "stopped", "compromised", "unknown")
SESSION_ID = "interlock-control"
FINDING_CATEGORY = "control.hook_tamper"

# record name -> the only `arguments` keys it may carry (besides "record", which every record has)
ARGUMENT_KEYS: dict[str, frozenset[str]] = {k: frozenset(v) | {"record"} for k, v in {
    # observed_mode / restored_mode / restore_error: `token_permissions` only (Requirement 8.4, 8.7, 8.9)
    "tamper_event": ("tamper_kind", "harness", "path", "expected_sha256", "observed_sha256", "reason",
                     "observed_mode", "restored_mode", "restore_error"),
    "operator_action": ("action", "harness", "protection_state", "via", "caused_by", "confirmed", "grace_s", "failed"),
    "operator_ack": ("reasons",),
    "protection_state": ("subject", "previous", "new", "reasons", "caused_by"),
    "daemon_started": ("marker_present", "marker_action"),
    "daemon_unexpected_exit": ("tamper_kind", "prev_pid", "prev_version"),
    "calls_unjudged": ("unjudged", "tamper_token_rejected", "tamper_daemon_identity", "tamper_daemon_lost",
                       "span_from", "span_to"),
    "policy_baseline_set": ("policy_kind", "path", "sha256", "failed", "previous_sha256", "caused_by"),
    "policy_modified": ("tamper_kind", "policy_kind", "path", "pinned_sha256", "on_disk_sha256", "added", "removed",
                        "changed", "unparseable"),
    "policy_restored": ("policy_kind", "path", "sha256", "rejected_sha256", "caused_by"),
    "token_rejected": ("tamper_kind", "adapter", "addr"),
    "token_rejected_summary": ("tamper_kind", "adapter", "count", "first_at", "last_at"),
    "expected_after_rotate": ("adapter", "addr"),
    "shim_repaired": ("harness", "path", "sha256"),
    "shim_repair_failed": ("harness", "path", "cause"),
    "hook_restored": ("harness", "path", "previous"),
    "state_unreadable": ("tamper_kind", "file", "reason"),
    "state_permissions": ("file", "check"),
    "state_write_failed": ("file", "reason"),
    "identity_restored": ("tamper_kind", "path"),
    "notify_failed": ("reason",),
    "no_baseline": ("harness",),
    "baseline_created": ("path",),
}.items()}

_CODE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}\Z")      # reason codes, check names, errno names
_HARNESS = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}\Z")
_SHA256 = re.compile(r"^[0-9a-f]{64}\Z")
_KEY = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")         # policy top-level key names
MAX_PATH = 1024


class Meta(TypedDict, total=False):
    mode: str            # the daemon's mode ("enforce" / "shadow"); "" when written by the CLI without a daemon
    policy_sha256: str
    at: str              # ISO time of the event; now when absent


def meta(daemon: Any) -> Meta:
    """The record context of a running daemon."""
    return {"mode": str(getattr(daemon, "mode", "") or ""), "policy_sha256": str(getattr(daemon, "policy_sha256", "") or "")}


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _code(v: Any) -> str:
    s = str(v or "")
    return s if not s or _CODE.match(s) else "invalid"


def _harness(v: Any) -> str:
    s = str(v or "")
    return s if not s or _HARNESS.match(s) else "invalid"


def _digest(v: Any) -> str:
    s = str(v or "")
    return s if _SHA256.match(s) else ""


def _path(v: Any) -> str:
    return "".join(c for c in str(v or "") if c.isprintable())[:MAX_PATH]


def _text(v: Any, n: int) -> str:
    """A short self-reported name (adapter, address): printable characters only, truncated."""
    return "".join(c for c in str(v or "") if c.isprintable())[:n]


def _ts(v: Any) -> str:
    s = str(v or "")
    return s if re.match(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z?\Z", s) else ""


def _int(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def _codes(vs: Iterable[Any], check=_code) -> list[str]:
    return [check(v) for v in vs]


def _base(record: str, *, component: str, arguments: dict[str, Any], harness: str = "", tamper_kind: str = "",
          reason: str = "", **m: Unpack[Meta]) -> dict[str, Any]:
    args = {"record": record, **arguments}
    if tamper_kind:
        if tamper_kind not in TAMPER_KINDS:
            raise ValueError(f"{tamper_kind!r} is not a tamper kind")
        args["tamper_kind"] = tamper_kind
    extra = set(args) - ARGUMENT_KEYS[record]
    if extra:
        raise ValueError(f"{record}: arguments {sorted(extra)} are not allowlisted")
    tool = f"interlock.{component}"
    findings = [{"category": FINDING_CATEGORY, "severity": "high", "rule": f"control.{tamper_kind}", "detector": tool,
                 "path": "hook", "subject": harness or "home", "score": 1.0}] if tamper_kind else []
    return {"event_id": ulid(), "received_at": m.get("at") or now_iso(), "kind": "control", "adapter": "interlock",
            "adapter_version": __version__, "agent_type": harness, "session_id": SESSION_ID, "tool_name": tool,
            "arguments": args, "tier": 0, "normalized": {"action_class": "control"},
            "disposition": "flag" if tamper_kind else "allow", "mode": m.get("mode") or "",
            "reason": tamper_kind or reason or record, "findings": findings, "timing_ms": {},
            "policy_sha256": m.get("policy_sha256") or "", "daemon_version": __version__}


# ---- tamper events and the enforcement point ---------------------------------------------------------------------

def tamper_event(tamper_kind: str, harness: str, path: str, expected_sha256: str = "", observed_sha256: str = "",
                 reason: str = "", *, detector: str = "watch", observed_mode: int | None = None,
                 restored_mode: int | None = None, restore_error: str | None = None,
                 **m: Unpack[Meta]) -> dict[str, Any]:
    """A change to an enforcement point, the token or the Home that no operator action explains. `detector` is
    "watch" (HookWatch) or "verifier" (hot path). `reason` is a fixed code; it defaults to the kind.
    `observed_mode`, `restored_mode` (POSIX modes as ints, -1 on Windows) and `restore_error` (a fixed code, ""
    when the restore worked) are added only when given: the `token_permissions` event carries them."""
    h = _harness(harness)
    args: dict[str, Any] = {"harness": h, "path": _path(path), "expected_sha256": _digest(expected_sha256),
                            "observed_sha256": _digest(observed_sha256), "reason": _code(reason or tamper_kind)}
    if observed_mode is not None:
        args["observed_mode"] = _int(observed_mode) if _int(observed_mode) == observed_mode else -1
    if restored_mode is not None:
        args["restored_mode"] = _int(restored_mode) if _int(restored_mode) == restored_mode else -1
    if restore_error is not None:
        args["restore_error"] = _code(restore_error)
    return _base("tamper_event", component=detector if detector in ("watch", "verifier") else "watch", harness=h,
                 tamper_kind=tamper_kind, arguments=args, **m)


def hook_restored(harness: str, path: str, previous: str, **m: Unpack[Meta]) -> dict[str, Any]:
    """HookWatch found an enforcement point intact again; `previous` is the problem it had."""
    h = _harness(harness)
    return _base("hook_restored", component="watch", harness=h, reason="hook_restored",
                 arguments={"harness": h, "path": _path(path), "previous": _code(previous)}, **m)


def shim_repaired(harness: str, path: str, sha256: str, **m: Unpack[Meta]) -> dict[str, Any]:
    h = _harness(harness)
    return _base("shim_repaired", component="watch", harness=h,
                 arguments={"harness": h, "path": _path(path), "sha256": _digest(sha256)}, **m)


def shim_repair_failed(harness: str, path: str, cause: str, **m: Unpack[Meta]) -> dict[str, Any]:
    """`cause` is a code such as an errno name (`EACCES`), never an exception message."""
    h = _harness(harness)
    return _base("shim_repair_failed", component="watch", harness=h,
                 arguments={"harness": h, "path": _path(path), "cause": _code(cause)}, **m)


def no_baseline(harness: str, **m: Unpack[Meta]) -> dict[str, Any]:
    h = _harness(harness)
    return _base("no_baseline", component="verifier", harness=h, arguments={"harness": h}, **m)


def baseline_created(path: str, **m: Unpack[Meta]) -> dict[str, Any]:
    return _base("baseline_created", component="integrity", arguments={"path": _path(path)}, **m)


def identity_restored(path: str, **m: Unpack[Meta]) -> dict[str, Any]:
    """The identity file was missing and the daemon rewrote it: the Tamper_Event for `identity_missing`."""
    return _base("identity_restored", component="identity", tamper_kind="identity_missing",
                 arguments={"path": _path(path)}, **m)


# ---- operator actions and protection state ----------------------------------------------------------------------

def operator_action(action: str, harness: str = "", protection_state: str = "", *, via: str = "cli",
                    caused_by: str = "", confirmed: bool = False, grace_s: int = 0, failed: bool = False,
                    **m: Unpack[Meta]) -> dict[str, Any]:
    h = _harness(harness)
    return _base("operator_action", component="operator", harness=h, reason=_code(action),
                 arguments={"action": _code(action), "harness": h,
                            "protection_state": protection_state if protection_state in STATES else "",
                            "via": _code(via), "caused_by": _code(caused_by), "confirmed": bool(confirmed),
                            "grace_s": _int(grace_s), "failed": bool(failed)}, **m)


def operator_ack(reasons: Iterable[str], **m: Unpack[Meta]) -> dict[str, Any]:
    """`reasons` are `subject:reason` codes (e.g. `claude-code:shim_modified`, `home:policy_modified`)."""
    return _base("operator_ack", component="operator", arguments={"reasons": _codes(reasons)}, **m)


def protection_state(subject: str, previous: str, new: str, reasons: Iterable[str], caused_by: str = "",
                     **m: Unpack[Meta]) -> dict[str, Any]:
    """`subject` is a harness name or "home"; `reasons` is the complete unresolved set after the change."""
    s = _harness(subject)
    return _base("protection_state", component="protection", harness="" if s == "home" else s, reason=_code(new),
                 arguments={"subject": s, "previous": previous if previous in STATES else "",
                            "new": new if new in STATES else "", "reasons": _codes(reasons),
                            "caused_by": _code(caused_by)}, **m)


# ---- daemon lifecycle ---------------------------------------------------------------------------------------------

def daemon_started(marker_present: bool, marker_action: str = "", **m: Unpack[Meta]) -> dict[str, Any]:
    return _base("daemon_started", component="lifecycle",
                 arguments={"marker_present": bool(marker_present), "marker_action": _code(marker_action)}, **m)


def daemon_unexpected_exit(prev_pid: int, prev_version: str, **m: Unpack[Meta]) -> dict[str, Any]:
    return _base("daemon_unexpected_exit", component="lifecycle", tamper_kind="daemon_unexpected_exit",
                 arguments={"prev_pid": _int(prev_pid), "prev_version": _code(prev_version)}, **m)


def calls_unjudged(*, unjudged: int = 0, tamper_token_rejected: int = 0, tamper_daemon_identity: int = 0,
                   tamper_daemon_lost: int = 0, span_from: str = "", span_to: str = "",
                   **m: Unpack[Meta]) -> dict[str, Any]:
    return _base("calls_unjudged", component="lifecycle",
                 arguments={"unjudged": _int(unjudged), "tamper_token_rejected": _int(tamper_token_rejected),
                            "tamper_daemon_identity": _int(tamper_daemon_identity),
                            "tamper_daemon_lost": _int(tamper_daemon_lost), "span_from": _ts(span_from),
                            "span_to": _ts(span_to)}, **m)


# ---- policy pinning -----------------------------------------------------------------------------------------------

def _policy_kind(kind: str) -> str:
    if kind not in ("policy", "managed"):
        raise ValueError(f"policy kind {kind!r} is not one of policy, managed")
    return kind


def policy_baseline_set(kind: str, path: str, sha256: str, *, failed: bool = False, previous_sha256: str = "",
                        caused_by: str = "", **m: Unpack[Meta]) -> dict[str, Any]:
    """`previous_sha256` and `caused_by` (the Operator_Action's event id) are set by `interlock policy accept`
    (Requirement 7.6) and omitted otherwise."""
    args: dict[str, Any] = {"policy_kind": _policy_kind(kind), "path": _path(path), "sha256": _digest(sha256),
                            "failed": bool(failed)}
    if previous_sha256:
        args["previous_sha256"] = _digest(previous_sha256)
    if caused_by:
        args["caused_by"] = _code(caused_by)
    return _base("policy_baseline_set", component="policy", arguments=args, **m)


def policy_modified(kind: str, path: str, pinned_sha256: str, on_disk_sha256: str, *, added: Iterable[str] = (),
                    removed: Iterable[str] = (), changed: Iterable[str] = (), unparseable: bool = False,
                    **m: Unpack[Meta]) -> dict[str, Any]:
    """Top-level key names only: no values, no nested keys, no file text. An absent file has on_disk_sha256 ""."""
    k = _policy_kind(kind)

    def keys(vs: Iterable[str]) -> list[str]:
        return [v if isinstance(v, str) and _KEY.match(v) else "invalid" for v in vs]

    return _base("policy_modified", component="policy",
                 tamper_kind="managed_policy_modified" if k == "managed" else "policy_modified",
                 arguments={"policy_kind": k, "path": _path(path), "pinned_sha256": _digest(pinned_sha256),
                            "on_disk_sha256": _digest(on_disk_sha256), "added": keys(added),
                            "removed": keys(removed), "changed": keys(changed), "unparseable": bool(unparseable)}, **m)


def policy_restored(kind: str, path: str, sha256: str, *, rejected_sha256: str = "", caused_by: str = "",
                    **m: Unpack[Meta]) -> dict[str, Any]:
    """`rejected_sha256` (the on-disk file `interlock policy revert` replaced, "" when it was absent) and `caused_by`
    (the Operator_Action's event id) are set by the revert (Requirement 7.7) and omitted otherwise."""
    args: dict[str, Any] = {"policy_kind": _policy_kind(kind), "path": _path(path), "sha256": _digest(sha256)}
    if caused_by:
        args["rejected_sha256"] = _digest(rejected_sha256)
        args["caused_by"] = _code(caused_by)
    return _base("policy_restored", component="policy", arguments=args, **m)


# ---- token --------------------------------------------------------------------------------------------------------

def token_rejected(adapter: str, addr: str, **m: Unpack[Meta]) -> dict[str, Any]:
    """`adapter` is the self-reported name (truncated to 64, "unknown" when absent). The presented token is never
    an input to this builder."""
    return _base("token_rejected", component="auth", tamper_kind="token_rejected",
                 arguments={"adapter": _text(adapter, 64) or "unknown", "addr": _text(addr, 128)}, **m)


def token_rejected_summary(adapter: str, count: int, first_at: str, last_at: str, **m: Unpack[Meta]) -> dict[str, Any]:
    return _base("token_rejected_summary", component="auth", tamper_kind="token_rejected",
                 arguments={"adapter": _text(adapter, 64) or "unknown", "count": _int(count),
                            "first_at": _ts(first_at), "last_at": _ts(last_at)}, **m)


def expected_after_rotate(adapter: str, addr: str, **m: Unpack[Meta]) -> dict[str, Any]:
    """The previous token presented within the rotation grace period: recorded, not a Tamper_Event."""
    return _base("expected_after_rotate", component="auth",
                 arguments={"adapter": _text(adapter, 64) or "unknown", "addr": _text(addr, 128)}, **m)


# ---- state files and notifications --------------------------------------------------------------------------------

def state_unreadable(file: str, reason: str, **m: Unpack[Meta]) -> dict[str, Any]:
    """`reason` is the reader's code (`state_unreadable:nesting`, ...)."""
    return _base("state_unreadable", component="statefile", tamper_kind="state_unreadable",
                 arguments={"file": _path(file), "reason": _code(reason)}, **m)


def state_permissions(file: str, check: str, **m: Unpack[Meta]) -> dict[str, Any]:
    return _base("state_permissions", component="statefile",
                 arguments={"file": _path(file), "check": _code(check)}, **m)


def state_write_failed(file: str, reason: str, **m: Unpack[Meta]) -> dict[str, Any]:
    return _base("state_write_failed", component="statefile",
                 arguments={"file": _path(file), "reason": _code(reason)}, **m)


def notify_failed(reason: str, **m: Unpack[Meta]) -> dict[str, Any]:
    return _base("notify_failed", component="notify", arguments={"reason": _code(reason)}, **m)


BUILDERS = {name: globals()[name] for name in ARGUMENT_KEYS}
