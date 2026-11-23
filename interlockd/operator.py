"""Operator_Actions: a state change the Operator makes through an `interlock` command (Requirement 11).

Every state-changing CLI command calls `record(settings, action)` before it changes anything. The record goes to the
running daemon (`POST /interlock/v1/control/operator-action`, bearer, at most 2 s) so the daemon knows *before* its
next HookWatch pass that the change about to happen is explained; when the daemon is down, refuses, does not
identify itself as this Home's daemon, or does not answer in time, the CLI appends the same record to the spool
directly (hash-chained under the spool's file lock, safe next to a running daemon) and the daemon picks it up with
`OperatorActions.seed` at its next start (11.1, 11.2).

`OperatorActions` is the daemon's view of recent actions. `explains(kind, now)` returns the newest action within the
grace period whose name is mapped to that kind of change in `EXPLAINS` (the grace table).

Daemon attributes the API routes look up (wired in `cmd_serve`, task 3.7); each is optional and the routes degrade
to recording in the spool when it is absent:

- `daemon.operator_actions: OperatorActions`
- `daemon.protection: protection.ProtectionState`

Request bodies are untrusted input: only allowlisted fields with fixed codes are read (`parse_action_body`,
`parse_ack_body`), records are rebuilt by `records.*` builders, and no body text reaches a record or a reply.
"""

from __future__ import annotations

import http.client
import json
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from . import identity as identity_mod
from . import records
from .protection import HARNESS_REASONS, HOME, HOME_REASONS

GRACE_S = 120.0
LOOKBACK_S = 600.0
CORRELATE_S = 30.0
CALLS_KEPT = 64                 # interlock_control decisions kept for correlation; agents run a handful per minute
ROUTE = "/interlock/v1/control/operator-action"
ACK_ROUTE = "/interlock/v1/control/ack"
MAX_BODY_BYTES = 4096
MAX_ACK_REASONS = 64

EXPLAINS: dict[str, frozenset[str]] = {k: frozenset(v) for k, v in {
    "enforcement_point": {"init", "uninstall", "ack"},
    "policy": {"init", "shadow", "enforce", "policy_accept", "policy_revert", "ack"},
    "managed_policy": {"console_sync", "ack"},
    "token": {"token_rotate", "init", "ack"},
    "daemon": {"stop", "restart", "shadow", "enforce", "uninstall", "token_rotate", "init"},
    "token_rejected": {"selftest", "token_rotate"},
}.items()}
# Requirement 11.2 names the minimum (uninstall/init -> enforcement point; policy_accept -> policy; token_rotate/init
# -> token; uninstall/stop -> daemon). shadow/enforce/init write the policy file and restart the daemon, selftest
# sends wrong tokens on purpose and ack re-baselines; they are added so those commands raise no alarm about themselves.

# Every action name the daemon accepts on the route: the grace table plus commands that are recorded but explain no
# file change by themselves (they pin or rewrite what they change directly).
ACTIONS = frozenset().union(*EXPLAINS.values()) | {"start", "policy_set", "policy_edit"}
VIA = frozenset({"cli", "console"})          # `hook_session` is set by the daemon only, never accepted from a body
OBSERVING = {"shadow": True, "enforce": False}   # actions that set or lift the Operator's `observing` reason

_ACTION_FIELDS = {"event_id": str, "action": str, "harness": str, "grace_s": int, "failed": bool, "via": str,
                  "cancels": str}
_EVENT_ID = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}\Z")       # ids.ulid: Crockford base32
_HARNESS = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}\Z")
_ACK_CODE = re.compile(r"^(?P<subject>[a-z0-9][a-z0-9_-]{0,31}):(?P<reason>[a-z_]{1,32})\Z")


class BadRequest(ValueError):
    """A control request body that fails validation. The message is fixed text, never copied from the body."""


def action_name(subcommand: str) -> str:
    """`policy accept` -> `policy_accept`, `token --rotate` -> `token_rotate` (CLI spelling -> record code)."""
    return "_".join(w.lstrip("-") for w in str(subcommand or "").split() if w.lstrip("-"))


def _epoch(iso: Any) -> float | None:
    if not isinstance(iso, str) or not iso:
        return None
    try:
        return datetime.fromisoformat(iso).timestamp()
    except ValueError:
        return None


# ---- request bodies (daemon side) -------------------------------------------------------------------------------

def _typed(body: Any, fields: dict[str, type]) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise BadRequest("body must be a JSON object")
    unknown = set(body) - set(fields)
    if unknown:
        raise BadRequest("unknown field")
    for k, t in fields.items():
        if k in body and (type(body[k]) is not t):          # bool is not accepted as int and vice versa
            raise BadRequest(f"field {k} has the wrong type")
    return body


def parse_action_body(body: Any) -> dict[str, Any]:
    """Validate an operator-action request. Returns the allowlisted fields with defaults filled in."""
    b = _typed(body, _ACTION_FIELDS)
    action = b.get("action")
    if action not in ACTIONS:
        raise BadRequest("unknown action")
    harness = b.get("harness", "")
    if harness and not _HARNESS.match(harness):
        raise BadRequest("invalid harness")
    eid = b.get("event_id", "")
    if eid and not _EVENT_ID.match(eid):
        raise BadRequest("invalid event_id")
    grace = b.get("grace_s", int(GRACE_S))
    if not 0 <= grace <= int(LOOKBACK_S):
        raise BadRequest("grace_s out of range")
    via = b.get("via", "cli")
    if via not in VIA:
        raise BadRequest("invalid via")
    cancels = b.get("cancels", "")
    if cancels and (not _EVENT_ID.match(cancels) or not b.get("failed", False)):
        raise BadRequest("invalid cancels")          # only a failed action cancels the one it follows
    return {"event_id": eid, "action": action, "harness": harness, "grace_s": grace,
            "failed": b.get("failed", False), "via": via, "cancels": cancels}


def parse_ack_body(body: Any) -> list[str]:
    """Validate an ack request: `{"reasons": ["claude-code:shim_modified", "home:policy_modified", ...]}`.
    Returns the distinct `subject:reason` codes in request order."""
    b = _typed(body, {"reasons": list})
    raw = b.get("reasons")
    if not isinstance(raw, list) or not raw:
        raise BadRequest("reasons must be a non-empty list")
    if len(raw) > MAX_ACK_REASONS:
        raise BadRequest("too many reasons")
    out: list[str] = []
    for code in raw:
        m = _ACK_CODE.match(code) if isinstance(code, str) else None
        if m is None:
            raise BadRequest("invalid reason code")
        allowed = HOME_REASONS if m["subject"] == HOME else HARNESS_REASONS
        if m["reason"] not in allowed:
            raise BadRequest("unknown reason")
        if code not in out:
            out.append(code)
    return out


# ---- daemon-side handling (called by api.py) --------------------------------------------------------------------

def handle_operator_action(daemon: Any, body: Any) -> dict[str, Any]:
    """The `POST /interlock/v1/control/operator-action` route body. Raises BadRequest on invalid input."""
    f = parse_action_body(body)
    actions: OperatorActions | None = getattr(daemon, "operator_actions", None)
    protection = getattr(daemon, "protection", None)
    via, caused_by, confirmed = f["via"], f["cancels"], False      # a failed action: caused_by = what it cancels
    if actions is not None and not f["failed"]:
        hit = actions.correlate_hook_session(f["action"], time.time())
        if hit is not None:
            via, caused_by, confirmed = "hook_session", hit["event_id"], hit["confirmed"]
    state = protection.aggregate() if protection is not None else ""
    rec = records.operator_action(f["action"], f["harness"], state, via=via, caused_by=caused_by,
                                  confirmed=confirmed, grace_s=f["grace_s"], failed=f["failed"],
                                  **records.meta(daemon))
    if f["event_id"]:
        rec["event_id"] = f["event_id"]   # the CLI's id, so its own copy and the stored record agree
    _append(daemon, rec)
    if actions is not None:
        actions.add(rec)
    if protection is not None and not f["failed"] and f["action"] in OBSERVING:
        # the Operator's `shadow` / `enforce` choice (11.3); persisted, so the restart that follows keeps it
        protection.set_observing(OBSERVING[f["action"]], caused_by=rec["event_id"])
    return {"event_id": rec["event_id"]}


def handle_ack(daemon: Any, body: Any) -> dict[str, Any]:
    """The `POST /interlock/v1/control/ack` route body: clear the listed reasons and record `control.operator_ack`
    naming each one cleared. Nothing unresolved among them: no record (11.9)."""
    codes = parse_ack_body(body)
    protection = getattr(daemon, "protection", None)
    if protection is None:              # no in-memory state to clear (pre-3.7 daemon): keep the audit trail anyway
        rec = records.operator_ack(codes, **records.meta(daemon))
        _append(daemon, rec)
        return {"event_id": rec["event_id"], "cleared": []}
    wanted = set(codes)
    matching = [r.code for r in protection.reasons() if r.code in wanted]
    if not matching:
        return {"event_id": None, "cleared": []}
    rec = records.operator_ack(matching, **records.meta(daemon))
    _append(daemon, rec)
    gone = protection.clear(lambda r: r.code in wanted, caused_by=rec["event_id"])
    return {"event_id": rec["event_id"], "cleared": [r.code for r in gone]}


def _append(daemon: Any, rec: dict[str, Any]) -> None:
    daemon.spool.append(rec)
    otel = getattr(daemon, "otel", None)
    if otel is not None:
        otel.submit(rec)


# ---- CLI side ---------------------------------------------------------------------------------------------------

def _daemon_address(settings: Any) -> tuple[str, int]:
    """Where this Home's daemon listens: `daemon.json` "listen" when present, else the configured address."""
    listen = settings.listen
    try:
        doc = json.loads((Path(settings.home) / "daemon.json").read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("listen"), str):
            listen = doc["listen"]
    except (OSError, ValueError):
        pass
    host, _, port = listen.rpartition(":")
    return host or "127.0.0.1", int(port)


def _deliver(settings: Any, body: dict[str, Any], timeout_s: float, path: str = ROUTE) -> dict[str, Any] | None:
    """POST `body` to this Home's daemon. The reply, or None on any failure: no token, connection refused, timeout
    (the whole exchange is bounded by `timeout_s`), a non-200 status, or a reply that does not carry this Home's
    identity (another process answering on the port is not this Home's daemon)."""
    deadline = time.monotonic() + timeout_s
    try:
        token = Path(settings.token_path).read_text(encoding="utf-8").strip()
        host, port = _daemon_address(settings)
    except (OSError, ValueError):
        return None
    if not token:
        return None
    want = identity_mod.read(Path(settings.home))
    if want is None:
        return None     # no daemon of this Home has identified itself: do not send the token to whoever listens
    data = json.dumps(body, separators=(",", ":")).encode()
    conn = http.client.HTTPConnection(host, port, timeout=timeout_s)
    try:
        conn.connect()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        conn.sock.settimeout(remaining)
        conn.request("POST", path, body=data, headers={"Authorization": f"Bearer {token}",
                                                      "Content-Type": "application/json"})
        resp = conn.getresponse()
        raw = resp.read(MAX_BODY_BYTES + 1)
        got = resp.headers.get_all(identity_mod.HEADER) or []
        if resp.status != 200 or not identity_mod.verify(got, want):
            return None
        reply = json.loads(raw or b"{}")
        return reply if isinstance(reply, dict) else None
    except (OSError, http.client.HTTPException, ValueError):
        return None
    finally:
        conn.close()


def record(settings: Any, action: str, *, harness: str = "", grace_s: float = GRACE_S, via: str = "cli",
           failed: bool = False, cancels: str = "", timeout_s: float = 2.0) -> dict[str, Any]:
    """Record an Operator_Action before the command changes any state (11.1). Delivered through the daemon when it
    acknowledges within `timeout_s`, else appended to the spool directly. Returns the record (with `event_id`).

    `failed=True, cancels=<event_id>` marks the action recorded as `event_id` as failed: the failed record carries
    the id in `caused_by`, and `OperatorActions` drops the cancelled action, so no grace period follows it (2.6).
    Raises ValueError for an action name the daemon would not accept, OSError when the direct append fails."""
    if action not in ACTIONS:
        raise ValueError(f"{action!r} is not an operator action")
    if via not in VIA:
        raise ValueError(f"via {via!r} is not one of {sorted(VIA)}")
    if cancels and (not failed or not _EVENT_ID.match(cancels)):
        raise ValueError("cancels needs failed=True and an event id")
    grace = int(grace_s)
    rec = records.operator_action(action, harness, via=via, caused_by=cancels, grace_s=grace, failed=failed)
    body = {"event_id": rec["event_id"], "action": action, "harness": harness, "grace_s": grace,
            "failed": bool(failed), "via": via}
    if cancels:
        body["cancels"] = cancels
    reply = _deliver(settings, body, timeout_s)
    if reply is not None and reply.get("event_id") == rec["event_id"]:
        return rec
    from .store.spool import Spool

    Spool(Path(settings.spool_dir)).append(rec)
    return rec


# ---- daemon-side view of recent actions -------------------------------------------------------------------------

class OperatorActions:
    """Recent Operator_Actions, newest last. Thread-safe."""

    def __init__(self, spool: Any, now: Callable[[], float] = time.time, *, lookback_s: float = LOOKBACK_S):
        self.spool = spool
        self._now = now
        self.lookback_s = lookback_s
        self._lock = threading.Lock()
        self._actions: deque[dict[str, Any]] = deque(maxlen=512)
        self._calls: deque[dict[str, Any]] = deque(maxlen=CALLS_KEPT)   # recent interlock_control decisions

    @staticmethod
    def _entry(rec: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(rec, dict) or rec.get("kind") != "control":
            return None
        args = rec.get("arguments")
        if not isinstance(args, dict) or args.get("record") != "operator_action" or args.get("failed"):
            return None     # a failed action changed nothing and starts no grace period (2.6)
        at = _epoch(rec.get("received_at"))
        action = args.get("action")
        if at is None or not isinstance(action, str) or not action:
            return None
        return {"action": action, "at": at, "event_id": str(rec.get("event_id") or ""),
                "harness": str(args.get("harness") or ""), "via": str(args.get("via") or "")}

    def seed(self, lookback_s: float | None = None) -> int:
        """Load the operator actions recorded in the spool in the last `lookback_s` seconds (by daemons and by CLIs
        appending directly while the daemon was down), before the first integrity check (11.2). Returns the count."""
        now = self._now()
        cutoff = now - (self.lookback_s if lookback_s is None else lookback_s)
        found: list[dict[str, Any]] = []
        calls: list[dict[str, Any]] = []
        claimed: set[str] = set()
        cancelled: set[str] = set()
        try:
            for rec in self.spool.iter_records():
                at = _epoch(rec.get("received_at")) if isinstance(rec, dict) else None
                if at is not None and at < cutoff - 60.0:
                    break           # newest first; a minute of slack for records written slightly out of order
                if c := self._cancelled(rec):
                    cancelled.add(c)
                e = self._entry(rec)
                if e is not None and e["at"] >= cutoff:
                    found.append(e)
                    caused_by = rec["arguments"].get("caused_by")
                    if isinstance(caused_by, str) and caused_by:
                        claimed.add(caused_by)
                call = _hook_session_entry(rec)
                if call is not None and now - call["at"] < CORRELATE_S:
                    calls.append(call)
        except (OSError, ValueError):
            pass                    # an unreadable spool segment must not stop the daemon from starting
        found = sorted((e for e in found if e["event_id"] not in cancelled), key=lambda e: e["at"])
        with self._lock:
            if cancelled:
                kept = [e for e in self._actions if e["event_id"] not in cancelled]
                self._actions.clear()
                self._actions.extend(kept)
            known = {e["event_id"] for e in self._actions}
            for e in found:
                if e["event_id"] not in known:
                    self._actions.append(e)
            self._sort()
            for c in self._calls:
                c["claimed"] = c["claimed"] or c["event_id"] in claimed
            seen = {c["event_id"] for c in self._calls}
            for c in sorted(calls, key=lambda c: c["at"]):
                if c["event_id"] not in seen:
                    c["claimed"] = c["event_id"] in claimed
                    self._calls.append(c)
        return len(found)

    def _sort(self) -> None:
        ordered = sorted(self._actions, key=lambda e: e["at"])
        self._actions.clear()
        self._actions.extend(ordered)

    @staticmethod
    def _cancelled(rec: Any) -> str:
        """The event id a failed operator-action record cancels, or ""."""
        if not isinstance(rec, dict) or rec.get("kind") != "control":
            return ""
        args = rec.get("arguments")
        if not isinstance(args, dict) or args.get("record") != "operator_action" or not args.get("failed"):
            return ""
        c = args.get("caused_by")
        return c if isinstance(c, str) else ""

    def add(self, rec: dict[str, Any]) -> None:
        cancelled = self._cancelled(rec)
        if cancelled:
            with self._lock:
                kept = [e for e in self._actions if e["event_id"] != cancelled]
                self._actions.clear()
                self._actions.extend(kept)
            return
        e = self._entry(rec)
        if e is None:
            return
        with self._lock:
            self._actions.append(e)
            if len(self._actions) > 1 and self._actions[-2]["at"] > e["at"]:
                self._sort()

    def recent(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._actions]

    def explains(self, change_kind: str, now: float | None = None) -> dict[str, Any] | None:
        """The newest action mapped to `change_kind` in `EXPLAINS` recorded within the preceding GRACE_S."""
        names = EXPLAINS.get(change_kind)
        if not names:
            return None
        t = self._now() if now is None else now
        with self._lock:
            for e in reversed(self._actions):
                if e["action"] in names and 0 <= t - e["at"] < GRACE_S:
                    return dict(e)
        return None

    # ---- hook-session correlation (design decision 8) ---------------------------------------------------------
    #
    # When an agent runs `interlock token --rotate` (or another control subcommand) through a gated tool call, the
    # daemon judged that call first: a `pre_action` decision record carrying the finding `persistence.interlock_control`
    # and `normalized.interlock_control` (the command-line spelling). Seconds later the CLI it started posts the
    # operator action. The pipeline hands every such decision to `note_decision` as it stores it, so correlation is a
    # lookup in a small in-memory ring, not a spool scan; `seed` refills the ring from the spool after a restart.
    #
    # Which decisions can have caused an action: only calls the harness actually ran. In shadow mode every call runs.
    # In enforce mode a `block`, or an `ask` to a harness without a hook-driven ask (Kiro, Windsurf, Cursor and
    # Gemini render ask as a refusal), did not run, so it cannot have started the command; the action is then the
    # Operator's own and stays `via: cli`.
    #
    # `confirmed` is true only with evidence the user approved this call: enforce mode and either an `ask` shown to a
    # harness that prompts the user (capabilities.ask; the command running at all means the prompt was answered yes,
    # and the operator action arrives while the tool runs, before any post hook could confirm it) or an `allow` the
    # transcript judge resolved from the user's own words (finding `x.interlock.confirmed_via_transcript`). Shadow
    # mode, an `allow` from a policy override and a `pass` carry no approval: `confirmed: false`.
    #
    # One decision explains at most one action: a correlated decision is claimed (in memory, and through
    # `caused_by` of operator-action records when seeding), so a second `interlock stop` 5 s later is not attributed
    # to the same tool call.

    def note_decision(self, rec: dict[str, Any]) -> None:
        """Called by the pipeline for every stored decision record; keeps the `interlock_control` ones."""
        e = _hook_session_entry(rec)
        if e is None:
            return
        with self._lock:
            self._calls.append(e)

    def correlate_hook_session(self, action: str, now: float | None = None, *,
                               window_s: float = CORRELATE_S) -> dict[str, Any] | None:
        """The newest unclaimed `pre_action` decision within the preceding `window_s` seconds whose finding rule is
        `persistence.interlock_control`, whose normalized subcommand names `action` and which the harness ran.
        Claims it and returns {"event_id", "disposition", "mode", "session_id", "confirmed"}, else None."""
        t = self._now() if now is None else now
        with self._lock:
            # the ring is small (CALLS_KEPT): scan it whole rather than trust append order across threads
            hits = [e for e in self._calls if e["action"] == action and not e["claimed"]
                    and -1.0 <= t - e["at"] < window_s]
            if not hits:
                return None
            e = max(hits, key=lambda e: e["at"])
            e["claimed"] = True
            return {k: e[k] for k in ("event_id", "disposition", "mode", "session_id", "confirmed")}


def _hook_session_entry(rec: Any) -> dict[str, Any] | None:
    """A decision record the agent's tool call produced for an `interlock` control subcommand it ran, or None."""
    if not isinstance(rec, dict) or rec.get("kind") != "pre_action":
        return None
    findings = [f for f in rec.get("findings") or [] if isinstance(f, dict)]
    if not any(f.get("rule") == "persistence.interlock_control" for f in findings):
        return None
    norm = rec.get("normalized")
    action = action_name(norm.get("interlock_control", "")) if isinstance(norm, dict) else ""
    at = _epoch(rec.get("received_at"))
    if not action or at is None:
        return None
    mode, disposition = str(rec.get("mode") or ""), str(rec.get("disposition") or "")
    caps = rec.get("capabilities")
    prompts = isinstance(caps, dict) and caps.get("ask") is True
    if mode == "enforce" and (disposition == "block" or (disposition == "ask" and not prompts)):
        return None                     # refused: the harness did not run this call
    confirmed = mode == "enforce" and (
        (disposition == "ask" and prompts)
        or (disposition == "allow"
            and any(f.get("category") == "x.interlock.confirmed_via_transcript" for f in findings)))
    return {"event_id": str(rec.get("event_id") or ""), "at": at, "action": action, "disposition": disposition,
            "mode": mode, "session_id": str(rec.get("session_id") or ""), "confirmed": confirmed, "claimed": False}
