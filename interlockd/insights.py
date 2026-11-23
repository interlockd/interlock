"""`interlock report` (what the gate decided, from the local spool) and `interlock doctor` (is protection actually on).

Both read only local state: the spool, the install manifest, the hook files, and the daemon's health endpoint.
"""

from __future__ import annotations

import json
import os
import re
import stat
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__

STOPPED = ("block", "ask", "withhold")


# ------------------------------------------------------------------------------------------------ report


@dataclass
class Report:
    days: int
    total: int = 0
    pre: int = 0
    post: int = 0
    by_disposition: Counter = field(default_factory=Counter)
    shadow_would: Counter = field(default_factory=Counter)     # decisions recorded in shadow that enforce would apply
    enforced: Counter = field(default_factory=Counter)
    rules: Counter = field(default_factory=Counter)
    agents: Counter = field(default_factory=Counter)
    examples: list[dict] = field(default_factory=list)
    latencies: list[float] = field(default_factory=list)
    unjudged: int = 0
    gateway_hidden: list[str] = field(default_factory=list)     # "server/tool: reason" from the MCP gateway log
    gateway_pinned: int = 0
    hook_changes: list[str] = field(default_factory=list)       # control records from the hook watch

    def p(self, q: float) -> float:
        xs = sorted(self.latencies)
        return round(xs[min(len(xs) - 1, int(q * len(xs)))], 1) if xs else 0.0


def _detail(rec: dict) -> str:
    a = rec.get("arguments") or {}
    d = a.get("command") or a.get("path") or a.get("file_path") or a.get("url") or a.get("query") or ""
    return str(d).replace("\n", " ")[:90]


def build_report(records: list[dict], *, days: int = 7, now: datetime | None = None) -> Report:
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=days)
    r = Report(days=days)
    for rec in records:
        if str(rec.get("session_id") or "").startswith("interlock-selftest"):
            continue
        try:
            ts = datetime.fromisoformat(rec.get("received_at", ""))
        except ValueError:
            continue
        if ts < cutoff:
            continue
        if rec.get("kind") == "control":
            who = rec.get("agent_type") or "home"
            r.hook_changes.append(f"{rec.get('received_at', '')[:16].replace('T', ' ')}  {who}  {rec.get('reason') or ''}"[:140])
            continue
        r.total += 1
        r.pre += rec.get("kind") == "pre_action"
        r.post += rec.get("kind") == "post_action"
        disp = rec.get("disposition", "?")
        r.by_disposition[disp] += 1
        r.agents[rec.get("agent_type") or rec.get("adapter") or "?"] += 1
        if rec.get("unjudged"):
            r.unjudged += 1
        t = (rec.get("timing_ms") or {}).get("total")
        if isinstance(t, (int, float)):
            r.latencies.append(float(t))
        if disp in STOPPED or disp == "warn":
            (r.shadow_would if rec.get("mode") == "shadow" else r.enforced)[disp] += 1
            for f in rec.get("findings") or []:
                if f.get("rule") and not str(f.get("category", "")).startswith("x.interlock"):
                    r.rules[f["rule"]] += 1
            if disp in STOPPED and len(r.examples) < 8:
                r.examples.append({"at": rec.get("received_at", "")[:16].replace("T", " "), "disposition": disp,
                                   "mode": rec.get("mode"), "tool": rec.get("tool_name"), "detail": _detail(rec),
                                   "reason": (rec.get("reason") or "")[:90]})
    return r


def add_gateway_log(r: Report, log: Path, *, now: datetime | None = None) -> None:
    """Tool-list interventions live in ~/.interlock/mcp-proxy.log (calls and results are already in the spool)."""
    if not log.exists():
        return
    cutoff = ((now or datetime.now(UTC)) - timedelta(days=r.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        if line[:20] < cutoff:
            continue
        try:
            server = line.split("[", 1)[1].split("]", 1)[0]
            msg = line.split("] ", 1)[1]
        except IndexError:
            continue
        for marker in ("hid tool ", "would hide (shadow) tool "):
            if msg.startswith(marker):
                tool, _, why = msg[len(marker):].partition(": ")
                entry = f"{server}/{tool}: {why[:80]}" + (" (shadow)" if "shadow" in marker else "")
                if entry not in r.gateway_hidden:
                    r.gateway_hidden.append(entry)
        if msg.startswith("pinned "):
            r.gateway_pinned += int(msg.split()[1])


def format_report(r: Report) -> str:
    if r.total == 0 and not r.gateway_hidden and not r.hook_changes:
        return (f"No decisions recorded in the last {r.days} days. Is the daemon running and are hooks installed? "
                "Try `interlock doctor`.")
    lines = [f"Interlock report: last {r.days} days", "",
             f"  {r.total} decisions ({r.pre} before a tool ran, {r.post} on tool results) across "
             + ", ".join(f"{n} {a}" for a, n in r.agents.most_common()),
             f"  latency p50 {r.p(0.5)} ms, p95 {r.p(0.95)} ms"]
    if r.shadow_would:
        lines.append("  in shadow mode, enforce would have: " + ", ".join(
            f"{_verb(d)} {n}" for d, n in r.shadow_would.most_common()))
    if r.enforced:
        lines.append("  enforced: " + ", ".join(f"{_verb(d)} {n}" for d, n in r.enforced.most_common()))
    if not r.shadow_would and not r.enforced:
        lines.append("  nothing was blocked, asked, or withheld")
    if r.unjudged:
        lines.append(f"  {r.unjudged} decisions were partly unjudged (a detector was unavailable)")
    if r.rules:
        lines += ["", "Top rules:"] + [f"  {n:>4}  {rule}" for rule, n in r.rules.most_common(8)]
    if r.gateway_hidden or r.gateway_pinned:
        lines += ["", f"MCP gateway: {r.gateway_pinned} tool definitions pinned; hidden from the agent:"]
        lines += [f"  {h}" for h in r.gateway_hidden[:10]] or ["  none"]
    if r.hook_changes:
        lines += ["", "Hook changes (enforcement lost or restored):"] + [f"  {h}" for h in r.hook_changes[-10:]]
    if r.examples:
        lines += ["", "Recent stops:"] + [
            f"  {e['at']}  {e['disposition']:<8}{' (shadow)' if e['mode'] == 'shadow' else '         '} {e['tool']:<10} {e['detail']}"
            for e in r.examples]
    if r.shadow_would:
        lines += ["", ("Ready to enforce? `interlock enforce`. Too noisy? override a rule in ~/.interlock/policy.yaml "
                       "(packs.overrides) and rerun this report.")]
    return "\n".join(lines)


def _verb(d: str) -> str:
    return {"block": "blocked", "ask": "asked on", "withhold": "withheld", "warn": "warned on"}.get(d, d)


# ------------------------------------------------------------------------------------------------ doctor


@dataclass
class Check:
    ok: bool
    name: str
    detail: str
    fix: str = ""
    warn: bool = False      # a soft finding: reported, does not fail the run
    lines: list[str] = field(default_factory=list)   # extra indented lines under the detail (event lists)


# ------------------------------------------------------------------------------------------------ health + protection


@dataclass
class Health:
    """One GET of `/interlock/v1/health`. `body` is set only when the reply carried exactly one identity header equal
    to `<Home>/identity` (Req 1): a reply from any other process is never read as this Home's state."""
    addr: str
    reachable: bool = False          # something answered HTTP on the address
    verified: bool = False           # ... and proved it is this Home's daemon
    body: dict[str, Any] | None = None
    headers: int = 0                 # how many identity header lines the reply carried
    identity_file: bool = False      # <Home>/identity exists and holds 32 lowercase hex


def fetch_health(home: Path, listen: str, *, timeout: float = 1.5) -> Health:
    """Unauthenticated health read: the token is never sent, so an unverified listener learns nothing from us."""
    import http.client

    from . import identity

    host, _, port = listen.rpartition(":")
    host = (host or "127.0.0.1").strip("[]")
    h = Health(addr=listen)
    expected = identity.read(home)
    h.identity_file = expected is not None
    try:
        conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
        try:
            conn.request("GET", "/interlock/v1/health")
            resp = conn.getresponse()
            values = resp.headers.get_all(identity.HEADER) or []
            raw = resp.read(256 * 1024)
        finally:
            conn.close()
    except (OSError, ValueError, http.client.HTTPException):
        return h
    h.reachable, h.headers = True, len(values)
    if expected is None or not identity.verify(list(values), expected) or resp.status != 200:
        return h
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return h
    if isinstance(body, dict):
        h.verified, h.body = True, body
    return h


_SAFE = re.compile(r"[^A-Za-z0-9_.:+-]")


def _safe(v: Any, n: int = 64) -> str:
    """A code, harness name or timestamp from health or a state file, reduced to characters that cannot carry
    terminal escapes or text."""
    return _SAFE.sub("", str(v or ""))[:n]


HARNESS_REPAIR = "`interlock doctor`, then `interlock init` to repair or `interlock ack` to accept the change"
REPAIR = {
    "shim_modified": HARNESS_REPAIR, "shim_missing": HARNESS_REPAIR, "shim_relocated": HARNESS_REPAIR,
    "hook_removed": HARNESS_REPAIR,
    "token_modified": "`interlock token --rotate`, or `interlock ack` to accept the token on disk",
    "token_missing": "`interlock token --rotate`, or `interlock ack`",
    "token_permissions": "`chmod 600` the token (the daemon restores it), then `interlock ack`",
    "policy_modified": "`interlock policy diff`, then `interlock policy accept` or `interlock policy revert`",
    "managed_policy_modified": "`interlock ack` to accept the managed policy on disk",
    "identity_missing": "`interlock ack` (the daemon has rewritten the identity file)",
    "state_unreadable": "`interlock ack` (the unreadable protection-state.json is replaced)",
    "daemon_unreachable": "`interlock doctor`, then `interlock start`",
    "daemon_identity": "stop the process answering on the daemon's address (another Interlock home?), "
                       "then `interlock restart`",
}
MANAGED_REPAIR_CONSOLE = ("re-run the Console sync: `interlock restart` (the Console add-on re-applies the org policy "
                          "on its first heartbeat), or `interlock ack`")


def _console_addon() -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec("interlockd_console") is not None
    except (ImportError, ValueError):
        return False


def repair_for(reason: str) -> str:
    if reason == "managed_policy_modified" and _console_addon():
        return MANAGED_REPAIR_CONSOLE
    return REPAIR.get(reason, "`interlock doctor`")


@dataclass(frozen=True)
class ReasonView:
    subject: str          # harness name or "home"
    reason: str
    detected_at: str


@dataclass
class ProtectionView:
    """What `status` and `doctor` print about protection, from one source: the verified health reply, or (daemon
    down) the Stop_Marker and the persisted protection-state.json."""
    aggregate: str                         # one of records.STATES, or "compromised" for the CLI-side causes below
    cause: str = ""                        # "daemon_unreachable" | "daemon_identity" when the CLI decided
    reasons: list[ReasonView] = field(default_factory=list)
    live: bool = False                     # read from the running daemon (else from files)
    marker_action: str = ""
    marker_at: str = ""
    policy_pin: dict[str, Any] = field(default_factory=dict)
    fail_mode_tamper: str = ""
    last_tamper_at: str = ""


def identity_problem(health: Health) -> tuple[str, str]:
    """(what is wrong, repair) for a reachable listener whose reply did not verify."""
    where = f"http://{health.addr}"
    if health.headers == 0 and not health.identity_file:
        what = (f"the process on {where} sends no identity and this home has no identity file: an Interlock daemon "
                "from before identities (restart it on this version) or another process")
        return what, "run `interlock restart`"
    why = ("no identity header" if health.headers == 0 else
           f"{health.headers} identity headers" if health.headers > 1 else "a different identity")
    return f"the process on {where} sent {why}: it is not this home's daemon", REPAIR["daemon_identity"]


def _snapshot_reasons(p: dict[str, Any]) -> list[ReasonView]:
    out: list[ReasonView] = []
    harnesses = p.get("harnesses") if isinstance(p.get("harnesses"), dict) else {}
    for name, row in sorted(harnesses.items()):
        for r in (row.get("reasons") or []) if isinstance(row, dict) else []:
            if isinstance(r, dict):
                out.append(ReasonView(_safe(name, 32), _safe(r.get("reason")), _safe(r.get("detected_at"))))
    for r in p.get("home_reasons") or []:
        if isinstance(r, dict):
            out.append(ReasonView("home", _safe(r.get("reason")), _safe(r.get("detected_at"))))
    return out


def persisted_reasons(home: Path) -> list[ReasonView] | None:
    """The unresolved reasons in `<Home>/protection-state.json` (read-only), or None when absent or unreadable."""
    from . import protection, statefile

    doc = statefile.read_state(home / protection.FILE, {"observing": bool, "reasons": dict, "events": dict})
    if doc is None:
        return None
    out = []
    for k, at in sorted(doc["reasons"].items()):
        parsed = protection._parse_key(k)
        if parsed is not None:
            out.append(ReasonView(parsed[0], parsed[1], _safe(at)))
    return out


def protection_view(home: Path, health: Health) -> ProtectionView:
    from . import lifecycle, records

    if not health.reachable:
        marker = lifecycle.read_stop_marker(home)
        if marker is not None:
            return ProtectionView("stopped", marker_action=_safe(marker.get("action")),
                                  marker_at=_safe(marker.get("written_at")))
        return ProtectionView("compromised", cause="daemon_unreachable", reasons=persisted_reasons(home) or [])
    if not health.verified:
        return ProtectionView("compromised", cause="daemon_identity")
    body = health.body or {}
    p = body.get("protection") if isinstance(body.get("protection"), dict) else {}
    agg = p.get("aggregate") if p.get("aggregate") in records.STATES else "unknown"
    pin = body.get("policy_pin") if isinstance(body.get("policy_pin"), dict) else {}
    return ProtectionView(agg, reasons=_snapshot_reasons(p), live=True,
                          policy_pin={k: _safe(pin.get(k)) for k in ("pinned_sha256", "on_disk_sha256")},
                          fail_mode_tamper=_safe(body.get("fail_mode_tamper"), 8),
                          last_tamper_at=_safe(p.get("last_tamper_at")))


def _spool(home: Path):
    from .store.spool import Spool

    sd = home / "spool"
    return Spool(sd, fsync=False) if sd.exists() else None


def latest_policy_change(home: Path, kind: str) -> dict[str, Any] | None:
    """The newest `control.policy_modified` record's key names for `kind` ("policy" | "managed"), or None."""
    sp = _spool(home)
    if sp is None:
        return None
    try:
        for rec in sp.iter_records(limit=20000):
            a = rec.get("arguments") or {}
            if rec.get("kind") == "control" and a.get("record") == "policy_modified" and a.get("policy_kind") == kind:
                return {k: [_safe(x) for x in a.get(k) or []] for k in ("added", "removed", "changed")} | {
                    "unparseable": bool(a.get("unparseable")),
                    "pinned_sha256": _safe(a.get("pinned_sha256")), "on_disk_sha256": _safe(a.get("on_disk_sha256"))}
    except (OSError, ValueError):
        return None
    return None


def _changed_keys(c: dict[str, Any] | None) -> str:
    if c is None:
        return "not recorded"
    if c["unparseable"]:
        return "the file on disk could not be parsed"
    parts = [f"{k}: {', '.join(c[k])}" for k in ("added", "removed", "changed") if c[k]]
    return "; ".join(parts) or "none at the top level"


def _policy_lines(home: Path, view: ProtectionView, reason: str, indent: str) -> list[str]:
    """Pinned versus on-disk digests and the changed top-level key names for a policy_modified reason (7.5, 7.10)."""
    from . import integrity

    kind = "managed" if reason == "managed_policy_modified" else "policy"
    change = latest_policy_change(home, kind)
    if kind == "policy" and view.policy_pin:
        pinned, on_disk = view.policy_pin.get("pinned_sha256", ""), view.policy_pin.get("on_disk_sha256", "")
    else:
        base = integrity.Baseline.load(home)
        pinned = base.managed_policy_file_sha256 if base is not None and kind == "managed" else (
            base.policy_file_sha256 if base is not None else "")
        on_disk = integrity.file_sha256(home / (integrity.MANAGED_POLICY_FILE if kind == "managed"
                                                else integrity.POLICY_FILE))
    return [f"{indent}pinned   {pinned or 'none'}", f"{indent}on disk  {on_disk or 'absent'}",
            f"{indent}changed  {_changed_keys(change)}"]


def format_protection_status(home: Path, listen: str, *, health: Health | None = None) -> tuple[str, int]:
    """The protection block `interlock status` prints first (Req 6.4, 7.5, 7.10, 9.8, 9.9). Exit 1 when compromised."""
    health = health or fetch_health(home, listen)
    v = protection_view(home, health)
    first = f"protection  {v.aggregate}" + (f" {v.cause}" if v.cause else "")
    lines = [first]
    if v.aggregate == "stopped":
        lines.append(f"            stopped by `interlock {v.marker_action}` at {v.marker_at}   (interlock start)")
    if v.cause == "daemon_unreachable":
        lines.append(f"            nothing answers on http://{listen} and no `interlock stop` explains it"
                     f"   → {REPAIR['daemon_unreachable']}")
        for r in v.reasons:
            lines.append(f"            last recorded: {r.subject} {r.reason} since {r.detected_at}")
    if v.cause == "daemon_identity":
        what, fix = identity_problem(health)
        lines.append(f"            {what}   → {fix}")
    for r in v.reasons if v.live else []:
        lines.append(f"  {r.subject:<12} {r.reason:<24} since {r.detected_at}   → {repair_for(r.reason)}")
        if r.reason in ("policy_modified", "managed_policy_modified"):
            lines += _policy_lines(home, v, r.reason, " " * 15)
    return "\n".join(lines), (1 if v.aggregate == "compromised" else 0)


# ------------------------------------------------------------------------------------------------ doctor: tamper


def tamper_events(home: Path, *, since: str | None = None) -> tuple[list[dict[str, Any]], str]:
    """Tamper_Events since the last `control.operator_ack` (else since the Integrity_Baseline was created), newest
    first, without the `token_rejected` records a `selftest` caused (Req 14.1, 14.7). Returns (events, since)."""
    from . import integrity, lifecycle, operator

    sp = _spool(home)
    if sp is None:
        return [], since or ""
    found: list[dict[str, Any]] = []
    selftests: list[datetime] = []
    ack_at = ""
    try:
        for rec in sp.iter_records():
            if rec.get("kind") != "control":
                continue
            a = rec.get("arguments") or {}
            if a.get("record") == "operator_ack":
                ack_at = str(rec.get("received_at") or "")
                break
            if a.get("record") == "operator_action" and a.get("action") == "selftest":
                if (t := lifecycle.parse_iso(rec.get("received_at"))) is not None:
                    selftests.append(t)
            elif a.get("tamper_kind"):
                found.append(rec)
    except (OSError, ValueError):
        pass
    if since is None:
        if ack_at:
            since = ack_at
        else:
            base = integrity.Baseline.load(home)
            since = base.created_at if base is not None else ""
    cutoff = lifecycle.parse_iso(since)
    grace = timedelta(seconds=operator.GRACE_S)
    out = []
    for rec in found:
        t = lifecycle.parse_iso(rec.get("received_at"))
        if t is None or (cutoff is not None and t < cutoff):
            continue
        if rec["arguments"]["tamper_kind"] == "token_rejected" and any(s <= t < s + grace for s in selftests):
            continue
        who = rec.get("agent_type") or rec["arguments"].get("adapter")     # token_rejected: the self-reported adapter
        out.append({"at": _safe(rec.get("received_at")), "subject": _safe(who, 32) or "home",
                    "kind": _safe(rec["arguments"]["tamper_kind"])})
    return out, _safe(since)


SHOWN_EVENTS = 50


def protection_checks(home: Path, health: Health, policy_tamper: str | None) -> list[Check]:
    """Doctor's protection block (Req 6.5, 14.1, 14.2): state, each reason, Tamper_Events, baseline coverage,
    fail_mode.tamper, the identity file, and recent `tamper` lines in hook.log."""
    from . import integrity
    from .onboard import Manifest

    out: list[Check] = []
    v = protection_view(home, health)
    if v.aggregate == "stopped":
        out.append(Check(True, "protection", f"stopped by `interlock {v.marker_action}` at {v.marker_at}",
                         "interlock start", warn=True))
    elif v.cause:
        fix = identity_problem(health)[1] if v.cause == "daemon_identity" else REPAIR[v.cause]
        out.append(Check(False, "protection", f"compromised {v.cause}", fix))
    else:
        out.append(Check(v.aggregate != "compromised", "protection", v.aggregate,
                         "see the reasons below" if v.aggregate == "compromised" else "",
                         warn=v.aggregate in ("observing", "unknown")))
    label = "" if v.live else " (last recorded)"
    for r in v.reasons:
        extra = _policy_lines(home, v, r.reason, "") if r.reason in ("policy_modified", "managed_policy_modified") else []
        out.append(Check(False, f"tamper {r.subject}", f"{r.reason} since {r.detected_at}{label}", repair_for(r.reason),
                         lines=extra))

    events, since = tamper_events(home)
    if events:
        shown = events[:SHOWN_EVENTS]
        more = f", showing the latest {SHOWN_EVENTS}" if len(events) > SHOWN_EVENTS else ""
        out.append(Check(True, "tamper events", f"{len(events)} since {since or 'the start of the audit log'}"
                         f" (last `interlock ack` or baseline){more}", warn=True,
                         lines=[f"{e['at']}  {e['subject']:<12} {e['kind']}" for e in shown]))
    else:
        out.append(Check(True, "tamper events", f"none since {since or 'the start of the audit log'}"))

    man = Manifest.load(home)
    harnesses = sorted({h["harness"] for h in (man.hooks if man else [])})
    base = integrity.Baseline.load(home)
    if base is None:
        out.append(Check(False, "baseline", f"{home / integrity.BASELINE} missing or unreadable"
                         + (f"; not covered: {', '.join(harnesses)}" if harnesses else ""), "run `interlock init`"))
    else:
        missing = [h for h in harnesses if integrity.key(h) not in base.shims]
        out.append(Check(not missing, "baseline",
                         f"covers {len(harnesses)} enforcement point(s), created {_safe(base.created_at)}" if not missing
                         else f"not covered: {', '.join(missing)}", "" if not missing else "run `interlock init`"))

    tamper = v.fail_mode_tamper if v.fail_mode_tamper in ("open", "closed") else (policy_tamper or "closed")
    if tamper == "open":
        out.append(Check(True, "fail_mode.tamper", "open: tampering and an unexplained daemon loss let calls through",
                         f"set `fail_mode: {{tamper: closed}}` in {home / 'policy.yaml'} (or remove the key), "
                         "then `interlock policy accept`", warn=True))
    else:
        out.append(Check(True, "fail_mode.tamper", "closed"))

    out.append(_identity_check(home, health))
    out += _hook_log_tamper(home)
    return out


def _identity_check(home: Path, health: Health) -> Check:
    from . import identity

    path = home / identity.FILE
    if not path.exists():
        return Check(False, "identity", f"{path} missing (shims refuse every call with daemon_identity)",
                     "run `interlock restart`")
    if hasattr(os, "getuid"):
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            return Check(False, "identity", f"{path} mode {oct(mode)}", f"chmod 600 {path}")
    if not health.identity_file:
        return Check(False, "identity", f"{path} is not 32 lowercase hex characters", "run `interlock restart`")
    if not health.reachable:
        return Check(True, "identity", f"{path} (daemon not running: not compared)")
    if not health.verified:
        what, fix = identity_problem(health)
        return Check(False, "identity", f"{what} (daemon_identity)", fix)
    return Check(True, "identity", f"{path} matches the daemon's reply")


def _hook_log_tamper(home: Path) -> list[Check]:
    log = home / "hook.log"
    if not log.exists():
        return []
    try:
        tail = log.read_text(errors="replace", encoding="utf-8").splitlines()[-2000:]
    except OSError:
        return []
    cutoff = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    hits = [ln for ln in tail if ln[:20] >= cutoff and len(w := ln.split()) > 2 and w[1] == "tamper"]
    if not hits:
        return []
    causes = Counter(ln.split()[2] for ln in hits)
    return [Check(True, "hook.log tamper", f"{len(hits)} hook calls in the last day met a tamper cause: "
                  + ", ".join(f"{_safe(c)} {n}" for c, n in causes.most_common()) + f" (see {log})",
                  "`interlock doctor` above names the cause; then `interlock restart` or `interlock start`", warn=True,
                  lines=["".join(ch for ch in ln if ch.isprintable())[:200] for ln in hits[-5:]])]


def expected_shim(harness: str, shim: Path | None = None) -> str | None:
    """This version's shim for `harness`, in the runtime of the installed `shim` (its suffix: .sh, .py, .mjs)."""
    from .cli import CLAUDE_SHIM_SRC, HOOK_SHIMS, PY_SHIM_SRC

    suffix = shim.suffix if shim is not None else ".sh"
    if suffix == ".py" and harness != "opencode":
        return PY_SHIM_SRC.read_text(encoding="utf-8").replace("__HARNESS__", harness)
    if harness in ("claude-code", "codex", "cursor", "gemini-cli", "copilot-cli", "windsurf", "antigravity"):
        return CLAUDE_SHIM_SRC.read_text(encoding="utf-8").replace("__HARNESS__", harness)
    if harness == "kiro":
        return HOOK_SHIMS["node" if suffix == ".mjs" else "sh"].read_text(encoding="utf-8")
    if harness == "opencode":
        from . import __version__
        from .cli import OPENCODE_PLUGIN_SRC

        return OPENCODE_PLUGIN_SRC.read_text(encoding="utf-8").replace("__VERSION__", __version__)
    return None


def hook_integrity(home: Path) -> list[dict[str, str]]:
    """For each hook `interlock init` installed: {harness, file, problem, detail}, where problem is "" (intact),
    "hook_removed" (the agent's hook file no longer runs Interlock), "shim_missing", or "shim_modified"."""
    from .onboard import Manifest, mentions

    man = Manifest.load(home)
    out = []
    for hk in (man.hooks if man else []):
        f, shim = Path(hk["file"]), Path(hk["marker"])
        row = {"harness": hk["harness"], "file": str(f), "shim": str(shim), "problem": "", "detail": str(f)}
        try:
            text = f.read_text(encoding="utf-8", errors="replace") if f.exists() else ""
        except OSError:
            text = ""
        if not mentions(text, hk["marker"]):
            row.update(problem="hook_removed", detail=f"Interlock hook missing from {f} (removed or edited)")
        elif state := shim_state(shim, hk["harness"]):
            row.update(problem=state, detail=SHIM_DETAIL[state].format(shim=shim))
        out.append(row)
    return out


SHIM_DETAIL = {"shim_missing": "shim {shim} missing", "shim_outdated": "shim {shim} is from an earlier Interlock version",
               "shim_modified": "shim {shim} differs from the packaged version beyond its version line (tampered)"}


def shim_state(shim: Path, harness: str) -> str:
    """"" when the shim is this version's, else shim_missing / shim_outdated (only the version line differs) /
    shim_modified."""
    if not shim.exists():
        return "shim_missing"
    want = expected_shim(harness, shim)
    have = shim.read_text(encoding="utf-8", errors="replace")
    if want is None or have == want:
        return ""
    return "shim_outdated" if _VERSION_LINE.sub("", have) == _VERSION_LINE.sub("", want) else "shim_modified"


_VERSION_LINE = re.compile(r'^(?:const )?VERSION\s*=\s*"[^"]*";?$', re.MULTILINE)


def refresh_outdated_shims(home: Path) -> list[str]:
    """Rewrite shims that differ from this version's only in their version line (left by an upgrade). Returns them."""
    done = []
    for h in hook_integrity(home):
        if h["problem"] == "shim_outdated":
            from .onboard import Manifest

            man = Manifest.load(home)
            for hk in (man.hooks if man else []):
                if hk["harness"] == h["harness"] and (want := expected_shim(h["harness"], Path(hk["marker"]))) is not None:
                    Path(hk["marker"]).write_text(want, encoding="utf-8")
                    done.append(hk["marker"])
    return done


def _has_interlock_hook(f: Path, home: Path) -> str | None:
    """The shim path an existing hook file points at, if it is one of ours (covers installs made before the manifest)."""
    if not f.exists():
        return None
    text = f.read_text(encoding="utf-8", errors="replace")
    for name in ("claude-code", "codex", "cursor", "gemini-cli", "copilot-cli", "windsurf", "antigravity", "kiro"):
        shim_dir = str(home / "adapters" / name)
        if shim_dir in text:
            for shim in (home / "adapters" / name).glob("interlock-hook.*"):
                if str(shim) in text:
                    return str(shim)
    return None


def latest_release(timeout: float = 2.0) -> str | None:
    """The newest interlockd on PyPI, or None (offline, slow, or INTERLOCK_NO_UPDATE_CHECK set)."""
    if os.environ.get("INTERLOCK_NO_UPDATE_CHECK"):
        return None
    try:
        with urllib.request.urlopen("https://pypi.org/pypi/interlockd/json", timeout=timeout) as r:
            return json.loads(r.read())["info"]["version"]
    except Exception:  # noqa: BLE001
        return None


def _newer(a: str, b: str) -> bool:
    import re

    def key(v: str) -> tuple:
        nums = [int(x) for x in re.findall(r"\d+", v.split("+")[0])[:3]]
        pre = bool(re.search(r"[a-z]", v.split("+")[0]))
        return (*nums, 0 if pre else 1)
    try:
        return key(a) > key(b)
    except ValueError:
        return False


def run_doctor(home: Path, listen: str, workspace_root: str | None = None) -> list[Check]:
    from .onboard import detect
    from .policy import load_policy

    out: list[Check] = []
    token = home / "token"
    if not token.exists():
        out.append(Check(False, "token", f"{token} missing", "run `interlock init`"))
    elif not hasattr(os, "getuid"):        # Windows: no POSIX modes; the user profile's ACL is what protects it
        out.append(Check(True, "token", f"{token} (Windows: protected by your user profile's permissions, not checked)",
                         warn=True))
    else:
        mode = stat.S_IMODE(token.stat().st_mode)
        out.append(Check(mode & 0o077 == 0, "token", f"{token} mode {oct(mode)}", f"chmod 600 {token}"))
        if token.stat().st_uid != os.getuid():
            out.append(Check(False, "token owner", "token is owned by another user", f"chown $USER {token}"))

    health = fetch_health(home, listen)
    h = health.body                      # trusted only when the identity header verified
    if not health.reachable:
        out.append(Check(False, "daemon", f"not answering on http://{listen}", "run `interlock start`; logs in ~/.interlock/interlockd.log"))
    elif h is None:
        what, fix = identity_problem(health)
        out.append(Check(False, "daemon", f"{what} (daemon_identity)", fix))
    else:
        out.append(Check(True, "daemon", f"running {h.get('version')} on http://{listen}, mode {h.get('mode')}"))
        if h.get("version") != __version__:
            out.append(Check(False, "version", f"daemon {h.get('version')} vs CLI {__version__}", "run `interlock restart`"))

    policy_tamper: str | None = None
    try:
        pol = load_policy(workspace_root, home=home)      # the same layers the daemon loads
        policy_tamper = pol.fail_mode.get("tamper")
        live = (h or {}).get("mode") or pol.mode
        out.append(Check(True, "policy", f"valid: {pol.source_paths or ['built-in defaults']}, mode {pol.mode}"))
        if h and h.get("mode") != pol.mode:
            out.append(Check(True, "mode", f"daemon runs {h.get('mode')} but the policy on disk says {pol.mode}",
                             "run `interlock restart` to apply the policy", warn=True))
        from .policy_lint import lint

        issues = lint(pol)
        errs = [i for i in issues if i.level == "error"]
        if errs:
            out.append(Check(False, "policy lint", f"{errs[0].where}: {errs[0].message}" + (f" (+{len(errs) - 1} more)" if len(errs) > 1 else ""),
                             "interlock policy lint"))
        if live == "shadow":
            out.append(Check(True, "mode", "shadow: decisions are recorded, nothing is blocked", "`interlock enforce` when ready", warn=True))
    except Exception as e:  # noqa: BLE001
        out.append(Check(False, "policy", f"invalid: {str(e)[:160]}", f"fix {home / 'policy.yaml'}"))

    out += protection_checks(home, health, policy_tamper)

    hooked = set()
    for h in hook_integrity(home):
        hooked.add(h["harness"])
        fix = (f"run `interlock init --yes --harness {h['harness']}`" if h["problem"] == "hook_removed"
               else "run `interlock init --yes` to reinstall it")
        out.append(Check(h["problem"] in ("", "shim_outdated"), f"hooks {h['harness']}", h["detail"], "" if not h["problem"] else fix,
                         warn=h["problem"] == "shim_outdated"))   # the daemon refreshes those itself
    for d in detect():
        if not (d.present and d.target) or d.name in hooked:
            continue
        shim = _has_interlock_hook(d.target, home)
        if shim:
            hooked.add(d.name)
            state = shim_state(Path(shim), d.name)
            out.append(Check(state in ("", "shim_outdated"), f"hooks {d.name}",
                             f"{d.target} (installed with `interlock install`)" if not state else SHIM_DETAIL[state].format(shim=shim),
                             "" if not state else f"run `interlock init --yes --harness {d.name}` to reinstall it",
                             warn=state == "shim_outdated"))
        else:
            out.append(Check(True, f"hooks {d.name}", f"{d.name} is installed but not protected",
                             f"run `interlock init --yes --harness {d.name}`", warn=True))
    if not hooked:
        out.append(Check(False, "hooks", "no Interlock hooks found in any harness", "run `interlock init`"))

    latest = latest_release()
    if latest and _newer(latest, __version__):
        out.append(Check(True, "version", f"interlockd {latest} is available (you have {__version__})",
                         "pipx upgrade interlockd   (or: uv tool upgrade interlockd)", warn=True))
    from .control import PauseState

    ps = PauseState(home).current()
    if ps is not None:
        out.append(Check(True, "paused", f"{', '.join(ps.get('agents') or []) or 'all agents'} paused"
                         + (f" until {ps['until']}" if ps.get("until") else "") + (f" ({ps['reason']})" if ps.get("reason") else ""),
                         "interlock resume", warn=True))
    sd = home / "spool"
    if sd.exists():
        from .store.spool import Spool

        r = Spool(sd, fsync=False).verify()
        out.append(Check(r["ok"], "audit log", f"intact: {r['records']} chained records" + (f" (+{r['legacy']} legacy)" if r["legacy"] else "")
                         if r["ok"] else f"BROKEN at {r['break']['segment']} line {r['break']['line']}: {r['break']['reason']}",
                         "" if r["ok"] else "investigate: the local audit log was modified outside Interlock"))
    try:
        from . import gateway

        rows = [c for c in gateway.status() if c.action in ("wrapped", "unwrapped")]   # coverable stdio servers
        bare = [f"{c.agent}/{c.server}" for c in rows if c.action == "unwrapped"]
        if rows:
            out.append(Check(True, "mcp gateway", (f"{len(rows) - len(bare)} of {len(rows)} stdio MCP servers go through the gateway"
                                                  + (f"; not: {', '.join(bare[:5])}" if bare else "")),
                             "interlock gateway wrap" if bare else "", warn=bool(bare)))
    except Exception as e:  # noqa: BLE001  a config we can't parse must not break doctor
        out.append(Check(True, "mcp gateway", f"could not read MCP configs ({type(e).__name__})", warn=True))

    log = home / "hook.log"
    if log.exists():
        recent = [ln for ln in log.read_text(errors="replace", encoding="utf-8").splitlines()[-200:] if "unjudged" in ln or "inert" in ln]
        cutoff = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        last_day = [ln for ln in recent if ln[:20] >= cutoff]
        if last_day:
            out.append(Check(True, "fail-open", f"{len(last_day)} hook calls in the last day could not reach the daemon "
                             f"(see {log})", "keep the daemon running: `interlock start`", warn=True))
    return out


def format_doctor(checks: list[Check]) -> tuple[str, int]:
    lines, failed = [], 0
    for c in checks:
        mark = "!" if c.warn else ("✓" if c.ok else "✗")
        failed += (not c.ok) and not c.warn
        lines.append(f"  {mark} {c.name:<18} {c.detail}")
        lines += [f"    {'':<18} {ln}" for ln in c.lines]
        if (not c.ok or c.warn) and c.fix:
            lines.append(f"    {'':<18} → {c.fix}")
    lines.append("")
    lines.append("All checks passed." if failed == 0 else f"{failed} problem{'s' if failed > 1 else ''} found.")
    return "\n".join(lines), (1 if failed else 0)
