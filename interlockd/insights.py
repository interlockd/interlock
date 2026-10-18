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
            r.hook_changes.append(f"{rec.get('received_at', '')[:16].replace('T', ' ')}  {rec.get('reason') or ''}"[:140])
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
    for line in log.read_text(errors="replace").splitlines():
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


def _health(listen: str) -> dict[str, Any] | None:
    host, _, port = listen.rpartition(":")
    try:
        with urllib.request.urlopen(f"http://{host or '127.0.0.1'}:{port}/interlock/v1/health", timeout=1.5) as r:
            return json.loads(r.read().decode())
    except Exception:  # noqa: BLE001
        return None


def expected_shim(harness: str) -> str | None:
    from .cli import CLAUDE_SHIM_SRC, HOOK_SHIMS

    if harness in ("claude-code", "codex", "cursor", "gemini-cli", "copilot-cli", "windsurf", "antigravity"):
        return CLAUDE_SHIM_SRC.read_text().replace("__HARNESS__", harness)
    if harness == "kiro":
        return HOOK_SHIMS["sh"].read_text()
    if harness == "opencode":
        from . import __version__
        from .cli import OPENCODE_PLUGIN_SRC

        return OPENCODE_PLUGIN_SRC.read_text().replace("__VERSION__", __version__)
    return None


def hook_integrity(home: Path) -> list[dict[str, str]]:
    """For each hook `interlock init` installed: {harness, file, problem, detail}, where problem is "" (intact),
    "hook_removed" (the agent's hook file no longer runs Interlock), "shim_missing", or "shim_modified"."""
    from .onboard import Manifest

    man = Manifest.load(home)
    out = []
    for hk in (man.hooks if man else []):
        f, shim = Path(hk["file"]), Path(hk["marker"])
        row = {"harness": hk["harness"], "file": str(f), "problem": "", "detail": str(f)}
        try:
            text = f.read_text(errors="replace") if f.exists() else ""
        except OSError:
            text = ""
        want = expected_shim(hk["harness"])
        if hk["marker"] not in text:
            row.update(problem="hook_removed", detail=f"Interlock hook missing from {f} (removed or edited)")
        elif not shim.exists():
            row.update(problem="shim_missing", detail=f"shim {shim} missing")
        elif want is not None and (have := shim.read_text(errors="replace")) != want:
            if _VERSION_LINE.sub("", have) == _VERSION_LINE.sub("", want):
                row.update(problem="shim_outdated", detail=f"shim {shim} is from an earlier Interlock version")
            else:
                row.update(problem="shim_modified", detail=f"shim {shim} differs from the installed version (tampered or outdated)")
        out.append(row)
    return out


_VERSION_LINE = re.compile(r'^(?:const )?VERSION\s*=\s*"[^"]*";?$', re.MULTILINE)


def refresh_outdated_shims(home: Path) -> list[str]:
    """Rewrite shims that differ from this version's only in their version line (left by an upgrade). Returns them."""
    done = []
    for h in hook_integrity(home):
        if h["problem"] == "shim_outdated":
            from .onboard import Manifest

            man = Manifest.load(home)
            for hk in (man.hooks if man else []):
                if hk["harness"] == h["harness"] and (want := expected_shim(h["harness"])) is not None:
                    Path(hk["marker"]).write_text(want)
                    done.append(hk["marker"])
    return done


def _has_interlock_hook(f: Path, home: Path) -> str | None:
    """The shim path an existing hook file points at, if it is one of ours (covers installs made before the manifest)."""
    if not f.exists():
        return None
    text = f.read_text(errors="replace")
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
    else:
        mode = stat.S_IMODE(token.stat().st_mode)
        out.append(Check(mode & 0o077 == 0, "token", f"{token} mode {oct(mode)}", f"chmod 600 {token}"))
        if token.stat().st_uid != os.getuid():
            out.append(Check(False, "token owner", "token is owned by another user", f"chown $USER {token}"))

    h = _health(listen)
    if h is None:
        out.append(Check(False, "daemon", f"not answering on http://{listen}", "run `interlock start`; logs in ~/.interlock/interlockd.log"))
    else:
        out.append(Check(True, "daemon", f"running {h.get('version')} on http://{listen}, mode {h.get('mode')}"))
        if h.get("version") != __version__:
            out.append(Check(False, "version", f"daemon {h.get('version')} vs CLI {__version__}", "run `interlock restart`"))

    try:
        pol = load_policy(workspace_root, home=home)      # the same layers the daemon loads
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

    hooked = set()
    for h in hook_integrity(home):
        hooked.add(h["harness"])
        fix = (f"run `interlock init --yes --harness {h['harness']}`" if h["problem"] == "hook_removed"
               else "run `interlock init --yes` to reinstall it")
        out.append(Check(not h["problem"], f"hooks {h['harness']}", h["detail"], "" if not h["problem"] else fix))
    for d in detect():
        if not (d.present and d.target) or d.name in hooked:
            continue
        shim = _has_interlock_hook(d.target, home)
        if shim:
            hooked.add(d.name)
            want = expected_shim(d.name)
            same = Path(shim).exists() and (want is None or Path(shim).read_text() == want)
            out.append(Check(same, f"hooks {d.name}", f"{d.target} (installed with `interlock install`)" if same else
                             f"shim {shim} differs from the packaged version (tampered or outdated)",
                             "" if same else f"run `interlock init --yes --harness {d.name}`"))
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
        recent = [ln for ln in log.read_text(errors="replace").splitlines()[-200:] if "unjudged" in ln or "inert" in ln]
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
        if (not c.ok or c.warn) and c.fix:
            lines.append(f"    {'':<18} → {c.fix}")
    lines.append("")
    lines.append("All checks passed." if failed == 0 else f"{failed} problem{'s' if failed > 1 else ''} found.")
    return "\n".join(lines), (1 if failed else 0)
