"""`interlock mcp`: Interlock as an MCP server (stdio, JSON-RPC 2.0, newline-delimited), for use inside an agent.

Advisory and read-only by design. Enforcement lives in the hooks, which the agent cannot skip; this server only
answers questions: what would the gate decide for this action, what was stopped and why, are my MCP servers risky,
is protection on. It can make an agent more careful, never less: no tool approves an action, changes the mode, or
edits policy (`suggest_rule_override` returns a snippet for a human to apply).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .config import Settings

PROTOCOL_VERSION = "2025-06-18"

TOOLS: list[dict[str, Any]] = [
    {"name": "check_action",
     "description": ("Ask Interlock what its gate would decide for an action BEFORE you take it: a shell command, or "
                     "any tool with arguments. Returns allow / ask / block with the rules that fired. Advisory: the "
                     "real gate still runs on the actual call."),
     "inputSchema": {"type": "object", "properties": {
         "command": {"type": "string", "description": "A shell command to check"},
         "tool": {"type": "string", "description": "Tool name, e.g. Bash, Write, WebFetch (default: Bash when command is set)"},
         "arguments": {"type": "object", "description": "Tool arguments, e.g. {\"file_path\": \"...\"}"},
         "cwd": {"type": "string", "description": "Working directory (default: the server's cwd)"}}}},
    {"name": "explain_decision",
     "description": "Explain an Interlock decision: why a call was blocked, asked, warned on, or withheld. Pass an event_id, or omit it for the most recent stop.",
     "inputSchema": {"type": "object", "properties": {"event_id": {"type": "string"}}}},
    {"name": "recent_decisions",
     "description": "List recent Interlock decisions (newest first). Set only_stops to see just blocks, asks, warnings, and withholds.",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 10, "maximum": 50},
                                                      "only_stops": {"type": "boolean", "default": True}}}},
    {"name": "scan_mcp_servers",
     "description": "Audit the MCP servers and agent settings on this machine (static; nothing is run or contacted; secrets are never shown).",
     "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}}}},
    {"name": "interlock_status",
     "description": "Is Interlock protecting this machine? Daemon, mode, policy, hooks per agent, shim integrity.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "suggest_rule_override",
     "description": ("Draft the policy snippet that would change how one rule behaves (e.g. a false positive). Returns "
                     "YAML for the user to review and add themselves; it does not change any policy."),
     "inputSchema": {"type": "object", "required": ["rule_id", "action"], "properties": {
         "rule_id": {"type": "string"}, "action": {"type": "string", "enum": ["block", "ask", "flag", "allow"]},
         "reason": {"type": "string"}}}},
]


class InterlockMCP:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings.load()

    # ---- tools
    def check_action(self, command: str | None = None, tool: str | None = None, arguments: dict | None = None,
                     cwd: str | None = None) -> dict:
        from .models import AdapterInfo, Context, Identity, InterlockEvent, ToolCall
        from .pipeline import Daemon
        from .policy import load_policy
        from .store.memory import MemoryRepository
        from .store.spool import Spool

        if not command and not tool:
            return {"error": "pass a command, or a tool with arguments"}
        args = dict(arguments or {})
        if command:
            args.setdefault("command", command)
        name = tool or "Bash"
        cwd = cwd or str(Path.cwd())
        pol = load_policy(cwd, home=self.settings.home)
        pol.mode = "enforce"                      # answer "what would enforce do", whatever the live mode is
        if not pol.trust.workspace_roots:
            pol.trust.workspace_roots = [cwd]
        with tempfile.TemporaryDirectory() as td:   # nothing from a what-if lands in the real audit log
            d = Daemon(self.settings, spool=Spool(Path(td)), repo=MemoryRepository(), policy=pol)
            v = d.decide(InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="interlock-mcp", version=__version__),
                                        identity=Identity(agent_type="interlock-mcp"), tool_call=ToolCall(name=name, arguments=args),
                                        context=Context(cwd=cwd)))
        return {"decision": v.disposition, "reason": v.reason,
                "rules": [{"rule": f.rule, "category": f.category, "severity": f.severity, "subject": f.subject}
                          for f in v.findings if f.rule],
                "note": ("Advisory. The gate decides on the real call. If this is blocked and the user truly needs it, "
                         "ask the user; do not rephrase or split the action to get around the rule.") if v.disposition != "allow" else ""}

    def _records(self, limit: int = 500) -> list[dict]:
        from .store.spool import Spool

        sd = self.settings.spool_dir
        recs = Spool(sd, fsync=False).iter_records(limit=limit) if sd.exists() else []
        return [r for r in recs if not str(r.get("session_id") or "").startswith("interlock-selftest")]

    def explain_decision(self, event_id: str | None = None) -> dict:
        from .det.describe import why

        recs = self._records()
        rec = next((r for r in recs if r.get("event_id") == event_id), None) if event_id else \
            next((r for r in recs if r.get("disposition") in ("block", "ask", "warn", "withhold")), None)
        if not rec:
            return {"error": "no such decision" if event_id else "no recent blocks, asks, warnings, or withholds"}
        return {"event_id": rec.get("event_id"), "at": rec.get("received_at"), "agent": rec.get("agent_type"),
                "tool": rec.get("tool_name"), "kind": rec.get("kind"), "decision": rec.get("disposition"),
                "mode": rec.get("mode"), "reason": rec.get("reason"),
                "rules": [{"rule": f.get("rule"), "category": f.get("category"), "severity": f.get("severity"),
                           "detector": f.get("detector"), "score": f.get("score"), "why": why(f.get("rule"))}
                          for f in rec.get("findings") or []],
                "what_to_do": ("Pursue the user's goal another legitimate way, or ask the user. If this is a false "
                               "positive, the user can override the rule (see suggest_rule_override).")}

    def recent_decisions(self, limit: int = 10, only_stops: bool = True) -> dict:
        limit = max(1, min(int(limit or 10), 50))
        out = []
        for r in self._records():
            if only_stops and r.get("disposition") not in ("block", "ask", "warn", "withhold"):
                continue
            a = r.get("arguments") or {}
            out.append({"event_id": r.get("event_id"), "at": r.get("received_at"), "agent": r.get("agent_type"),
                        "tool": r.get("tool_name"), "decision": r.get("disposition"), "mode": r.get("mode"),
                        "target": str(a.get("command") or a.get("file_path") or a.get("path") or a.get("url") or "")[:120],
                        "reason": (r.get("reason") or "")[:160]})
            if len(out) >= limit:
                break
        return {"decisions": out}

    def scan_mcp_servers(self, project: str | None = None) -> dict:
        from .scan import run_scan

        r = run_scan(Path.home(), self.settings.home, Path(project or Path.cwd()).expanduser().resolve())
        j = r.to_json()
        return {"servers": [{k: s[k] for k in ("agent", "name", "transport", "command", "url", "disabled")} for s in j["servers"]],
                "findings": [f for f in j["findings"] if f["severity"] != "info"]}

    def interlock_status(self) -> dict:
        from .insights import run_doctor

        checks = run_doctor(self.settings.home, self.settings.listen,
                            self.settings.workspace_roots[0] if self.settings.workspace_roots else None)
        return {"ok": all(c.ok or c.warn for c in checks),
                "checks": [{"check": c.name, "ok": c.ok, "warning": c.warn, "detail": c.detail, "fix": c.fix} for c in checks]}

    def suggest_rule_override(self, rule_id: str, action: str, reason: str | None = None) -> dict:
        from .det import (
            RULES,
            packs,  # noqa: F401  registers the rules
        )

        if rule_id not in RULES:
            return {"error": f"unknown rule {rule_id!r}", "hint": "rule ids appear in check_action and explain_decision results"}
        snippet = f"packs:\n  overrides:\n    {rule_id}: {{ action: {action} }}" + (f"   # {reason}" if reason else "")
        return {"apply_to": str(self.settings.home / "policy.yaml") + " (user) or <repo>/.interlock/policy.yaml (workspace)",
                "yaml": snippet, "note": "Interlock does not apply this. The user reviews it, adds it, and runs `interlock restart`."}

    # ---- JSON-RPC
    def call(self, name: str, args: dict) -> dict:
        fn = {t["name"]: getattr(self, t["name"]) for t in TOOLS}.get(name)
        if fn is None:
            raise KeyError(name)
        return fn(**{k: v for k, v in (args or {}).items() if v is not None})

    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:                        # notification (e.g. notifications/initialized)
            return None
        try:
            if method == "initialize":
                result = {"protocolVersion": (msg.get("params") or {}).get("protocolVersion") or PROTOCOL_VERSION,
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "interlock", "version": __version__},
                          "instructions": ("Interlock guards this machine's agent tool calls. Use check_action before "
                                           "risky shell, git, network, or file actions; use explain_decision when "
                                           "something was blocked. Never try to get around a block.")}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                p = msg.get("params") or {}
                try:
                    out = self.call(p.get("name", ""), p.get("arguments") or {})
                    result = {"content": [{"type": "text", "text": json.dumps(out, indent=2, default=str)}],
                              "structuredContent": out, "isError": "error" in out}
                except KeyError:
                    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {p.get('name')!r}"}}
                except TypeError as e:
                    result = {"content": [{"type": "text", "text": f"bad arguments: {e}"}], "isError": True}
            else:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
        except Exception as e:  # noqa: BLE001  a tool failure must not kill the server
            result = {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def serve(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> int:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n")
                stdout.flush()
                continue
            for m in (msg if isinstance(msg, list) else [msg]):
                reply = self.handle(m) if isinstance(m, dict) else None
                if reply is not None:
                    stdout.write(json.dumps(reply, default=str) + "\n")
                    stdout.flush()
        return 0
