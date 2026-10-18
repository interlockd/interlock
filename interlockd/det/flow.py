"""Toxic-flow detection: the "lethal trifecta" across one session.

An agent that (1) has read private data, (2) has taken in untrusted content, and (3) now calls something that can send
data out, is one injected instruction away from exfiltration. Each call alone looks fine, so per-call rules miss it.
The session ledger keeps the first two legs with evidence; the third is checked on every pre-action call.

  private    sensitive-path reads, secrets seen in a tool result, MCP tools matching `flow.private_sources`
  untrusted  web / network tool results, MCP results matching `flow.untrusted_sources`, any result the injection probe
             flagged
  sink       network egress (shell or web tool), git push, MCP tools matching `flow.sinks`
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any

from ..models import Finding, InterlockEvent
from ..policy import Policy
from ..tiers import NETWORK_TOOLS
from . import DetResult, rule
from .mcp import split_mcp_name

R_FLOW_TRIFECTA = rule("flow.lethal_trifecta", "security.data_exfiltration", "high", "ask")
R_FLOW_MEMORY = rule("flow.memory_poisoning", "security.memory_poisoning", "high", "ask")
PRIVATE_RULES = {"secrets.read_sensitive_path", "secrets.dump_environment", "secrets.literal_in_result"}


def _mcp_target(event: InterlockEvent) -> str | None:
    st = split_mcp_name(event)
    return f"{st[0]}/{st[1]}" if st else None


def _matches(target: str | None, patterns: list[str]) -> bool:
    return bool(target) and any(fnmatchcase(target, p) for p in patterns)


def _legs(session: dict[str, Any]) -> dict[str, list[str]]:
    return session.setdefault("flow", {"private": [], "untrusted": []})


def _note(legs: dict, leg: str, evidence: str) -> None:
    if evidence not in legs[leg]:
        legs[leg] = (legs[leg] + [evidence])[-5:]


def observe(event: InterlockEvent, session: dict[str, Any], policy: Policy, findings: list[Finding]) -> None:
    """Update the session's private / untrusted legs from a decided event (pre or post)."""
    if not policy.flow.enabled:
        return
    legs = _legs(session)
    target = _mcp_target(event)
    name = event.tool_call.name
    for f in findings:
        if f.rule in PRIVATE_RULES:
            _note(legs, "private", f"{f.rule}: {(f.subject or '')[:80]}")
    if event.kind == "post_action":
        if _matches(target, policy.flow.private_sources):
            _note(legs, "private", f"read from {target}")
        if name in NETWORK_TOOLS:
            _note(legs, "untrusted", f"{name} result")
        if _matches(target, policy.flow.untrusted_sources):
            _note(legs, "untrusted", f"result from {target}")
        if any(f.category == "security.prompt_injection" for f in findings):
            _note(legs, "untrusted", f"{name} result flagged as injected")


def is_sink(event: InterlockEvent, res: DetResult, policy: Policy) -> str | None:
    if res.normalized.get("egress_hosts"):
        return "network egress to " + ", ".join(res.normalized["egress_hosts"][:3])
    if event.tool_call.name in NETWORK_TOOLS:
        return f"{event.tool_call.name} request"
    cmds = res.normalized.get("commands") or []
    if "git" in cmds and "push" in str(event.tool_call.arguments.get("command", "")):
        return "git push"
    target = _mcp_target(event)
    if _matches(target, policy.flow.sinks):
        return f"MCP {target}"
    return None


def check(event: InterlockEvent, res: DetResult, session: dict[str, Any], policy: Policy) -> None:
    """Pre-action: fire when this call is a sink and both other legs are already present in the session."""
    if not policy.flow.enabled or event.kind != "pre_action":
        return
    legs = _legs(session)
    if legs["untrusted"]:
        from .memory import is_memory_tool

        target = _mcp_target(event)
        mem = res.normalized.get("memory_write") or (f"MCP {target}" if is_memory_tool(target) else None)
        if mem:
            res.add(policy, R_FLOW_MEMORY, path="session",
                    subject=f"this session took in untrusted content ({legs['untrusted'][-1]}); now writing persistent agent memory: {mem}")
    if not (legs["private"] and legs["untrusted"]):
        return
    sink = is_sink(event, res, policy)
    if not sink:
        return
    subject = (f"this session read private data ({legs['private'][-1]}) and took in untrusted content "
               f"({legs['untrusted'][-1]}); now: {sink}")
    if policy.rule_action(R_FLOW_TRIFECTA, policy.flow.action) is not None:
        before = len(res.findings)
        res.add(policy, R_FLOW_TRIFECTA, path="session", subject=subject)
        if len(res.findings) > before and R_FLOW_TRIFECTA not in policy.packs.overrides:
            res.actions[R_FLOW_TRIFECTA] = policy.flow.action      # flow.action unless an explicit rule override
