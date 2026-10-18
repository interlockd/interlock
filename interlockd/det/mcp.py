"""MCP server / tool policy (`mcp.tools` in policy): which servers and tools an agent may use, from any harness.

Tool names differ per harness: Claude Code / Codex and the gateway use `mcp__<server>__<tool>`, Gemini CLI
`mcp_<server>_<tool>`, Cursor `MCP:<tool>` with the server in the payload. `split_mcp_name` recovers (server, tool).
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from ..models import InterlockEvent
from ..policy import Policy
from . import DetResult, rule

R_MCP_BLOCKED = rule("mcp.tool_blocked", "security.unauthorized_tool", "high", "block")
R_MCP_ASK = rule("mcp.tool_requires_approval", "security.unauthorized_tool", "medium", "ask")


def split_mcp_name(event: InterlockEvent, known_servers: list[str] = ()) -> tuple[str, str] | None:
    name = event.tool_call.name
    server_hint = (event.context.mcp_server or {}).get("name")
    if name.startswith("mcp__"):
        parts = name[5:].split("__", 1)
        return (parts[0], parts[1]) if len(parts) == 2 else (parts[0], "")
    if name.startswith("MCP:"):
        return (server_hint or "*", name[4:])
    if name.startswith("mcp_"):
        rest = name[4:]
        for s in sorted([*known_servers, *([server_hint] if server_hint else [])], key=len, reverse=True):
            if rest.startswith(s + "_"):
                return (s, rest[len(s) + 1:])
        head, _, tail = rest.partition("_")             # ambiguous without a known server: first segment
        return (head, tail)
    if server_hint:
        return (server_hint, name)
    return None


def _specificity(pattern: str) -> tuple[int, int, int]:
    """Tool-level beats server-level, then exact beats glob, then longer beats shorter."""
    return (1 if "/" in pattern else 0, 0 if any(c in pattern for c in "*?[") else 1, len(pattern.replace("*", "")))


def resolve(policy: Policy, server: str, tool: str) -> tuple[str, str | None]:
    """(action, matching pattern). Patterns without a `/` match the whole server; a pattern that names a tool always
    outranks a server-wide one."""
    best, best_key = None, None
    for pat, action in policy.mcp.tools.items():
        target = f"{server}/{tool}" if "/" in pat else server
        matches = fnmatchcase(target, pat) or pat == server
        if matches and (best_key is None or _specificity(pat) > _specificity(best_key)):
            best, best_key = action, pat
    return (best or policy.mcp.default, best_key)


def check_mcp_policy(event: InterlockEvent, res: DetResult, policy: Policy) -> None:
    if not policy.mcp.tools and policy.mcp.default == "allow":
        return
    known = sorted({p.split("/", 1)[0] for p in policy.mcp.tools if not any(c in p.split("/", 1)[0] for c in "*?[")})
    st = split_mcp_name(event, known)
    if st is None:
        return
    server, tool = st
    action, pat = resolve(policy, server, tool)
    res.normalized["mcp"] = {"server": server, "tool": tool, "policy": pat or "default", "action": action}
    why = f"{server}/{tool} ({'mcp.tools[' + repr(pat) + ']' if pat else 'mcp.default'}: {action})"
    if action == "block":
        res.add(policy, R_MCP_BLOCKED, path="tool_call.name", subject=why)
    elif action == "ask":
        res.add(policy, R_MCP_ASK, path="tool_call.name", subject=why)
