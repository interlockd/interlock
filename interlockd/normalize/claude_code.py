"""Claude Code (and Codex, which uses the same event schema) hook payload -> InterlockEvent.

Documented PreToolUse fields: session_id, prompt_id, transcript_path, cwd, permission_mode, tool_name, tool_input,
tool_use_id, mcp_server {name, source}. PostToolUse adds tool_response (shape depends on the tool; Bash carries
stdout/stderr and may carry bashEditDiff.changedFiles). Written to the published contract; the first real capture
replaces this docstring with measured facts, as adapters/kiro/PAYLOADS.md did for Kiro.
"""

from __future__ import annotations

import getpass
import json
import socket
from typing import Any

from ..models import AdapterInfo, Capabilities, Context, Identity, InterlockEvent, ToolCall, ToolResult
from .kiro import workspace_name

CLAUDE_CAPABILITIES = Capabilities(ask=True, rewrite=True, withhold=True)
CODEX_CAPABILITIES = Capabilities(ask=True, rewrite=True, withhold=True)   # via decision "block" (measured)


def _response_text(resp: Any) -> tuple[str, dict[str, Any]]:
    """Flatten a tool_response into text plus structured evidence."""
    evidence: dict[str, Any] = {}
    if resp is None:
        return "", evidence
    if isinstance(resp, str):
        return resp, evidence
    if isinstance(resp, dict):
        for k in ("exit_code", "exitCode", "returncode", "interrupted", "duration_ms"):
            if k in resp:
                evidence[k] = resp[k]
        diff = resp.get("bashEditDiff")
        if isinstance(diff, dict):
            evidence["changed_files"] = diff.get("changedFiles") or []
            for k in ("moreFiles", "unavailable", "skipped", "shared"):
                if k in diff:
                    evidence[f"changed_files_{k}"] = diff[k]
        parts = []
        for k in ("stdout", "stderr", "output", "content", "text", "result", "file", "message"):
            v = resp.get(k)
            if isinstance(v, str) and v:
                parts.append(v)
            elif isinstance(v, dict) and isinstance(v.get("content"), str):
                parts.append(v["content"])
        if parts:
            return "\n".join(parts), evidence
        return json.dumps(resp, ensure_ascii=False)[:200_000], evidence
    if isinstance(resp, list):
        texts = [b.get("text", "") if isinstance(b, dict) else str(b) for b in resp]
        return "\n".join(t for t in texts if t), evidence
    return str(resp), evidence


def normalize_claude_code(payload: dict[str, Any], *, agent_type: str = "claude-code", agent_id: str = "",
                          adapter_version: str = "0") -> InterlockEvent:
    hook = str(payload.get("hook_event_name") or "")
    kind = "post_action" if hook.lower() in ("posttooluse", "posttoolusefailure") else "pre_action"
    cwd = payload.get("cwd")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input} if tool_input is not None else {}
    result = None
    if kind == "post_action":
        text, evidence = _response_text(payload.get("tool_response"))
        if hook.lower() == "posttoolusefailure":
            evidence["failed"] = True
            if payload.get("error"):
                text = text or str(payload.get("error"))
        result = ToolResult(content=text, evidence=evidence)
    mcp = payload.get("mcp_server") if isinstance(payload.get("mcp_server"), dict) else None
    caps = CLAUDE_CAPABILITIES if agent_type in ("claude-code", "claude-agent-sdk") else CODEX_CAPABILITIES
    return InterlockEvent(
        kind=kind,
        adapter=AdapterInfo(name=agent_type, version=adapter_version),
        identity=Identity(
            agent_id=agent_id or f"{agent_type}-{socket.gethostname().split('.')[0]}",
            agent_type=agent_type,
            agent_workspace=workspace_name(cwd),
            agent_user=getpass.getuser(),
        ),
        session_hint=payload.get("session_id"),
        tool_call=ToolCall(id=payload.get("tool_use_id"), name=str(payload.get("tool_name") or ""), arguments=tool_input),
        context=Context(cwd=cwd, user_messages=None, mcp_server=mcp, permission_mode=payload.get("permission_mode"),
                        transcript_path=payload.get("transcript_path")),
        result=result,
        capabilities=caps,
    )
