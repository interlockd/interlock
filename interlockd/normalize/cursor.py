"""Cursor agent hook payload -> InterlockEvent (https://cursor.com/docs/agent/hooks, read 2026-10-17).

Interlock registers `preToolUse` and `postToolUse` (one generic pair for every tool type: Shell, Read, Write, Grep,
Delete, Task, MCP:<tool>). The shell-specific `beforeShellExecution` / `afterShellExecution` shapes are accepted too.
Built from the documentation; not yet captured from a running Cursor (see adapters/cursor/PAYLOADS.md).
"""

from __future__ import annotations

import getpass
import socket
from typing import Any

from ..models import AdapterInfo, Capabilities, Context, Identity, InterlockEvent, ToolCall, ToolResult
from .claude_code import _response_text
from .kiro import workspace_name

POST_EVENTS = {"posttooluse", "posttoolusefailure", "aftershellexecution", "aftermcpexecution"}


def normalize_cursor(payload: dict[str, Any], *, agent_id: str = "", adapter_version: str = "0") -> InterlockEvent:
    hook = str(payload.get("hook_event_name") or "")
    kind = "post_action" if hook.lower() in POST_EVENTS else "pre_action"
    roots = payload.get("workspace_roots") or []
    cwd = payload.get("cwd") or (roots[0] if roots else None)
    name = str(payload.get("tool_name") or "")
    args = payload.get("tool_input")
    if hook.lower() in ("beforeshellexecution", "aftershellexecution"):
        name, args = "Shell", {"command": payload.get("command", "")}
    if not isinstance(args, dict):
        args = {"value": args} if args is not None else {}
    result = None
    if kind == "post_action":
        raw = payload.get("tool_output", payload.get("output", payload.get("result_json")))
        text, evidence = _response_text(raw)
        if hook.lower() == "posttoolusefailure":
            evidence["failed"] = True
            text = text or str(payload.get("error_message") or "")
        result = ToolResult(content=text, evidence=evidence)
    is_mcp = name.startswith("MCP:") or bool(payload.get("mcp_server_name"))
    return InterlockEvent(
        kind=kind,
        adapter=AdapterInfo(name="cursor", version=adapter_version),
        identity=Identity(agent_id=agent_id or f"cursor-{socket.gethostname().split('.')[0]}", agent_type="cursor",
                          agent_workspace=workspace_name(cwd), agent_user=getpass.getuser()),
        session_hint=payload.get("conversation_id"),
        tool_call=ToolCall(id=payload.get("tool_use_id"), name=name, arguments=args),
        context=Context(cwd=cwd, mcp_server={"name": payload["mcp_server_name"]} if payload.get("mcp_server_name") else None,
                        transcript_path=payload.get("transcript_path")),
        result=result,
        # ask is "accepted by the schema but not enforced for preToolUse"; output replacement is MCP-only
        capabilities=Capabilities(ask=False, rewrite=True, withhold=is_mcp),
    )
