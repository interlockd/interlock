"""GitHub Copilot CLI, Windsurf (Cascade), and Antigravity CLI hook payloads -> InterlockEvent.

Built from the official docs (read 2026-10-18), not yet captured from the running tools:
  Copilot CLI   https://docs.github.com/en/copilot/reference/hooks-configuration
  Windsurf      https://docs.devin.ai/desktop/cascade/hooks
  Antigravity   https://antigravity.google/docs/hooks/
The shim passes `event` ("pre" | "post") because Copilot's camelCase payload does not name its event.
"""

from __future__ import annotations

import getpass
import json
import socket
from typing import Any

from ..models import AdapterInfo, Capabilities, Context, Identity, InterlockEvent, ToolCall, ToolResult
from .claude_code import _response_text
from .kiro import workspace_name


def _event(harness: str, kind: str, name: str, args: Any, *, session: str | None, cwd: str | None, version: str,
           agent_id: str, result: str | None = None, mcp: dict | None = None, caps: Capabilities, transcript: str | None = None):
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            args = {"value": args}
    if not isinstance(args, dict):
        args = {"value": args} if args is not None else {}
    return InterlockEvent(
        kind=kind, adapter=AdapterInfo(name=harness, version=version),
        identity=Identity(agent_id=agent_id or f"{harness}-{socket.gethostname().split('.')[0]}", agent_type=harness,
                          agent_workspace=workspace_name(cwd), agent_user=getpass.getuser()),
        session_hint=session, tool_call=ToolCall(name=str(name or ""), arguments=args),
        context=Context(cwd=cwd, mcp_server=mcp, transcript_path=transcript),
        result=ToolResult(content=result) if result is not None else None, capabilities=caps)


def normalize_copilot(payload: dict[str, Any], *, event: str = "pre", agent_id: str = "", adapter_version: str = "0") -> InterlockEvent:
    p = payload
    hook = str(p.get("hook_event_name") or "")
    kind = "post_action" if event == "post" or hook.lower().startswith("posttooluse") else "pre_action"
    name = p.get("toolName", p.get("tool_name"))
    args = p.get("toolArgs", p.get("tool_input"))
    result = None
    if kind == "post_action":
        tr = p.get("toolResult", p.get("tool_response", p.get("tool_output")))
        if isinstance(tr, dict) and "textResultForLlm" in tr:      # measured on Copilot CLI 1.0.98
            tr = tr.get("textResultForLlm")
        result, _ = _response_text(tr)
    return _event("copilot-cli", kind, name, args, session=p.get("sessionId", p.get("session_id")), cwd=p.get("cwd"),
                  version=adapter_version, agent_id=agent_id, result=result,
                  caps=Capabilities(ask=True, rewrite=True, withhold=True))     # postToolUse modifiedResult replaces


def normalize_windsurf(payload: dict[str, Any], *, event: str = "pre", agent_id: str = "", adapter_version: str = "0") -> InterlockEvent:
    p = payload
    action = str(p.get("agent_action_name") or "")
    info = p.get("tool_info") or {}
    kind = "post_action" if event == "post" or action.startswith("post_") else "pre_action"
    mcp = None
    if "run_command" in action:
        name, args = "Shell", {"command": info.get("command_line", "")}
    elif "mcp_tool_use" in action:
        server = str(info.get("mcp_server_name") or "")
        name, args = f"mcp__{server}__{info.get('mcp_tool_name', '')}", info.get("mcp_tool_arguments") or {}
        mcp = {"name": server, "source": "windsurf"}
    elif "read_code" in action:
        name, args = "Read", {"file_path": info.get("file_path") or info.get("path") or ""}
    elif "write_code" in action:
        name, args = "Write", {"file_path": info.get("file_path") or info.get("path") or "",
                               **({"content": info["content"]} if isinstance(info.get("content"), str) else {})}
    else:
        name, args = action or "unknown", info
    result = None
    if kind == "post_action":
        result, _ = _response_text(info.get("output") or info.get("result") or p.get("output"))
    return _event("windsurf", kind, name, args, session=p.get("trajectory_id"), cwd=info.get("cwd"), version=adapter_version,
                  agent_id=agent_id, result=result, mcp=mcp, caps=Capabilities(ask=False, rewrite=False, withhold=False))


def normalize_antigravity(payload: dict[str, Any], *, event: str = "pre", agent_id: str = "", adapter_version: str = "0") -> InterlockEvent:
    p = payload
    call = p.get("toolCall") or {}
    hook = str(p.get("hook_event_name") or p.get("hookEventName") or "")
    kind = "post_action" if event == "post" or hook == "PostToolUse" else "pre_action"
    name, args = call.get("name", ""), dict(call.get("args") or {})
    if name == "run_command":                      # documented: args CommandLine, Cwd
        args = {"command": args.get("CommandLine", ""), **({"cwd": args["Cwd"]} if args.get("Cwd") else {})}
        name = "Shell"
    roots = p.get("workspacePaths") or []
    result = None
    if kind == "post_action":
        result, _ = _response_text(p.get("toolResult") or p.get("result") or p.get("output"))
    return _event("antigravity", kind, name, args, session=p.get("conversationId"), cwd=args.get("cwd") or (roots[0] if roots else None),
                  version=adapter_version, agent_id=agent_id, result=result, transcript=p.get("transcriptPath"),
                  caps=Capabilities(ask=True, rewrite=True, withhold=False))     # PostToolUse returns {} (no replacement)
