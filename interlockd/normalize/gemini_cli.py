"""Gemini CLI hook payload -> InterlockEvent (https://geminicli.com/docs/hooks/reference/, read 2026-10-17).

`BeforeTool` / `AfterTool` cover every tool, including shell (`run_shell_command`) and MCP (`mcp_<server>_<tool>`).
AfterTool carries `tool_response {llmContent, returnDisplay, error}`. Built from the documentation; not yet captured
from a running Gemini CLI (see adapters/gemini-cli/PAYLOADS.md).
"""

from __future__ import annotations

import getpass
import socket
from typing import Any

from ..models import AdapterInfo, Capabilities, Context, Identity, InterlockEvent, ToolCall, ToolResult
from .claude_code import _response_text
from .kiro import workspace_name


def _gemini_text(resp: Any) -> tuple[str, dict[str, Any]]:
    if isinstance(resp, dict) and ("llmContent" in resp or "returnDisplay" in resp):
        text, evidence = _response_text(resp.get("llmContent"))
        if not text:
            text, _ = _response_text(resp.get("returnDisplay"))
        if resp.get("error"):
            evidence["failed"] = True
            text = text or str(resp["error"])
        return text, evidence
    return _response_text(resp)


def normalize_gemini_cli(payload: dict[str, Any], *, agent_id: str = "", adapter_version: str = "0") -> InterlockEvent:
    hook = str(payload.get("hook_event_name") or "")
    kind = "post_action" if hook.lower() == "aftertool" else "pre_action"
    cwd = payload.get("cwd")
    args = payload.get("tool_input")
    if not isinstance(args, dict):
        args = {"value": args} if args is not None else {}
    result = None
    if kind == "post_action":
        text, evidence = _gemini_text(payload.get("tool_response"))
        result = ToolResult(content=text, evidence=evidence)
    name = str(payload.get("tool_name") or "")
    mcp = payload.get("mcp_context") if isinstance(payload.get("mcp_context"), dict) else None
    return InterlockEvent(
        kind=kind,
        adapter=AdapterInfo(name="gemini-cli", version=adapter_version),
        identity=Identity(agent_id=agent_id or f"gemini-cli-{socket.gethostname().split('.')[0]}", agent_type="gemini-cli",
                          agent_workspace=workspace_name(cwd), agent_user=getpass.getuser()),
        session_hint=payload.get("session_id"),
        tool_call=ToolCall(name=name, arguments=args),
        context=Context(cwd=cwd, mcp_server=mcp, transcript_path=payload.get("transcript_path")),
        result=result,
        # no documented ask; AfterTool deny replaces the result the model sees
        capabilities=Capabilities(ask=False, rewrite=True, withhold=True),
    )
