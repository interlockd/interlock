"""Kiro hook payload -> InterlockEvent. Field mapping per adapters/kiro/PAYLOADS.md §8."""

from __future__ import annotations

import getpass
import os
import re
import socket
from typing import Any

from ..models import AdapterInfo, Capabilities, Context, Identity, InterlockEvent, ToolCall, ToolResult
from ..paths import find_git_root

_EXIT = re.compile(r"Exit Code:\s*(-?\d+)\s*$")

KIRO_CAPABILITIES = Capabilities(ask=False, rewrite=False, withhold=False)


def default_agent_id() -> str:
    return f"kiro-{socket.gethostname().split('.')[0]}"


def workspace_name(cwd: str | None) -> str:
    root = find_git_root(cwd) if cwd else None
    base = root or cwd or ""
    return os.path.basename(os.path.normpath(base)) if base else ""


def normalize_kiro(payload: dict[str, Any], *, agent_id: str = "", adapter_version: str = "0") -> InterlockEvent:
    hook = payload.get("hook_event_name") or ""
    kind = "post_action" if hook.lower() == "posttooluse" else "pre_action"
    cwd = payload.get("cwd")
    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input} if tool_input is not None else {}

    result = None
    if kind == "post_action":
        content = payload.get("tool_response")
        if content is None:
            content = ""
        if not isinstance(content, str):
            content = str(content)
        evidence: dict[str, Any] = {}
        m = _EXIT.search(content.strip()[-64:])
        if m:
            evidence["exit_code"] = int(m.group(1))
        result = ToolResult(content=content, evidence=evidence)

    return InterlockEvent(
        kind=kind,
        adapter=AdapterInfo(name="kiro", version=adapter_version),
        identity=Identity(
            agent_id=agent_id or default_agent_id(),
            agent_type="kiro",
            agent_workspace=workspace_name(cwd),
            agent_user=getpass.getuser(),
        ),
        session_hint=payload.get("session_id"),
        tool_call=ToolCall(id=None, name=tool_name, arguments=tool_input),
        context=Context(cwd=cwd, user_messages=None),
        result=result,
        capabilities=KIRO_CAPABILITIES,
    )
