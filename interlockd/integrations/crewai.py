"""Interlock for CrewAI: global tool-call hooks (crewai.hooks), so every agent and crew in the process is covered.

    from interlockd.integrations.crewai import install
    install()        # before building your crews; `uninstall()` removes the hooks

CrewAI blocks a call when a before_tool_call hook returns False, and then reports a generic "Tool execution blocked
by hook" to the agent. Its after_tool_call hooks run even for blocked calls (read from crewai 1.15's executor), so
Interlock's after hook swaps that generic text for Interlock's notice, and replaces injected results (an after hook's
returned string becomes the tool result). Built against crewai 1.15 and tested through its hook registry.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from .client import InterlockClient

BLOCKED_PREFIX = "Tool execution blocked by hook"
_installed: list[Any] = []


def _key(ctx: Any) -> str:
    return f"{ctx.tool_name}:{json.dumps(ctx.tool_input, sort_keys=True, default=str)}"


def make_hooks(client: InterlockClient | None = None, *, session: str | None = None):
    client = client or InterlockClient(agent_type="crewai")
    pending: dict[str, str] = {}
    lock = threading.Lock()

    def before(ctx: Any) -> bool | None:
        v = client.decide("pre_action", ctx.tool_name, dict(ctx.tool_input or {}), session=session)
        notice = None
        if v is None and client.fails_closed():
            notice = InterlockClient.UNREACHABLE
        elif InterlockClient.stops(v):
            notice = v.get("notice") or f"[interlock] refused: {v.get('reason')}"
        if notice:
            with lock:
                pending[_key(ctx)] = notice
            return False
        return None

    def after(ctx: Any) -> str | None:
        with lock:
            notice = pending.pop(_key(ctx), None)
        result = ctx.tool_result if isinstance(ctx.tool_result, str) else str(ctx.tool_result or "")
        if notice and result.startswith(BLOCKED_PREFIX):
            return notice                                   # tell the agent why, not just that it was blocked
        if not result.strip():
            return None
        v = client.decide("post_action", ctx.tool_name, dict(ctx.tool_input or {}), content=result, session=session)
        if InterlockClient.withholds(v):
            return v.get("notice") or "[interlock] tool result withheld"
        return None

    return before, after


def install(client: InterlockClient | None = None, *, session: str | None = None) -> None:
    from crewai.hooks import register_after_tool_call_hook, register_before_tool_call_hook

    if _installed:
        return
    before, after = make_hooks(client, session=session)
    register_before_tool_call_hook(before)
    register_after_tool_call_hook(after)
    _installed[:] = [before, after]


def uninstall() -> None:
    from crewai.hooks import unregister_after_tool_call_hook, unregister_before_tool_call_hook

    if _installed:
        unregister_before_tool_call_hook(_installed[0])
        unregister_after_tool_call_hook(_installed[1])
        _installed.clear()
