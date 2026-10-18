"""Interlock for Google's Agent Development Kit (ADK): tool callbacks on any LlmAgent.

    from google.adk.agents import LlmAgent
    from interlockd.integrations.google_adk import guard_agent
    agent = guard_agent(LlmAgent(name="dev", model=..., tools=[shell, search]))

ADK's before_tool_callback skips the tool when it returns a dict (that dict becomes the tool's result), and
after_tool_callback replaces the result when it returns one. ADK passes their arguments by keyword. Interlock's
callbacks are appended to any the agent already has. Built against google-adk 2.12.
"""

from __future__ import annotations

import json
from typing import Any

from .client import InterlockClient


def interlock_callbacks(client: InterlockClient | None = None, *, session: str | None = None):
    """(before_tool_callback, after_tool_callback) for an ADK agent."""
    client = client or InterlockClient(agent_type="google-adk")

    def _session(tool_context: Any) -> str | None:
        if session:
            return session
        inv = getattr(tool_context, "invocation_id", None) or getattr(getattr(tool_context, "session", None), "id", None)
        return str(inv) if inv else None

    def before_tool_callback(tool: Any, args: dict, tool_context: Any) -> dict | None:
        v = client.decide("pre_action", getattr(tool, "name", str(tool)), dict(args or {}), session=_session(tool_context))
        if v is None:
            return {"error": InterlockClient.UNREACHABLE} if client.fails_closed() else None
        if InterlockClient.stops(v):
            return {"error": v.get("notice") or f"[interlock] refused: {v.get('reason')}"}
        return None

    def after_tool_callback(tool: Any, args: dict, tool_context: Any, tool_response: Any) -> dict | None:
        text = tool_response if isinstance(tool_response, str) else json.dumps(tool_response, default=str)
        if not text.strip():
            return None
        v = client.decide("post_action", getattr(tool, "name", str(tool)), dict(args or {}), content=text,
                          session=_session(tool_context))
        if InterlockClient.withholds(v):
            return {"result": v.get("notice") or "[interlock] tool result withheld"}
        return None

    return before_tool_callback, after_tool_callback


def guard_agent(agent: Any, client: InterlockClient | None = None, *, session: str | None = None) -> Any:
    """Append Interlock's callbacks to an LlmAgent (idempotent). Returns the agent."""
    before, after = interlock_callbacks(client, session=session)

    def _merged(existing: Any, cb: Any) -> list:
        cur = existing if isinstance(existing, list) else ([existing] if existing else [])
        return cur if any(getattr(c, "__name__", "") == cb.__name__ and getattr(c, "_interlock", False) for c in cur) else [*cur, cb]

    before._interlock = after._interlock = True  # type: ignore[attr-defined]
    agent.before_tool_callback = _merged(agent.before_tool_callback, before)
    agent.after_tool_callback = _merged(agent.after_tool_callback, after)
    return agent
