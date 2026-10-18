"""Interlock for Strands Agents: a HookProvider that gates every tool call and checks every tool result.

    from strands import Agent
    from interlockd.integrations.strands import InterlockHooks
    agent = Agent(tools=[...], hooks=[InterlockHooks()])

BeforeToolCallEvent: a refusal sets `cancel_tool` to Interlock's notice (Strands returns it to the model as an error
tool result, and the tool never runs). AfterToolCallEvent: a withhold replaces `result` with the notice. Measured
against strands-agents 1.61.
"""

from __future__ import annotations

import json
from typing import Any

from .client import InterlockClient


def _text(result: Any) -> str:
    if isinstance(result, dict):
        parts = []
        for c in result.get("content") or []:
            if isinstance(c, dict):
                if isinstance(c.get("text"), str):
                    parts.append(c["text"])
                elif "json" in c:
                    parts.append(json.dumps(c["json"]))
        return "\n".join(parts)
    return "" if result is None else str(result)


class InterlockHooks:
    """Strands HookProvider (duck-typed; Strands checks `register_hooks`)."""

    def __init__(self, client: InterlockClient | None = None, *, session: str | None = None):
        self.client = client or InterlockClient(agent_type="strands")
        self.session = session

    def register_hooks(self, registry: Any, **kwargs: Any) -> None:
        from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent

        registry.add_callback(BeforeToolCallEvent, self.before_tool)
        registry.add_callback(AfterToolCallEvent, self.after_tool)

    def _session(self, event: Any) -> str | None:
        return self.session or getattr(getattr(event, "agent", None), "agent_id", None) or getattr(getattr(event, "agent", None), "name", None)

    def before_tool(self, event: Any) -> None:
        tu = event.tool_use
        v = self.client.decide("pre_action", tu.get("name", ""), tu.get("input") or {}, session=self._session(event))
        if v is None:
            if self.client.fails_closed():
                event.cancel_tool = InterlockClient.UNREACHABLE
            return
        if InterlockClient.stops(v):
            event.cancel_tool = v.get("notice") or f"[interlock] refused: {v.get('reason')}"

    def after_tool(self, event: Any) -> None:
        if getattr(event, "cancel_message", None) or not isinstance(event.result, dict):
            return
        text = _text(event.result)
        if not text.strip():
            return
        tu = event.tool_use
        v = self.client.decide("post_action", tu.get("name", ""), tu.get("input") or {}, content=text, session=self._session(event))
        if InterlockClient.withholds(v):
            event.result = {"toolUseId": event.result.get("toolUseId", tu.get("toolUseId")), "status": "success",
                            "content": [{"text": v.get("notice") or "[interlock] tool result withheld"}]}
