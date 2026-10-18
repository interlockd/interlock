"""Interlock for the OpenAI Agents SDK: native tool guardrails on every function tool.

    from agents import Agent
    from interlockd.integrations.openai_agents import guard_agent_tools
    agent = guard_agent_tools(Agent(name="dev", tools=[shell, search]))

Uses the SDK's own ToolInputGuardrail / ToolOutputGuardrail: a refused call or a withheld result becomes
`reject_content(<notice>)`, so the tool never runs (or its output is replaced) and the model reads the notice.
Built against openai-agents 0.24.
"""

from __future__ import annotations

import json
from typing import Any

from .client import InterlockClient


def interlock_guardrails(client: InterlockClient | None = None, *, session: str | None = None):
    """(input_guardrail, output_guardrail) to add to any FunctionTool."""
    from agents import ToolGuardrailFunctionOutput, tool_input_guardrail, tool_output_guardrail

    client = client or InterlockClient(agent_type="openai-agents")

    def _args(ctx: Any) -> dict:
        raw = getattr(ctx, "tool_arguments", None) or "{}"
        try:
            v = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            v = {"value": raw}
        return v if isinstance(v, dict) else {"value": v}

    @tool_input_guardrail(name="interlock")
    def interlock_input(data: Any) -> Any:
        ctx = data.context
        v = client.decide("pre_action", ctx.tool_name, _args(ctx), session=session)
        if v is None:
            return ToolGuardrailFunctionOutput.reject_content(InterlockClient.UNREACHABLE) if client.fails_closed() \
                else ToolGuardrailFunctionOutput.allow()
        if InterlockClient.stops(v):
            return ToolGuardrailFunctionOutput.reject_content(v.get("notice") or f"[interlock] refused: {v.get('reason')}",
                                                               output_info={"rules": [f.get("rule") for f in v.get("findings") or []]})
        return ToolGuardrailFunctionOutput.allow()

    @tool_output_guardrail(name="interlock")
    def interlock_output(data: Any) -> Any:
        ctx = data.context
        out = data.output
        text = out if isinstance(out, str) else json.dumps(out, default=str)
        v = client.decide("post_action", ctx.tool_name, _args(ctx), content=text, session=session)
        if InterlockClient.withholds(v):
            return ToolGuardrailFunctionOutput.reject_content(v.get("notice") or "[interlock] tool result withheld")
        return ToolGuardrailFunctionOutput.allow()

    return interlock_input, interlock_output


def guard_agent_tools(agent: Any, client: InterlockClient | None = None, *, session: str | None = None) -> Any:
    """Attach Interlock's guardrails to every FunctionTool on the agent (idempotent). Returns the agent."""
    from agents import FunctionTool

    gin, gout = interlock_guardrails(client, session=session)
    for t in agent.tools:
        if isinstance(t, FunctionTool):
            ins = list(t.tool_input_guardrails or [])
            outs = list(t.tool_output_guardrails or [])
            if not any(getattr(g, "name", None) == "interlock" for g in ins):
                t.tool_input_guardrails = [*ins, gin]
            if not any(getattr(g, "name", None) == "interlock" for g in outs):
                t.tool_output_guardrails = [*outs, gout]
    return agent
