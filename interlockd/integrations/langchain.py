"""Interlock for LangChain and LangGraph: wrap tools so every call is gated and every result checked.

    from interlockd.integrations.langchain import guard_tools
    tools = guard_tools([search, shell, ...])
    agent = create_react_agent(model, tools)          # or ToolNode(tools), AgentExecutor(tools=tools)

A refused call returns Interlock's notice as the tool's output (the tool never runs), which the model reads like any
tool error; a withheld result is replaced by the notice. Built against langchain-core 1.6.
"""

from __future__ import annotations

from typing import Any

from .client import InterlockClient


def guard_tools(tools: list[Any], client: InterlockClient | None = None, *, session: str | None = None) -> list[Any]:
    from langchain_core.tools import BaseTool

    client = client or InterlockClient(agent_type="langchain")

    class GuardedTool(BaseTool):
        inner: Any = None

        def _decide_pre(self, args: dict) -> str | None:
            v = client.decide("pre_action", self.name, args, session=session)
            if v is None:
                return InterlockClient.UNREACHABLE if client.fails_closed() else None
            return (v.get("notice") or f"[interlock] refused: {v.get('reason')}") if InterlockClient.stops(v) else None

        def _decide_post(self, args: dict, out: Any) -> Any:
            text = out if isinstance(out, str) else str(getattr(out, "content", out))
            v = client.decide("post_action", self.name, args, content=text, session=session)
            return (v.get("notice") or "[interlock] tool result withheld") if InterlockClient.withholds(v) else out

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            kwargs.pop("run_manager", None)
            refusal = self._decide_pre(kwargs)
            if refusal:
                return refusal
            return self._decide_post(kwargs, self.inner.invoke(kwargs if kwargs else (args[0] if args else {})))

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            kwargs.pop("run_manager", None)
            refusal = self._decide_pre(kwargs)
            if refusal:
                return refusal
            return self._decide_post(kwargs, await self.inner.ainvoke(kwargs if kwargs else (args[0] if args else {})))

    out = []
    for t in tools:
        if not isinstance(t, BaseTool):
            from langchain_core.tools import tool as as_tool

            t = as_tool(t)
        out.append(GuardedTool(name=t.name, description=t.description, args_schema=t.args_schema, inner=t,
                               return_direct=getattr(t, "return_direct", False)))
    return out
