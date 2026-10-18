"""Interlock for Semantic Kernel (Python): a function-invocation filter on the kernel.

    from semantic_kernel import Kernel
    from interlockd.integrations.semantic_kernel import guard_kernel
    kernel = guard_kernel(Kernel())

The filter wraps every native (plugin) function call, whether the model chose it through auto function calling or
your code invoked it. A refused call never runs: its result is Interlock's notice. A result that carries injected
instructions is replaced before the model reads it. Prompt functions (LLM calls) pass through unchecked. Built
against semantic-kernel 1.36.
"""

from __future__ import annotations

import json
from typing import Any

from .client import InterlockClient

_PLAIN = (str, int, float, bool, type(None), list, dict)


def interlock_filter(client: InterlockClient | None = None, *, session: str | None = None):
    """An async FUNCTION_INVOCATION filter: `kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, interlock_filter())`."""
    from semantic_kernel.functions import FunctionResult

    client = client or InterlockClient(agent_type="semantic-kernel")

    async def interlock_function_filter(context: Any, next: Any) -> None:
        meta = context.function.metadata
        if meta.is_prompt:
            await next(context)
            return
        args = {k: v if isinstance(v, _PLAIN) else str(v) for k, v in dict(context.arguments or {}).items()}
        name = context.function.name
        v = client.decide("pre_action", name, args, session=session)
        refused = (InterlockClient.UNREACHABLE if v is None and client.fails_closed() else
                   (v.get("notice") or f"[interlock] refused: {v.get('reason')}") if InterlockClient.stops(v) else None)
        if refused:
            context.result = FunctionResult(function=meta, value=refused)
            return
        await next(context)
        value = getattr(context.result, "value", None)
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        if value is None or not text.strip():
            return
        v = client.decide("post_action", name, args, content=text, session=session)
        if InterlockClient.withholds(v):
            context.result = FunctionResult(function=meta, value=v.get("notice") or "[interlock] tool result withheld")

    interlock_function_filter._interlock = True  # type: ignore[attr-defined]
    return interlock_function_filter


def guard_kernel(kernel: Any, client: InterlockClient | None = None, *, session: str | None = None) -> Any:
    """Add Interlock's filter to a Kernel (idempotent). Returns the kernel."""
    from semantic_kernel.filters import FilterTypes

    if not any(getattr(f, "_interlock", False) for _, f in kernel.function_invocation_filters):
        kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, interlock_filter(client, session=session))
    return kernel
