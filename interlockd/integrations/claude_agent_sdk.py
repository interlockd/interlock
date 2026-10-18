"""Claude Agent SDK: Interlock as in-process PreToolUse / PostToolUse hooks.

    from claude_agent_sdk import ClaudeAgentOptions, query
    from interlockd.integrations.claude_agent_sdk import guard_options

    options = guard_options(ClaudeAgentOptions(allowed_tools=["Bash", "Read"]))
    async for message in query(prompt="...", options=options): ...

The SDK hands its hooks the same payloads as Claude Code's command hooks, so each call goes to the daemon's
Claude Code hook route and the reply is the hook output Claude Code applies: a refused call is denied with the
reason, and an injected tool result is replaced (`updatedToolOutput`) before the model reads it. Your own hooks are
kept and run alongside. With the daemon unreachable, calls run unless the fail mode is closed.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Any

from .. import __version__
from .client import InterlockClient

ROUTE = "/interlock/v1/hooks/claude-agent-sdk?format=claude-code"
_MARK = "_interlock_hook"


def _post(client: InterlockClient, payload: dict[str, Any], event: str) -> dict[str, Any] | None:
    """The daemon's hook output for this payload ({} for no opinion), or None when it can't be reached."""
    if not client.token:
        return None
    body = json.dumps({"adapter": {"name": "claude-agent-sdk", "version": __version__, "event": event},
                       "payload": payload}, default=str).encode()
    req = urllib.request.Request(client.url + ROUTE, data=body, method="POST")
    req.add_header("authorization", f"Bearer {client.token}")
    req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=client.timeout if event == "pre" else client.timeout + 1) as r:
            raw = r.read()
    except Exception:  # noqa: BLE001  unreachable daemon: the caller applies the fail mode
        return None
    return json.loads(raw) if raw.strip() else {}


def make_hooks(client: InterlockClient | None = None):
    """(pre_tool_use, post_tool_use) async callbacks for `HookMatcher(hooks=[...])`."""
    client = client or InterlockClient(agent_type="claude-agent-sdk")

    async def pre_tool_use(input_data, tool_use_id, context):
        out = await asyncio.to_thread(_post, client, dict(input_data), "pre")
        if out is None:
            if client.fails_closed():
                return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                               "permissionDecisionReason": InterlockClient.UNREACHABLE}}
            return {}
        return out

    async def post_tool_use(input_data, tool_use_id, context):
        return await asyncio.to_thread(_post, client, dict(input_data), "post") or {}

    setattr(pre_tool_use, _MARK, True)
    setattr(post_tool_use, _MARK, True)
    return pre_tool_use, post_tool_use


def hooks(client: InterlockClient | None = None) -> dict[str, list]:
    """`ClaudeAgentOptions(hooks=...)` value with Interlock on every tool."""
    from claude_agent_sdk import HookMatcher

    pre, post = make_hooks(client)
    return {"PreToolUse": [HookMatcher(matcher=None, hooks=[pre])], "PostToolUse": [HookMatcher(matcher=None, hooks=[post])]}


def guard_options(options, client: InterlockClient | None = None):
    """Add Interlock's hooks to a `ClaudeAgentOptions`, keeping any you set. Idempotent; returns the same object."""
    current = dict(options.hooks or {})
    for event, matchers in hooks(client).items():
        existing = list(current.get(event) or [])
        if not any(getattr(h, _MARK, False) for m in existing for h in m.hooks):
            existing = matchers + existing                    # Interlock runs first
        current[event] = existing
    options.hooks = current
    return options
