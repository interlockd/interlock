"""State projector (design §4.4, revised by the spike): minimal, role-separated, size-capped.

The intent judge sees the user's messages, one-line summaries of prior tool calls, and the structured proposed action.
It never sees assistant prose, tool outputs, or the policy text (which lives in the question criteria). The probe
sees the untrusted content, capped head and tail, beside the user's messages.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import InterlockEvent


def _summary(tool: str, args: dict[str, Any], limit: int = 160) -> str:
    for k in ("command", "path", "file_path", "url", "query", "sql"):
        v = args.get(k)
        if isinstance(v, str) and v:
            return f"{tool}: {v[:limit]}"
    return tool


def _truncate_tokens(text: str, max_tokens: int) -> tuple[str, bool]:
    budget = max_tokens * 4  # ~4 chars per token
    if len(text) <= budget:
        return text, False
    half = budget // 2
    return text[:half] + "\n…[truncated]…\n" + text[-half:], True


def project_intent(event: InterlockEvent, *, normalized: dict[str, Any], prior_calls: list[str], max_tokens: int = 1000) -> dict[str, Any]:
    args = event.tool_call.arguments
    compact_args = {k: (v[:600] if isinstance(v, str) else v) for k, v in args.items() if k not in ("description", "explanation")}
    state = {
        "user_messages": [{"n": m.n, "text": m.text[:1200]} for m in (event.context.user_messages or [])],
        "prior_tool_calls": [{"arguments_summary": s} for s in prior_calls[-6:]],
        "proposed_action": {"tool": event.tool_call.name, "arguments": compact_args,
                            "normalized": {k: v for k, v in normalized.items() if k in ("action_class", "git_push", "egress_hosts", "commands", "undeclared_packages")}},
    }
    # keep the whole state within budget by trimming older user messages first
    while len(json.dumps(state)) > max_tokens * 4 and len(state["user_messages"]) > 1:
        state["user_messages"].pop(0)
    return state


def project_probe(event: InterlockEvent, *, max_untrusted_tokens: int = 3000) -> tuple[dict[str, Any], bool]:
    content = event.result.content if event.result else ""
    text, truncated = _truncate_tokens(content, max_untrusted_tokens)
    state = {
        "user_messages": [{"n": m.n, "text": m.text[:800]} for m in (event.context.user_messages or [])][-2:],
        "tool": event.tool_call.name,
        "untrusted_content": text,
    }
    return state, truncated


def user_context_text(event: InterlockEvent) -> str | None:
    msgs = event.context.user_messages or []
    if not msgs:
        return None
    return "The user's instructions to the coding agent were: " + " | ".join(m.text[:400] for m in msgs[-2:])


def action_summary(event: InterlockEvent, normalized: dict[str, Any]) -> str:
    """One line a person would recognize: the normalized structure first, the raw argument as a fallback."""
    if "git_push" in normalized:
        gp = normalized["git_push"]
        return f"git push {'--force ' if gp.get('force') else ''}{gp.get('remote')} {gp.get('branch')}".strip()
    cmds = normalized.get("commands")
    if cmds:
        return "shell: " + ", ".join(dict.fromkeys(c for c in cmds if c))[:200]
    return _summary(event.tool_call.name, event.tool_call.arguments)


def project_confirmation(event: InterlockEvent, *, normalized: dict[str, Any], reason: str | None) -> dict[str, Any]:
    msgs = event.context.user_messages or []
    return {
        "what_the_agent_asked_permission_for": action_summary(event, normalized),
        "why_it_was_held": (reason or "security policy")[:300],
        "user_messages_since": [{"n": m.n, "text": m.text[:600]} for m in msgs[-2:]],
    }
