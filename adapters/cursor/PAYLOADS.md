# Cursor hooks (documented contract; not yet measured)

**Status: built from the documentation, not verified against a running Cursor.** Source: https://cursor.com/docs/agent/hooks (read 2026-10-17). Hooks arrived in Cursor 1.7. Payload shapes used by the tests are in `daemon/tests/test_cursor_gemini.py`; replace them with captures (`tests/fixtures/cursor/`) once measured.

## What Interlock registers

`~/.cursor/hooks.json` (user level; `<project>/.cursor/hooks.json` with `interlock install --cursor --project P`):

```json
{"version": 1, "hooks": {
  "preToolUse":  [{"command": "sh ~/.interlock/adapters/cursor/interlock-hook.sh", "type": "command", "timeout": 5, "matcher": "*"}],
  "postToolUse": [{"command": "sh ~/.interlock/adapters/cursor/interlock-hook.sh", "type": "command", "timeout": 5, "matcher": "*"}]}}
```

`preToolUse` / `postToolUse` cover every tool type (`Shell`, `Read`, `Write`, `Grep`, `Delete`, `Task`, `MCP:<tool>`). The normalizer also accepts `beforeShellExecution` / `afterShellExecution` payloads.

## Documented input

| Event | Fields Interlock uses |
|---|---|
| `preToolUse` | `hook_event_name`, `conversation_id`, `tool_name`, `tool_input`, `tool_use_id`, `cwd`, `workspace_roots`, `transcript_path` |
| `postToolUse` | the above plus `tool_output`, `duration` |
| `postToolUseFailure` | `error_message`, `failure_type` |

## Documented output, and what Interlock emits

| Goal | Interlock emits | Documented behaviour |
|---|---|---|
| Refuse a call | `{"permission": "deny", "agent_message": "...", "user_message": "..."}` | tool does not run |
| Ask the user | — | `ask` "is accepted by the schema but not enforced for preToolUse today"; Interlock degrades ask to deny with a notice |
| Withhold an injected result | `{"updated_mcp_tool_output": ...}` (MCP tools only) | output replacement is MCP-only |
| Warn after a result | `{"additional_context": "..."}` | annotates the result |
| No opinion | **exit 1, no output** | exit 0 with output that isn't valid permission JSON *blocks*; any non-zero code other than 2 fails open |

## To verify live

1. Block: a force-push is refused and the agent sees `agent_message`.
2. No opinion: a benign command runs normally with exit 1 and no output (and Cursor shows no error the user has to dismiss).
3. Warn on a non-MCP Read of an injected file; withhold on an MCP result.
4. Project hooks need a trusted workspace.
