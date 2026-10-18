# Cursor hooks (measured)

**Measured:** 2026-10-18 on the Cursor CLI (`cursor-agent` 2026.10.16), `cursor-agent -p --trust --force`, project hooks in `.cursor/hooks.json`. Captures (usernames and the `user_email` field redacted) are fixtures in `daemon/tests/fixtures/cursor/`. Contract source: https://cursor.com/docs/agent/hooks.

## What Interlock registers

`~/.cursor/hooks.json` (or `<project>/.cursor/hooks.json`; project hooks need a trusted workspace):

```json
{"version": 1, "hooks": {
  "preToolUse":  [{"command": "sh ~/.interlock/adapters/cursor/interlock-hook.sh", "type": "command", "timeout": 5, "matcher": "*"}],
  "postToolUse": [{"command": "sh ~/.interlock/adapters/cursor/interlock-hook.sh", "type": "command", "timeout": 5, "matcher": "*"}]}}
```

## Measured input

| Event | Keys |
|---|---|
| `preToolUse` | `conversation_id`, `cursor_version`, `cwd`, `generation_id`, `hook_event_name`, `model`, `session_id`, `tool_input`, `tool_name`, `tool_use_id`, `transcript_path`, `user_email`, `workspace_roots` |
| `postToolUse` | the above plus `duration`, `tool_output` |

- Shell is `tool_name: "Shell"` with `tool_input {command, cwd, timeout}`; reads are `Read` with `{file_path}`.
- `tool_output` is a **JSON string**: Shell `{"output": "...", "exitCode": 0}`; Read only `{"file_path", "content_length"}`, **without the file contents**, so Interlock cannot check what the agent reads through Cursor's Read tool (shell output is checked).
- Payloads include the signed-in user's email; Interlock does not store it.

## Measured output

| Goal | JSON | Verified |
|---|---|---|
| Refuse a call | `{"permission": "deny", "agent_message": "...", "user_message": "..."}` | ✅ the call did not run; the agent reported `Rejected: Interlock blocked this action: ...` |
| No opinion | no output, **exit 1** | ✅ the call ran normally (exit 1 is fail-open) |
| Withhold | `updated_mcp_tool_output` (MCP tools only) | not measured |
