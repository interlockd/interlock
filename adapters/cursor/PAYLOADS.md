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
## Tamper refusals
Shared contract (classification, cause keywords, messages, `hook.log`, the `shim` request field and the `X-Interlock-Identity` header): `adapters/README.md`. Cursor output, within the contract above:
| Case | Interlock emits |
|---|---|
| `token_rejected`, `daemon_identity`, `daemon_lost` on `preToolUse`, `fail_mode.tamper: closed` | `{"permission": "deny", "agent_message": "<tamper message>", "user_message": "<short summary>"}`, exit 0. The cause keyword is in `agent_message`; `user_message` is a one-line summary without it |
| `enforcement_point` on `preToolUse` (daemon block) | the refusal above with the daemon's notice as `agent_message` |
| `fail_mode.tamper: open` on `preToolUse` | no output, **exit 1** (Cursor's no opinion) |
| Any `postToolUse` | no output, exit 0 |
