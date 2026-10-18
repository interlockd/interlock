# Gemini CLI hooks (documented contract; not yet measured)

**Status: built from the documentation, not verified against a running Gemini CLI.** Sources: https://geminicli.com/docs/hooks/ and /docs/hooks/reference/ (read 2026-10-17). Payload shapes used by the tests are in `daemon/tests/test_cursor_gemini.py`; replace them with captures (`tests/fixtures/gemini-cli/`) once measured. Note: Google replaced Gemini CLI with Antigravity CLI for unpaid-tier and Google One users on 2026-06-18; Antigravity's hook contract has not been checked.

## What Interlock registers

`~/.gemini/settings.json` (other settings and hooks preserved):

```json
{"hooks": {
  "BeforeTool": [{"matcher": ".*", "hooks": [{"name": "interlock", "type": "command", "command": "sh ~/.interlock/adapters/gemini-cli/interlock-hook.sh", "timeout": 5000}]}],
  "AfterTool":  [{"matcher": ".*", "hooks": [{"name": "interlock", "type": "command", "command": "sh ~/.interlock/adapters/gemini-cli/interlock-hook.sh", "timeout": 5000}]}]}}
```

`timeout` is in milliseconds. Shell is `run_shell_command`; MCP tools are `mcp_<server>_<tool>`.

## Documented input

| Event | Fields Interlock uses |
|---|---|
| `BeforeTool` | `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `tool_name`, `tool_input`, `mcp_context` |
| `AfterTool` | the above plus `tool_response {llmContent, returnDisplay, error}` |

## Documented output, and what Interlock emits

| Goal | Interlock emits | Documented behaviour |
|---|---|---|
| Refuse a call | `{"decision": "deny", "reason": "..."}` | tool does not run; reason sent to the agent as a tool error |
| Ask the user | — | not documented; Interlock degrades ask to deny with a notice |
| Withhold an injected result | `{"decision": "deny", "reason": "<notice>"}` on AfterTool | reason replaces the tool result sent to the model |
| Warn after a result | `{"hookSpecificOutput": {"hookEventName": "AfterTool", "additionalContext": "..."}}` | annotates the result |
| No opinion | no output, exit 0 | — |

## To verify live

1. Block and withhold as above. 2. `hooksConfig.enabled` is true (default). 3. Whether hooks need `/hooks enable` after install. 4. Project-level hooks need a trusted folder.
