# Claude Code hook payloads (measured)

**Measured:** 2026-10-17 on Claude Code 2.1.296 (ASBX build, stable channel), headless `claude -p`, project-level hooks in `.claude/settings.json`. Captures (usernames redacted) are test fixtures in `daemon/tests/fixtures/claude-code/`, replayed through the API by `test_live_captured_payloads`.

## Input (stdin)

| Event | Keys |
|---|---|
| `PreToolUse` | `cwd`, `effort`, `hook_event_name`, `permission_mode`, `prompt_id`, `session_id`, `tool_input`, `tool_name`, `tool_use_id`, `transcript_path` |
| `PostToolUse` | the above plus `duration_ms`, `tool_response` |

`tool_response` shapes seen: Bash `{stdout, stderr, interrupted, isImage, noOutputExpected}`; Read `{type: "text", file: {filePath, content, numLines, startLine, totalLines}}`.

## Output (stdout) — what the CLI actually applies

| Goal | JSON | Verified |
|---|---|---|
| Refuse a call | `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..."}}` | ✅ the agent saw the reason, did not retry, and reported the block |
| Replace a tool result (withhold) | `{"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": <same shape as tool_response>}}` | ✅ Bash and Read: the model received only the replacement |
| Add a warning after a result | `{"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "..."}}` | documented; not separately measured |

Findings that changed the renderer:

- `updatedToolOutput` as a **bare string** is ignored: the model saw the injected file.
- A shape-matching `updatedToolOutput` at the **top level** (as the hooks reference describes) was ignored on 2.1.296; inside `hookSpecificOutput` it was applied. Interlock emits both placements.
- Hooks fire before the permission check, including in `-p` mode with `--allowedTools`.

Interlock never emits `permissionDecision: "allow"` (that would skip the CLI's own permission prompt).
