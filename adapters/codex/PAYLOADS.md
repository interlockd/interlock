# Codex hook payloads (measured)

**Measured:** 2026-10-17 on Codex CLI 0.162.1 (stable), `codex exec --dangerously-bypass-hook-trust -s workspace-write`, project hooks in `.codex/hooks.json`. Captures (usernames redacted) are test fixtures in `daemon/tests/fixtures/codex/`.

## Input (stdin)

| Event | Keys |
|---|---|
| `PreToolUse` | `cwd`, `hook_event_name`, `model`, `permission_mode`, `session_id`, `tool_input`, `tool_name`, `tool_use_id`, `transcript_path`, `turn_id` |
| `PostToolUse` | the above plus `tool_response` |

## Output

| Goal | JSON | Verified |
|---|---|---|
| Refuse a call | Claude-compatible `permissionDecision: "deny"` | ✅ logged as `Command blocked by PreToolUse hook: [interlock] ...`; the agent reported the block |
| Replace a tool result (withhold) | `{"decision": "block", "reason": "<notice>"}` | ✅ the model received only the reason (codeword test and a live injected README) |
| Add a warning after a result | `hookSpecificOutput.additionalContext` | ✅ the model saw the note |

Controlled test (2026-10-17, codeword in a file, `cat` through Bash): `updatedToolOutput` (inside `hookSpecificOutput` or top level) was **ignored**; `decision: "block"` replaced the output; `additionalContext` was applied. This is the opposite of Claude Code, where `decision: "block"` keeps the original output visible, so the renderer branches per harness.

Notes:

- Hooks need trust: interactively run `/hooks` once in Codex; non-interactive runs need `--dangerously-bypass-hook-trust` (use only with hooks you installed yourself).
- Hooks fire in `codex exec` only with stdin closed (`< /dev/null`) in automation; with an open stdin it waits.
