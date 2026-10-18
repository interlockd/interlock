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

Notes:

- Hooks need trust: interactively run `/hooks` once in Codex; non-interactive runs need `--dangerously-bypass-hook-trust` (use only with hooks you installed yourself).
- Post-action withhold has not been measured on Codex yet.
