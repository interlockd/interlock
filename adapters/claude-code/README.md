# Interlock adapter for Claude Code

Written to the documented hook contract (https://code.claude.com/docs/en/hooks); the payload capture that
`adapters/kiro/PAYLOADS.md` provides for Kiro is still pending for Claude Code, so treat field names here as
"per the docs" until a capture confirms them.

Install: `interlock install --claude-code --project /path/to/repo` (or `--user`). It merges two hook groups into
`.claude/settings.json`:

```json
{ "hooks": {
    "PreToolUse":  [{ "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit|WebFetch|Task|mcp__.*",
                      "hooks": [{ "type": "command", "command": "sh ~/.interlock/adapters/claude-code/interlock-hook.sh", "timeout": 5 }] }],
    "PostToolUse": [{ "matcher": "Bash|Read|WebFetch|mcp__.*",
                      "hooks": [{ "type": "command", "command": "sh ~/.interlock/adapters/claude-code/interlock-hook.sh", "timeout": 5 }] }] } }
```

What the daemon returns and what Claude Code does with it:

| Interlock | Claude Code sees | Effect |
|---|---|---|
| `block` | `permissionDecision: "deny"` + reason | Tool does not run; Claude reads the reason. Fires above the permission system, so it holds in `--dangerously-skip-permissions` and auto mode. |
| `ask` | `permissionDecision: "ask"` + reason | Native permission prompt, labelled `[settings]`, with Interlock's reason. Forces a prompt even in auto mode. |
| `allow` (or shadow mode) | nothing | Claude Code's own permission rules decide. Interlock never returns `allow`. |
| post-action `warn` | `additionalContext` | A warning line Claude reads alongside the result. |
| post-action `withhold` | `updatedToolOutput` | The result is replaced with a notice; the original stays in the audit store. |
| daemon unreachable, fail closed | `deny` with an explanation | Fail open prints nothing. |

User messages for the intent judge are read by the daemon from `transcript_path` (type == "user" lines, text blocks
only; tool_result blocks are not instructions).
