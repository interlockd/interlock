# Interlock adapter for Codex

Codex hooks (https://developers.openai.com/codex/hooks/) use the same event schema as Claude Code hooks: JSON on
stdin, `hookSpecificOutput` JSON on stdout. The adapter therefore shares `daemon/interlockd/shims/claude-code/interlock-hook.sh`
with `HARNESS=codex`, and the daemon normalizes the payload the same way. Payload capture is pending.

Install: `interlock install --codex --project /path/to/repo` writes `.codex/hooks.json` (or `--user` for
`~/.codex/hooks.json`). Codex requires a one-time review of non-managed hooks (`/hooks` in the CLI); enterprises can
pin managed hooks in `requirements.toml`.

```json
{ "description": "Interlock pre/post-action gate",
  "hooks": {
    "PreToolUse":  [{ "matcher": "Bash|apply_patch|Edit|Write|mcp__.*",
                      "hooks": [{ "type": "command", "command": "sh ~/.interlock/adapters/codex/interlock-hook.sh", "timeout": 5, "statusMessage": "Interlock" }] }],
    "PostToolUse": [{ "matcher": "Bash|mcp__.*",
                      "hooks": [{ "type": "command", "command": "sh ~/.interlock/adapters/codex/interlock-hook.sh", "timeout": 5 }] }] } }
```

Hosted tools (WebSearch) do not pass through hooks; `write_stdin` polls of an existing exec session do not fire
PreToolUse again.
