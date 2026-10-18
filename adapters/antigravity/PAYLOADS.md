# Antigravity CLI hooks (documented contract; not yet measured)

**Status: built from the documentation, not verified against a running Antigravity CLI.** Source: https://antigravity.google/docs/hooks/ (read 2026-10-18). Antigravity replaced Gemini CLI for unpaid-tier and Google One users on 2026-06-18.

Interlock adds a named group to `~/.gemini/config/hooks.json` (other groups kept):

```json
{"interlock": {"enabled": true,
  "PreToolUse":  [{"matcher": "*", "hooks": [{"type": "command", "command": "sh ~/.interlock/adapters/antigravity/interlock-hook.sh pre",  "timeout": 10}]}],
  "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "sh ~/.interlock/adapters/antigravity/interlock-hook.sh post", "timeout": 10}]}]}}
```

Input: `toolCall.name`, `toolCall.args` (shell is `run_command` with `CommandLine`, `Cwd`), `conversationId`, `workspacePaths`, `transcriptPath`.

| Goal | Interlock emits |
|---|---|
| Refuse | `{"decision": "deny", "reason": "..."}` |
| Ask | `{"decision": "ask", "reason": "..."}` |
| No opinion | `{"decision": "allow"}` (a decision is required; Interlock never sends `auto_approve`) |
| After a tool | `{}` (PostToolUse cannot replace the result) |

To verify live: non-shell tool names and their argument keys, exit-code behaviour.
