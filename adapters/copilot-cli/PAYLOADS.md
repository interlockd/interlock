# GitHub Copilot CLI hooks (documented contract; not yet measured)

**Status: built from the documentation, not verified against a running Copilot CLI.** Source: https://docs.github.com/en/copilot/reference/hooks-configuration (read 2026-10-18).

Interlock writes `~/.copilot/hooks/interlock.json`:

```json
{"version": 1, "hooks": {
  "preToolUse":  [{"type": "command", "bash": "sh ~/.interlock/adapters/copilot-cli/interlock-hook.sh pre",  "timeoutSec": 5}],
  "postToolUse": [{"type": "command", "bash": "sh ~/.interlock/adapters/copilot-cli/interlock-hook.sh post", "timeoutSec": 5}]}}
```

The camelCase payload (`sessionId`, `timestamp`, `cwd`, `toolName`, `toolArgs`) does not name its event, so the shim is told `pre` / `post`.

| Goal | Interlock emits | Documented behaviour |
|---|---|---|
| Refuse | `{"permissionDecision": "deny", "permissionDecisionReason": "..."}` | denied; exit 2 also denies |
| Ask | `{"permissionDecision": "ask", ...}` | asks the user |
| Withhold a result | `{"modifiedResult": {"resultType": "success", "textResultForLlm": "<notice>"}}` | replaces the result |
| Warn | `{"additionalContext": "..."}` | annotates |
| No opinion | no output, exit 0 | **any non-zero exit denies** (fail closed), so the shim never exits non-zero for no opinion |

To verify live: shell tool name (`bash` assumed), whether `toolArgs` is a string or an object (both handled), withhold.
