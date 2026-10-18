# GitHub Copilot CLI hooks (measured)

**Measured:** 2026-10-18 on GitHub Copilot CLI 1.0.98, `copilot -p ... --allow-all-tools`, user-level hooks in `$COPILOT_HOME/hooks/interlock.json` (a sandbox `COPILOT_HOME`). Captures are fixtures in `daemon/tests/fixtures/copilot-cli/`. Contract source: https://docs.github.com/en/copilot/reference/hooks-configuration.

## What Interlock registers

`~/.copilot/hooks/interlock.json`:

```json
{"version": 1, "hooks": {
  "preToolUse":  [{"type": "command", "bash": "sh ~/.interlock/adapters/copilot-cli/interlock-hook.sh pre",  "timeoutSec": 5}],
  "postToolUse": [{"type": "command", "bash": "sh ~/.interlock/adapters/copilot-cli/interlock-hook.sh post", "timeoutSec": 5}]}}
```

Repo-level hooks (`.github/hooks/*.json`) did **not** fire until the folder was in `trustedFolders`; the user-level file always fires, which is why `interlock init` installs there.

## Measured input

| Event | Keys |
|---|---|
| pre | `cwd`, `sessionId`, `timestamp`, `toolArgs`, `toolName` |
| post | the above plus `toolResult` |

- Shell is `toolName: "bash"`, `toolArgs {command, description}` (an object, not a string).
- `toolResult` is `{"resultType": "success", "textResultForLlm": "..."}`.
- The payload does not name its event, so the shim is registered with `pre` / `post`.

## Measured output

| Goal | JSON | Verified |
|---|---|---|
| Refuse a call | `{"permissionDecision": "deny", "permissionDecisionReason": "..."}` | ✅ `Denied by preToolUse hook: [interlock] ...`; the agent stopped and asked |
| Withhold a result | `{"modifiedResult": {"resultType": "success", "textResultForLlm": "<notice>"}}` | ✅ the model received only the notice (codeword test with an injected README) |
| No opinion | no output, exit 0 | ✅ calls ran normally |
