# Kiro hook payloads, captured

**Captured:** October 8, 2026, Kiro IDE (session `sess_a2fd71e8…`, macOS, Kiro agent harness) and Kiro CLI 2.28.0.
**How:** `spikes/kiro-capture/capture.sh` installed as `PreToolUse` and `PostToolUse` command hooks at the workspace root; every record is the exact bytes the hook received on stdin. Probe scripts in the same directory tested the exit-code and stdout channels.
**Why it matters:** the adapter field mapping in `phase1-design.md` §4.1 is written against these captures, not against documentation.

## 1. Where hooks live and when they load

- Hook files are read from `<workspace-root>/.kiro/hooks/*.json`, where the workspace root is the folder Kiro has open (`session.json: rootPaths`), not the git repository. In this workspace that is `/Users/dev/Documents/codes/interlock`, one level above the repo. `interlock install --kiro` must resolve the Kiro workspace root, not the repo root.
- New and edited hook files are picked up live, mid-session. No restart was needed.
- `matcher` is compiled as a JavaScript regular expression. The documented `"*"` ("all tools") does **not** compile in the IDE (`Invalid regular expression: /*/: Nothing to repeat`, logged to `~/.kiro/logs/<ts>/kiro.log`, hook silently never fires). Use `".*"`, or an explicit alternation such as `"execute_bash|fs_write|str_replace|delete_file|web_fetch"`.
- Every hook invocation is recorded in the session transcript (`~/.kiro/sessions/<ws>/<session>/messages.jsonl`) as a `ContextualHookInvoked` payload with `hookId`, `name`, `status`, `executionId`.

## 2. Environment

| Variable | PreToolUse / PostToolUse (IDE) | userPromptSubmit (CLI) |
|---|---|---|
| `KIRO_SESSION_ID` | set | set |
| `USER_PROMPT` | unset | set |
| `KIRO_CLI_ACP_CLIENT_NAME` | unset | set (CLI only) |

The hook's working directory is the workspace root. The command runs under `sh` with the user's environment.

## 3. PreToolUse stdin (IDE)

```json
{
  "session_id": "sess_a2fd71e8-b865-4aeb-9465-a8fa86242e4e",
  "hook_event_name": "PreToolUse",
  "cwd": "/Users/dev/Documents/codes/interlock",
  "tool_name": "execute_bash",
  "tool_input": {
    "command": "grep -o '\"hook\":\"[A-Za-z]*\"' ~/.interlock/spike/kiro-hook-capture.jsonl | sort | uniq -c",
    "description": "Check whether the IDE hook fired after the matcher fix",
    "cwd": null,
    "run_in_background": false,
    "timeout": null
  }
}
```

Exactly five top-level keys on every PreToolUse event seen: `session_id`, `hook_event_name`, `cwd`, `tool_name`, `tool_input`. **Not present:** the user's messages, a transcript path, a tool-call id, a permission mode, an agent or subagent id.

`tool_input` is the tool's own argument object, verbatim, including the model-written `description`/`explanation` fields. Shapes seen:

| `tool_name` | `tool_input` keys |
|---|---|
| `execute_bash` | `command`, `description`, `cwd` (nullable), `run_in_background`, `timeout` (nullable) |
| `read_file` | `path`, `offset`, `limit` |
| `grep_search` | `query`, `caseSensitive`, `excludePattern`, `explanation`, `includePattern` |
| `file_search` | `explanation`, `query`, `excludePattern`, `includeIgnoredFiles` |
| `fs_write`, `str_replace`, `delete_file`, `web_fetch`, MCP tools | not yet captured; MCP tools are documented as `"tool_name": "@<server>/<tool>"` |

Note that `read_file.path` can arrive relative or absolute as the model wrote it (Claude Code normalizes to absolute; Kiro does not appear to). The adapter must normalize against `cwd`.

## 4. PostToolUse stdin (IDE)

Same five keys plus `tool_response`, a **string** (the rendered tool output the model sees), for example:

```json
{
  "session_id": "sess_…", "hook_event_name": "PostToolUse", "cwd": "/Users/dev/Documents/codes/interlock",
  "tool_name": "read_file", "tool_input": { "path": "…/README.md", "offset": null, "limit": null },
  "tool_response": "<file name=\"…/README.md\" language=\"markdown\" >\n<content>\n# interlock-AI\n</content>\n</file>"
}
```

For `execute_bash` the string is `"Output:\n…\n\nExit Code: 0"`. No structured exit code, no changed-files list, no duration. The reconciliation seed on Kiro is therefore limited to parsing the exit code out of the string and hashing the output.

## 5. Decision channels (measured)

| Channel | Result | Consequence for the adapter |
|---|---|---|
| PreToolUse, exit 2 with text on stderr | **Tool not executed.** The agent receives the stderr text as a hook instruction and is told the tool was not run and to decide how to proceed | This is the block primitive. The notice should follow OGR `continuation` wording: what was refused, that it did not run, what the agent may do instead, do not retry in disguised form |
| PreToolUse, exit 0 with text on stdout | Tool runs; **stdout is not shown to the agent** | No `additionalContext` channel on Kiro |
| PreToolUse, exit 0 with a Claude-Code-style JSON decision (`permissionDecision: "ask"`) on stdout | Tool runs normally; **JSON is ignored** | Kiro has no hook-driven "ask". The ask band renders as a block whose notice instructs the agent to confirm with the user before retrying, plus the denial budget. A hard prompt requires Kiro's own permissions configuration, which is static |
| PostToolUse, exit 2 with text on stderr | Tool already ran; **stderr does not reach the agent** (docs: shown as a warning to the user) | The post-action probe on Kiro is record-only plus a user-visible warning. It cannot warn the model or replace the tool output |
| Hook timeout | `timeout` is in seconds in the v1 schema (default 60); `timeout_ms` is the CLI 2.x name | Set `timeout: 3` for the pre-action hook and apply the local fail mode inside the shim before that fires |

## 6. User instructions: where to get them

The payload carries no user messages, so the intent judge cannot be fed from stdin alone. The session transcript at `~/.kiro/sessions/<workspace-hash>/<session_id>/messages.jsonl` holds them: one JSON object per line, `payload.type == "user"` for user messages, with `turn_start`/`turn_end`, `tool_call`, `tool_result`, `assistant` entries alongside. `session.json` in the same directory has `rootPaths`, `agentMode`, `autopilot`, and `modelId`. The `session_id` on the hook event matches the directory name, and the workspace hash directory is discoverable by scanning for a child named `<session_id>`. The transcript is written continuously and was current to the second during capture (the hook's own invocation appeared in it immediately), so lag is small; the adapter should still tolerate a missing last message.

The daemon, not the hook, should read the transcript: the hook stays a thin shim and the daemon caches the last N user messages per session.

## 7. Kiro CLI 2.28 (not the target)

With hooks embedded in an agent config (`~/.kiro/agents/<name>.json`, `"hooks": {"preToolUse": [...]}`), a one-shot `kiro-cli chat --no-interactive --trust-all-tools` run fired `userPromptSubmit` (payload: `hook_event_name`, `cwd`, `session_id`, `prompt`) but **not** `preToolUse`/`postToolUse` in two attempts (matcher `".*"` and explicit tool names) even though three tools ran. Cause not determined. CLI 3.0 shares the IDE's standalone format and is the supported target; it was not available on this machine.

## 8. Adapter field mapping (Kiro → InterlockEvent)

| InterlockEvent | Source |
|---|---|
| `kind` | `hook_event_name` (`PreToolUse` → `pre_action`, `PostToolUse` → `post_action`) |
| `identity.agent_type` | `"kiro"` |
| `identity.agent_id` | config, default `kiro-<hostname>` |
| `identity.agent_workspace` | config, default basename of the git root containing `cwd`, else basename of `cwd` |
| `identity.agent_user` | `$USER` |
| `session_hint` | `session_id` |
| `tool_call.id` | none on the wire; the daemon mints `<session_id>:<n>` and pairs pre/post by `(session_id, tool_name, sha256(tool_input))` |
| `tool_call.name`, `tool_call.arguments` | `tool_name`, `tool_input` |
| `context.cwd` | `cwd` |
| `context.user_messages` | daemon reads them from the session transcript (§6); absent in the hook payload |
| `context.permission_mode` | `session.json: autopilot` (boolean), read by the daemon |
| `result.content` | `tool_response` (string), post-action only |
| `result.evidence.exit_code` | parsed from the trailing `Exit Code: N` of an `execute_bash` response |
| `capabilities` | `{ "ask": false, "rewrite": false, "withhold": false }` |
