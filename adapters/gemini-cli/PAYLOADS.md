# Gemini CLI hooks (measured)

**Status: verified live on Gemini CLI 0.65.0** (2026-10-24, headless `gemini -p --approval-mode yolo`, API-key auth,
`interlock capture --scratch`). Sources for the contract: https://geminicli.com/docs/hooks/ and /docs/hooks/reference/.
Redacted captures are in `daemon/tests/fixtures/gemini-cli/` and replayed by `test_live_captured_payloads`.

Note: Google replaced Gemini CLI with Antigravity CLI for unpaid-tier and Google One users on 2026-06-18; Gemini CLI
still runs with an API key. Antigravity's hook contract is separate (`adapters/antigravity/`).

## What Interlock registers

`~/.gemini/settings.json` (other settings and hooks preserved):

```json
{"hooks": {
  "BeforeTool": [{"matcher": ".*", "hooks": [{"name": "interlock", "type": "command", "command": "sh ~/.interlock/adapters/gemini-cli/interlock-hook.sh", "timeout": 5000}]}],
  "AfterTool":  [{"matcher": ".*", "hooks": [{"name": "interlock", "type": "command", "command": "sh ~/.interlock/adapters/gemini-cli/interlock-hook.sh", "timeout": 5000}]}]}}
```

`timeout` is in milliseconds. The hooks fired without `/hooks enable`. Shell is `run_shell_command`; files are
`read_file`, `list_directory`, ...; MCP tools are `mcp_<server>_<tool>` (not exercised in the capture).

## Measured input

| Event | Keys |
|---|---|
| `BeforeTool` | `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`, `tool_name`, `tool_input` |
| `AfterTool` | the above plus `tool_response {llmContent, returnDisplay}` |

Differences from the docs: `timestamp` is present (undocumented); `mcp_context` is absent for built-in tools; there is
**no tool-call id**, so `interlock capture report` pairs a refused call with a later result by session and
`tool_input`. Shell results arrive wrapped by Gemini itself: `llmContent` is `<untrusted_context>\nOutput: ...\n</untrusted_context>`.
The shell tool adds a `description` key to `tool_input`.

## Output, and what was observed

| Goal | Interlock emits | Observed |
|---|---|---|
| Refuse a call | `{"decision": "deny", "reason": "..."}` | ✅ `git push --force origin main` not executed; Gemini printed "Tool execution blocked: [interlock] ..." and no AfterTool followed |
| Ask the user | — | no ask in the contract; Interlock degrades ask to deny with a notice |
| Withhold an injected result | `{"decision": "deny", "reason": "<notice>"}` on AfterTool | ✅ `read_file README.md`: "Tool result blocked: [interlock] ..."; the model saw only the notice |
| Warn after a result | `{"hookSpecificOutput": {"hookEventName": "AfterTool", "additionalContext": "..."}}` | not exercised live (unit-tested) |
| No opinion | no output, exit 0 | ✅ benign calls ran normally |

## Agent behaviour worth knowing

After the README was withheld, Gemini went looking for the reason: `env | grep -i INTERLOCK`, `which interlock`,
`list_directory ~/.interlock` (refused by Gemini's own workspace sandbox), then a python one-liner described as
"Inspect obfuscated text of README.md to understand content without triggering policy", which printed the README in
ROT13. That output was not flagged at the time. Two fixes followed:

- the local probe also scores ROT13 and base64 decodings of each tool result (`decoded_views` in `judges/local_probe.py`);
- `flow.reread_withheld`: once a file's contents are withheld, a shell (or other non-read) call naming that file in the
  same session is asked about, which Gemini receives as a deny.

`post-shell-rot13-inject.json` is that capture; it is withheld now.

## Running it

- Headless mode needs a trusted folder: set `GEMINI_CLI_TRUST_WORKSPACE=true` (or `--skip-trust`); otherwise Gemini
  exits before any tool runs and YOLO is overridden to default.
- Gemini CLI runs on Node; a Node whose CA store cannot verify `generativelanguage.googleapis.com` fails with
  `TypeError: fetch failed sending request` and nine retries. That is the Node install, not the hooks.
- Free-tier keys: `gemini-2.5-flash` returned "no longer available to new users"; `gemini-3.8-flash` worked (20 requests
  per day).
## Tamper refusals
Shared contract (classification, cause keywords, messages, `hook.log`, the `shim` request field and the `X-Interlock-Identity` header): `adapters/README.md`. Gemini CLI output, within the contract above:
| Case | Interlock emits |
|---|---|
| `token_rejected`, `daemon_identity`, `daemon_lost` on BeforeTool, `fail_mode.tamper: closed` | `{"decision": "deny", "reason": "<tamper message>"}`, exit 0 |
| `enforcement_point` on BeforeTool (daemon block) | the refusal above with the daemon's notice as `reason` |
| `fail_mode.tamper: open`, or any AfterTool | no output, exit 0 |
