# Windsurf (Cascade) hooks (measured)

**Status: verified live on Windsurf 3.10.67** (2026-10-24; the app now ships as **Devin.app**, bundle id
`com.exafunction.windsurf`; docs at https://docs.devin.ai/desktop/cascade/hooks). Captured with `interlock capture`
and project-level hooks in a scratch workspace; redacted payloads in `daemon/tests/fixtures/windsurf/`.

## What Interlock registers

`interlock init` adds to `~/.codeium/windsurf/hooks.json` (your own hooks are kept): `pre_run_command`,
`pre_mcp_tool_use`, `pre_read_code`, `pre_write_code`, each
`{"command": "sh ~/.interlock/adapters/windsurf/interlock-hook.sh pre", "show_output": true}`.

Windsurf also merges system (`/Library/Application Support/Devin/hooks.json`) and workspace (`.devin/hooks.json`,
legacy `.windsurf/hooks.json`) files. Measured: **both** workspace files load when both exist, although the docs say
the legacy one is skipped. Hooks don't run in Restricted Mode (trust the folder).

## Measured input

Every event: `agent_action_name`, `trajectory_id` (one per Cascade conversation), `execution_id` (one per Cascade
turn, shared by every call in it), `timestamp`, `tool_info`. No `model_name` arrived.

| Event | `tool_info` |
|---|---|
| `pre_run_command` / `post_run_command` | `command_line`, `cwd` — **`cwd` is always `null`** |
| `pre_read_code` / `post_read_code` | `file_path` (absolute) — **no content** |
| `post_run_command` | same as pre — **no output** |

Hooks run with the workspace as their working directory. The shim sends that directory (`adapter.cwd`) and the daemon
uses it when `tool_info.cwd` is null; without it a repository policy in the workspace was never found and an
enforcing scratch policy did not apply.

**Every hook runs twice**, ~60 ms apart, with identical payloads. The daemon answers the repeat from the first
decision (keyed on `execution_id`, event and `tool_info`, 5 s), so it is recorded and counted once.

## Output, and what was observed

| Goal | Interlock emits | Observed |
|---|---|---|
| Refuse a call | exit 2, reason on stderr | ✅ `git push --force origin main` not run; Cascade showed "Hook block" and quoted the reason |
| Refuse an injected file before it is read | exit 2 on `pre_read_code` (see below) | ✅ README.md refused; Cascade reported "the file was not read because it appears to contain instructions addressed to the agent" |
| Read a withheld file another way | exit 2 (`flow.reread_withheld`, ask → refusal) | ✅ `cat README.md` refused; Cascade asked the user to confirm |
| Withhold or annotate a result | — | not possible: post hooks can't change anything and carry no result |
| No opinion | exit 0 | ✅ `ls -la` ran |

## Reads are probed from disk

Because no hook carries file contents, the daemon reads the file named by `pre_read_code` itself (up to 256 KiB, regular
files only, never a sensitive path) and runs the injection probe on it. An injected file is refused before Cascade
reads it, and the path is remembered for `flow.reread_withheld`. Shell output can't be checked on Windsurf.
