# Windsurf (Cascade) hooks (documented contract; not yet measured)

**Status: built from the documentation, not verified against a running Windsurf.** Source: https://docs.devin.ai/desktop/cascade/hooks (docs.windsurf.com redirects there; read 2026-10-18).

Interlock adds to `~/.codeium/windsurf/hooks.json` (your own hooks are kept): `pre_run_command`, `pre_mcp_tool_use`, `pre_read_code`, `pre_write_code`, each `{"command": "sh ~/.interlock/adapters/windsurf/interlock-hook.sh pre", "show_output": true}`.

| Event | Fields Interlock uses |
|---|---|
| `pre_run_command` | `tool_info.command_line`, `tool_info.cwd` |
| `pre_mcp_tool_use` | `tool_info.mcp_server_name`, `mcp_tool_name`, `mcp_tool_arguments` |
| `pre_read_code` / `pre_write_code` | `tool_info.file_path` (assumed key) |

Blocking is **exit code 2** with the reason on stderr (shown to the agent); any other exit lets the action proceed. There is no documented way to replace a result, so post-action detections are not rendered. The daemon replies in text form and the shim turns a block into exit 2, only in enforce mode.

To verify live: the read/write `tool_info` keys, that stderr reaches the agent.
