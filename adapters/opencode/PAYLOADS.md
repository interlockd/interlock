# OpenCode plugin (documented contract; not yet measured)

**Status: built from the documentation and tested under Node against a real daemon; not yet run inside OpenCode.** Source: https://opencode.ai/docs/plugins/ (read 2026-10-18).

OpenCode has no command hooks; it loads JS/TS plugins from `~/.config/opencode/plugins/` (and `.opencode/plugins/`). `interlock init` writes `~/.config/opencode/plugins/interlock.js` (source: `daemon/interlockd/shims/opencode/interlock.js`), which:

- on `tool.execute.before (input, output)`: sends `input.tool` and `output.args` to the daemon's `/interlock/v1/decide`; in enforce mode a block or ask **throws**, OpenCode's documented way to stop a call, with the notice as the message;
- on `tool.execute.after`: sends the output for the injection probe (record-only: replacing the result is not documented);
- when the daemon does not answer, applies `~/.interlock/fail-mode.json`.

Tool names assumed from the docs: `bash` (`command`), `read` / `write` / `edit` (`filePath`), `webfetch`. To verify live: these names and argument keys, and that a thrown error reaches the model as a tool error.
## Tamper refusals
Shared contract (classification, cause keywords, messages, `hook.log` and the `X-Interlock-Identity` header): `adapters/README.md`. The plugin posts an event to `/interlock/v1/decide` rather than a hook route; its `adapter` block is `{"name": "opencode", "version": "...", "shim": "<path of interlock.js>"}` (`shim` from `fileURLToPath(import.meta.url)`, omitted when that fails). It reads the identity with `res.headers.get("x-interlock-identity")`; duplicated headers come back joined with `, ` and fail the comparison.
| Case | Interlock does |
|---|---|
| `token_rejected`, `daemon_identity`, `daemon_lost` on `tool.execute.before`, `fail_mode.tamper: closed` | `throw new Error("<tamper message>")` |
| `enforcement_point` on `tool.execute.before` (daemon block, enforce mode) | `throw new Error("<daemon notice>")` |
| `fail_mode.tamper: open` on `tool.execute.before` | returns without throwing (no opinion) |
| Any `tool.execute.after` | logs only, never throws |
