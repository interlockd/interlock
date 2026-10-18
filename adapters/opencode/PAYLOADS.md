# OpenCode plugin (documented contract; not yet measured)

**Status: built from the documentation and tested under Node against a real daemon; not yet run inside OpenCode.** Source: https://opencode.ai/docs/plugins/ (read 2026-10-18).

OpenCode has no command hooks; it loads JS/TS plugins from `~/.config/opencode/plugins/` (and `.opencode/plugins/`). `interlock init` writes `~/.config/opencode/plugins/interlock.js` (source: `daemon/interlockd/shims/opencode/interlock.js`), which:

- on `tool.execute.before (input, output)`: sends `input.tool` and `output.args` to the daemon's `/interlock/v1/decide`; in enforce mode a block or ask **throws**, OpenCode's documented way to stop a call, with the notice as the message;
- on `tool.execute.after`: sends the output for the injection probe (record-only: replacing the result is not documented);
- when the daemon does not answer, applies `~/.interlock/fail-mode.json`.

Tool names assumed from the docs: `bash` (`command`), `read` / `write` / `edit` (`filePath`), `webfetch`. To verify live: these names and argument keys, and that a thrown error reaches the model as a tool error.
