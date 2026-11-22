# Adapters

Harness documentation: measured hook payloads and adapter mappings. The hook shims themselves ship inside the package at `daemon/interlockd/shims/` so `interlock install` / `interlock init` work from an installed wheel.

## Tamper refusals (all shims)

This section is the shared reference for what every shim sends and emits when Interlock's own protection cannot be trusted. Each harness's `PAYLOADS.md` lists the exact output in that harness's format. Nothing here changes a harness's hook contract: refusals use the same channel as a policy block, and "no opinion" is the response the harness already treats as "no decision".

### Request: the `shim` field

Shims add their own absolute file path to the adapter block, so the daemon verifies the file that actually ran:

```json
{"adapter": {"name": "claude-code", "version": "0.2.0", "event": "pre", "cwd": "/work", "shim": "/Users/dev/.interlock/adapters/claude-code/interlock-hook.sh"}, "payload": {...}}
```

`shim` is optional. Shims from 0.1.x and SDK integrations omit it, and the daemon then checks the path recorded in the manifest.

### Reply: the `X-Interlock-Identity` header

Every daemon reply (hook routes in every format, `/interlock/v1/health`, control routes, and every error status including 401) carries exactly one `X-Interlock-Identity` header: 32 lowercase hex characters, also written to `<Home>/identity` (mode 0600) when the daemon starts. A shim applies a reply only when it has exactly one such header (name compared case-insensitively) and its value equals the first line of `<Home>/identity`. The value never appears in the shim's output or in `hook.log`. Shims from 0.1.x ignore the header, so their output is unchanged.

### Classification

Each shim classifies a call in this order:

| Condition | Outcome | Fail mode used |
|---|---|---|
| No `<Home>/token` | `inert: no token` (no request sent) | none: no opinion |
| `daemon.json` absent, connection refused, or timeout, with `stop-marker.json` valid and without expiry (`interlock stop`, `uninstall`) | `unjudged why=operator_stopped` | `fail_mode.default` |
| Same, with `expires_epoch` later than now (`restart`, `shadow`, `enforce`, `token --rotate`, `init`) | `unjudged why=restarting` | `fail_mode.default` |
| Same, with no marker, an expired marker, or an unparseable marker | `tamper daemon_lost` | `fail_mode.tamper` |
| HTTP 401 or 403 | `tamper token_rejected` | `fail_mode.tamper` |
| Any other HTTP status ≥ 400 | `unjudged why=http_<status>` | `fail_mode.default` |
| Identity header missing, duplicated, or not equal to `<Home>/identity` (including a missing `identity` file) | `tamper daemon_identity` | `fail_mode.tamper` |
| Otherwise | reply applied unchanged | none |

`fail_mode.tamper` and `fail_mode.default` come from `<Home>/fail-mode.json` (`"tamper": "open"|"closed"`, `"default": "open"|"closed"`). A missing file, missing key or invalid value means `tamper: closed` and `default: open`. `INTERLOCK_FAIL_MODE=closed` forces both to `closed`; any other value of the variable is ignored.

### Cause keywords

Every tamper refusal and every tamper `hook.log` line contains exactly one of these keywords, spelled verbatim:

| Keyword | Raised by | Repair command in the message |
|---|---|---|
| `token_rejected` | shim (401/403) | `interlock doctor` |
| `daemon_identity` | shim (identity check) | `interlock doctor` |
| `daemon_lost` | shim (unreachable, no valid marker) | `interlock doctor`, then `interlock start` |
| `enforcement_point` | daemon (shim or hook config modified, removed or relocated) | `interlock doctor`, then `interlock init` or `interlock ack` |

### Refusal messages

With `fail_mode.tamper: closed`, a pre-tool call is refused through the harness's block channel with one of these messages (`<addr>` is the address that answered, `<Home>` the Interlock home):

```
[interlock] This action was NOT executed: the process at <addr> rejected this hook's token (token_rejected). Run `interlock doctor`.
[interlock] This action was NOT executed: the process answering at <addr> is not this home's Interlock daemon (daemon_identity). Run `interlock doctor`.
[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly (daemon_lost). Home: <Home>. Run `interlock doctor`, then `interlock start`.
```

`enforcement_point` is not a shim-side outcome. The daemon is reachable and verified, so it returns an ordinary `block` verdict (enforce mode) rendered like any policy block, with this notice:

```
[interlock] Protection for <harness> is compromised (<reason>, enforcement_point). This action was NOT executed. Tell the user. To repair, the user runs `interlock doctor`, then `interlock init` to reinstall the hook or `interlock ack` to accept the change.
```

`<reason>` is one of `shim_modified`, `shim_missing`, `shim_relocated`, `hook_removed`. The notice text appears at most once per harness and reason per 60 s; the block itself is returned on every request. In shadow mode the verdict is unchanged and the notice (with "Interlock is in shadow mode, so this action was not stopped." in place of "This action was NOT executed.") reaches the agent only on Claude Code, as PreToolUse `additionalContext`; the other formats have no message channel without a decision, so the notice is omitted there (`SHADOW_NOTICE_HARNESSES` in `interlockd/render.py`).

With `fail_mode.tamper: open`, and on every post-tool call whatever the mode, the shim writes the `hook.log` line and returns the harness's no-opinion response: the tool has already run on post-tool calls, and the hook contracts offer no refusal there.

### `hook.log` lines

One line per outcome in `<Home>/hook.log`, space-separated `key=value` fields. No tool arguments, token, or identity value:

```
<ts> unjudged why=<operator_stopped|restarting|http_NNN|bad_reply|...> harness=<h> tool=<name|?> kind=<pre|post> addr=<base> [status=<NNN|->] fail_mode=<open|closed>
<ts> tamper token_rejected harness=<h> tool=<name|?> kind=<pre|post> addr=<base> status=<401|403> fail_mode=<open|closed>
<ts> tamper daemon_identity harness=<h> tool=<name|?> kind=<pre|post> addr=<base> status=<NNN> fail_mode=<open|closed>
<ts> tamper daemon_lost harness=<h> tool=<name|?> kind=<pre|post> addr=<base> status=- fail_mode=<open|closed>
<ts> inert: no token at <Home>/token
```

The `unjudged` reasons and the presence of `status=` vary slightly by shim; the first two words and the `tamper` cause are fixed, because the daemon's startup summary (`control.calls_unjudged`) groups lines by the second word and, for `tamper`, the third.

If `hook.log` cannot be written, the shim prints `[interlock] could not write <Home>/hook.log` to stderr and still applies the fail mode.

`interlock selftest --shim` and the shim subprocess tests (`tests/test_shim_*.py`, `tests/test_opencode.py`) check each harness's refusal against the "Tamper refusals" table in its `PAYLOADS.md`.
