# 0.1.8 shim fixtures

The hook shims as released in 0.1.8, copied byte for byte from `interlockd/shims/` at tag `v0.1.8`:

| file | installed for |
|---|---|
| `claude-code/interlock-hook.sh` | claude-code, codex, cursor, gemini-cli, copilot-cli, windsurf, antigravity |
| `py/interlock-hook.py` | the same harnesses plus kiro (hosts without sh + curl) |
| `kiro/interlock-hook.sh`, `kiro/interlock-hook.mjs` | kiro |
| `opencode/interlock.js` | opencode |

They are templates: `__HARNESS__` (and `__VERSION__` in the OpenCode plugin) are still in place. The tests render
them the way `interlock init` does, with `tests/shim_stub.py:install_shim`.

`recorded/<runtime>.json` holds what each fixture shim printed (exit code, stdout, stderr, hook.log) and sent
(path, adapter fields) for allow, ask, block, shadow and post-tool replies from `tests/shim_stub.py`'s stub daemon.
The reply bodies follow the 0.1.8 renderers. Temporary paths and addresses are replaced with `$HOME_DIR`, `$CWD`,
`$ROOT` and `$LISTEN`, and `$IDENTITY` stands for the home's identity value. Re-record with
`python tests/shim_stub.py record`. `scripts/check-hygiene.sh` rejects token-shaped values and real home paths here.
