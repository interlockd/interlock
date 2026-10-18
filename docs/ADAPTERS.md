# Writing an Interlock adapter

An adapter connects one agent (a "harness": Claude Code, Codex, Kiro, Cursor, ...) to the Interlock daemon. It is small by design: the harness calls a **shim** on every tool call, the shim forwards the raw payload to the daemon, the daemon **normalizes** it into an `InterlockEvent`, decides, and **renders** the verdict in the harness's own hook vocabulary. Shims stay dumb; all logic lives in the daemon, where it is tested.

```
harness hook ──stdin──▶ shim ──HTTP──▶ daemon: normalize → decide → render ──▶ shim ──stdout/exit──▶ harness
```

Every adapter is four pieces plus evidence:

| Piece | Where | What it does |
|---|---|---|
| Normalizer | `interlockd/normalize/<harness>.py` | Raw hook payload → `InterlockEvent` |
| Renderer | `interlockd/render.py` | `Verdict` → the exact stdout JSON / exit code the harness applies |
| Shim | `interlockd/shims/<harness>/` | POSIX `sh` + `curl`: read stdin, POST to the daemon, print the reply, apply the fail mode when the daemon is down |
| Installer + detection | `interlockd/cli.py`, `interlockd/onboard.py` | Write the harness's hook config; let `interlock init` find the harness |
| **Evidence** | `tests/fixtures/<harness>/*.json`, `adapters/<harness>/PAYLOADS.md` | Payloads **captured from the real tool**, and what you measured |

## 1. The normalized event (in)

```python
InterlockEvent(
    kind="pre_action" | "post_action",
    adapter=AdapterInfo(name="cursor", version="<shim version>"),
    identity=Identity(agent_id, agent_type="cursor", agent_workspace, agent_user),
    session_hint="<harness session id>",            # groups a session's calls
    tool_call=ToolCall(id="<call id>", name="<tool name>", arguments={...}),
    context=Context(cwd, user_messages=None,         # the daemon may read them from transcript_path
                    mcp_server={"name": ...} | None, permission_mode, transcript_path),
    result=ToolResult(content="<tool output as text>", evidence={...}) | None,   # post_action only
    capabilities=Capabilities(ask=..., rewrite=..., withhold=...),               # what the harness can render
)
```

Rules:

- **Tool names.** Map the harness's tool names onto the tier tables in `interlockd/tiers.py` (shell, read-only, in-workspace write, network, subagent). Unknown tools are gated, which is safe but noisy: add yours.
- **Arguments.** Keep the harness's argument keys; make sure the shell command lands in `command` and file paths in `path` / `file_path`, which the engine reads.
- **Capabilities are honest.** Set `ask`, `rewrite`, `withhold` only if you measured that the harness applies them. The composer degrades gracefully: `ask` becomes `block` with a notice, `withhold` becomes `warn`.
- **Never read agent prose into user messages.** Only the user's own words go in `user_messages`; the intent judge's injection defense depends on it.

## 2. The verdict (out)

The daemon returns a `Verdict` with `disposition` in `allow | ask | block` (pre-action) or `pass | warn | withhold` (post-action), plus `notice` (the text to show the agent), `reason`, and `findings`. The renderer turns it into the harness's contract. Two rules:

- **Interlock never emits "allow"** in a form that skips the harness's own permission prompt. An empty reply means "no opinion": the harness's normal behaviour applies.
- **Shadow mode renders nothing.** Decisions are recorded, the harness is untouched.

## 3. The shim

Copy `interlockd/shims/claude-code/interlock-hook.sh` as a template. It must:

- read the token from `~/.interlock/token` (exit 0 silently if missing: an uninstalled Interlock must never break the agent);
- POST `{"adapter": {...}, "payload": <raw stdin>}` to `/interlock/v1/hooks/<harness>?format=<renderer>` with the bearer token and a short timeout (pre 1.5 s, post 2.5 s);
- print the daemon's reply verbatim and exit with the code the harness expects;
- when the daemon does not answer, apply `~/.interlock/fail-mode.json` locally (closed categories block, the rest pass) and log one line to `~/.interlock/hook.log`.

## 4. Evidence: capture before you claim

Documented hook contracts have been wrong in practice: Claude Code ignores a documented placement of `updatedToolOutput`, and a bare string there is silently dropped. So:

1. Install a capture hook that tees stdin to a file and forwards to the shim (see `adapters/claude-code/PAYLOADS.md` for the method).
2. Drive the real tool headless with one benign call, one call a default rule blocks, and one tool result carrying an injection.
3. Save the redacted payloads to `tests/fixtures/<harness>/{pre,post}-<tool>-{benign,block,inject}.json`. `test_live_captured_payloads` replays every fixture through the API and checks the rendered reply.
4. Write `adapters/<harness>/PAYLOADS.md`: version measured, input keys per event, the output forms you verified, and anything that differed from the docs.

An adapter is **verified** only when block (and withhold, if claimed) has been observed working in the real tool. Until then it is **built**, and docs and `interlock init` say so.

## 5. Checklist for a pull request

- [ ] Normalizer + unit tests for each event the harness sends
- [ ] Renderer for each disposition the harness supports
- [ ] Shim with fail-mode handling
- [ ] `interlock install --<harness>` and detection in `interlock init` / `doctor` / `scan`
- [ ] Captured fixtures and `PAYLOADS.md` (or the adapter is marked "built, not verified")
- [ ] `ruff check .`, `pytest -q`, `interlock test` green
