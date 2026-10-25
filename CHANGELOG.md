# Changelog

## Unreleased

- Releases publish `@interlockd/sdk` to npm from the release workflow with npm trusted publishing (no stored token) and npm provenance; the release checks that the tag matches the JS SDK's version too.

## 0.1.5 (2026-10-24)

- Plugin API: `interlockd.plugin_api` (version 1) is the stable interface for plugins (settings, policy validation, the managed policy, daemon status, hook integrity, audit records without tool content), covered by contract tests. A plugin can require a newer API with `PLUGIN_API = <n>`; an older interlockd skips it with a message. `interlock plugins` shows the API version.
- `examples/aws/interlock-audit.yaml`: a CloudFormation sample for the optional DynamoDB audit table (it keeps the table, and your audit records, if the stack is deleted); the user guide links it.

## 0.1.4 (2026-10-24)

- Windsurf adapter verified live on Windsurf (Devin.app) 3.10.67: a refused force push, an injected README refused before Cascade read it, and a `cat` of it refused (`flow.reread_withheld`). Windsurf's read hooks carry no contents, so the daemon reads the file itself (256 KiB, never a sensitive path). Fixed live: Windsurf sends `cwd: null`, so a repository policy never applied; the hook's own directory is used now. Windsurf runs each hook twice; the repeat is answered from the first decision.
- `interlock capture` pairs Windsurf's calls with their results (its report showed a false "block held: no").
- Contributing: pull requests are reviewed and merged in this repository, with a DCO sign-off on each commit (`git commit -s`, checked in CI); CI also runs `scripts/check-hygiene.sh`, which keeps real home paths, account ids and keys out of the repository.

## 0.1.3 (2026-10-24)

- **Security fix (macOS, Windows):** path rules now match without case where the file system ignores it. On macOS (default APFS) a write to `~/.CLAUDE/settings.json`, `.GIT/hooks/pre-commit` or `.GitHub/Workflows/ci.yml` changes the real file but was allowed. Linux is unchanged.
- Native Windows, first part: the daemon (`interlock start | stop | status`, a detached background process), policy, audit log, `scan`, `report`, `explain`, `test` and the Python and JavaScript SDKs run on Windows without WSL2. Paths are matched the same way on every OS (`C:\Users\me\.claude\settings.json` hits the same rules as `~/.claude/settings.json`), and the Startup folder and PowerShell profiles count as persistence. Agent hooks, `interlock init`, the gateway, the sandbox and the local judge still need macOS or Linux (on Windows, WSL2); those commands say so. Verified on a Windows CI runner: the full test suite, and a live daemon (start, decisions through the Python client, `audit verify`, stop).
- Gemini CLI adapter verified live on Gemini CLI 0.65.0: a refused force push and a withheld injected README; captured payloads replayed in tests.
- Withheld content can't be read back another way: the local probe also scores ROT13 and base64 decodings of each tool result, and once a file is withheld, a shell call naming it in the same session asks (`flow.reread_withheld`). Found live: Gemini CLI re-read a withheld README through ROT13 "without triggering policy".
- `interlock capture`: `--scratch` projects push nowhere; for agents that send no tool-call id (Gemini CLI), the report pairs a refused call with a later result by session and input.
- Text files are read and written as UTF-8 on every platform.

## 0.1.2 (2026-10-24)

- Managed policy: `<interlock home>/managed-policy.yaml` is applied last and can only tighten decisions (it can switch enforce on, never loosen anything). It is reloaded without a restart; a file that doesn't parse is ignored and reported by `interlock policy lint`. For device management and centrally managed machines.
- Plugins: installed packages that register under the `interlockd.plugins` entry-point group can add commands and run background work beside `interlock serve`. Plugins never sit in the decision path; a plugin that fails is skipped with a warning. `interlock plugins` lists them; `INTERLOCK_PLUGINS=0` turns them off.
- Platforms stated: macOS and Linux; on Windows, `interlock` explains how to use WSL2 instead of crashing on import. Homebrew: `brew install interlockd/tap/interlock`.
- `interlock judge install | status | remove`: run the optional judge model (Strands Decider 2B) locally in one step. The daemon starts it in the background instead of delaying startup.
- Contributing: pull requests are imported into the development repository with author credit (`CONTRIBUTING.md`); a code of conduct; `demo/demo.sh` (and a VHS tape) for a self-contained recording.
- `@interlockd/sdk` for JavaScript and TypeScript agents (`sdk/js`, no dependencies): `guardTools` for the Vercel AI SDK, Mastra and any `{ execute }` tool map, and `guardOptions` for the Claude Agent SDK for TypeScript. Both verified with the real packages.
- Injection detector, measured on public benchmarks (`docs/BENCHMARKS.md`, scripts in `benchmarks/`): catches AgentDojo's leaderboard template (0% -> 100%), InjecAgent's enhanced attacks (37% -> 97% on the harm set), typo'd "ignore your previous ..." and `###(system_message)` markers. False positives on real documentation fell from 2.2% to 0.25% ("bypass the X policy" and "silently skipped" no longer count).
- `shred <file>` is an irreversible delete (asked or recorded like `rm -rf`), no longer blocked as a disk wipe; `shred /dev/...` still is.
- Releases carry signed build provenance (`gh attestation verify`), and the release workflow regenerates the Homebrew formula and commits it to `interlockd/homebrew-tap` when a tap token is configured.
- `interlock capture`: record the real hook payloads an agent sends (with Interlock's replies), check that blocks held, and export redacted fixtures. `--scratch` sets up a verification project. Verified live with Claude Code.
- Cedar mandate: shell egress (`curl`, `wget`, ...) now binds to `net.egress` with its hosts, like fetch tools (it was reported unjudged). With `mandate.mode: enforce`, a mandate without a `net.egress` permit now refuses shell egress; `docs/mandate-example.cedar` shows a host allowlist. Enforce mode verified live through the hook shim.
- MCP OAuth checks in the HTTP gateway: a JWT issued for another service is never passed to an MCP server (audience binding), scopes in `mcp.oauth.deny_scopes` are refused, administrative scopes are flagged, and each server's authorization servers are pinned on first use so a change is refused until `interlock mcp-pins --accept`.

## 0.1.1 (2026-10-18)

- Google ADK and CrewAI integrations.
- Semantic Kernel integration (`guard_kernel`): a function-invocation filter, tested through a real Kernel.
- Claude Agent SDK integration (`guard_options`): in-process PreToolUse / PostToolUse hooks, verified live (a refused force-push, a withheld injected README).
- `interlock pause` / `resume` kill switch.
- Linux sandbox (bubblewrap) verified in CI.
- Repository policies: a committed `<repo>/.interlock/policy.yaml` applies to every call inside the repository, re-read on change. It can only tighten your policy unless you list the repository in `trust.trusted_workspaces`; `interlock policy lint --workspace <repo>` shows what was not applied.
- Hook watch: the daemon re-checks the hooks it installed every minute and records a removed hook or a modified shim (and the repair) in the audit chain; `interlock report` lists them. Shims left by an upgrade are refreshed instead of flagged.
- `interlock bench`: decision, probe, HTTP and hook-shim latency on your machine; see `docs/PERFORMANCE.md`.
- Faster audit writes: the hash chain's head is cached between appends instead of re-read; decision p50 4.2 ms -> 1.2 ms.
- `interlock doctor` reports when a newer release is on PyPI (`INTERLOCK_NO_UPDATE_CHECK=1` turns it off).
- Docs: the hooks apply `fail_mode.default` while the daemon is down (the per-category entries had been described as applying too).

## 0.1.0 (2026-10-17)

First public release.

- `interlock init` / `uninstall`: one-command setup for Claude Code, Codex, Kiro, Cursor, and GitHub Copilot CLI (verified live), plus Gemini CLI, Windsurf, Antigravity CLI, and OpenCode (built from their documented hooks and plugin API); background service (launchd, systemd user, or detached process); shadow mode by default.
- Pre-action gate: 48 deterministic rules in 6 packs (shell, git, egress, persistence, secrets, packages) with a shell decomposer.
- Post-action injection probe that runs locally (no cloud), withholding injected results in Claude Code.
- Custom agents: `interlockd.integrations.strands.InterlockHooks`, `interlockd.integrations.langchain.guard_tools`, and `interlockd.integrations.openai_agents.guard_agent_tools`.
- MCP gateway: `interlock gateway wrap | unwrap | status` routes stdio MCP servers through `interlock mcp-proxy` and remote (Streamable HTTP) servers through the daemon, which pins tool definitions (rug-pull detection), hides poisoned tools, gates tool calls with the same rules as the agent's own shell, and withholds injected results.
- `interlock mcp`: Interlock as an MCP server with read-only advisory tools (`check_action`, `explain_decision`, `recent_decisions`, `scan_mcp_servers`, `interlock_status`, `suggest_rule_override`); `interlock init --mcp` registers it.
- Codex: injected tool results are withheld (`decision: block`, measured live).
- Memory-poisoning protection: writes to agent instruction files (CLAUDE.md, AGENTS.md, ...) and MCP memory tools are recorded, and asked when the content reads as injected or the session took in untrusted content.
- `interlock pause` / `resume`: a kill switch that refuses every agent action (all or named agents, optionally timed), in any mode.
- `interlock egress-proxy`: decides every outbound host (metadata endpoints refused; `--strict` allowlist); `interlock sandbox --egress` makes it the agent's only way out.
- `interlock sandbox -- <agent>`: OS-level sandbox (macOS seatbelt; Linux bubblewrap) refusing persistence and guard-rail writes, with optional secret-read and network limits.
- Packaging: published on PyPI as `interlockd` (the command is still `interlock`) via a trusted-publishing release workflow, and a Homebrew formula generator for `interlockd/homebrew-tap`.
- `interlock replay`: re-decide recorded calls with your current policy and see what would change.
- `interlock policy lint`: unknown rule ids (a typo in an override silently does nothing), weakened critical rules, catch-all allows.
- `interlock selftest`: attack shapes through the live daemon in each agent's hook format; run by `init`.
- `interlock explain`: why a call was stopped, in plain language, with the override snippet.
- OpenTelemetry: one span per decision to any OTLP/HTTP collector (`otlp_endpoint` in config), and `interlock otel export` to backfill.
- `interlock aibom`: CycloneDX 1.6 AI bill of materials for the agent stack (agents, models, MCP servers with package URLs and pinning, remote endpoints).
- Hardening: the daemon also listens on a 0600 Unix socket that the hooks prefer; `interlock token --rotate`.
- Tamper-evident audit log: hash-chained records, `interlock audit verify` and `audit head`.
- `interlock scan`: static audit of MCP servers and agent settings across Claude Code, Claude Desktop, Codex, Cursor, VS Code, Kiro, Gemini CLI, and Windsurf.
- `interlock report`, `doctor`, `status`, `log`, `enforce` / `shadow`, `test`.
- Optional: Cedar mandate, open-weights judge, Amazon Bedrock Guardrails as an extra detector, DynamoDB audit store.
