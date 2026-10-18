# Changelog

## 0.1.1 (unreleased)

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
