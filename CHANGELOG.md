# Changelog

## 0.1.0 (2026-10-17)

First public release.

- `interlock init` / `uninstall`: one-command setup for Claude Code, Codex, and Kiro (verified live), plus Cursor and Gemini CLI (built from their documented hooks); background service (launchd, systemd user, or detached process); shadow mode by default.
- Pre-action gate: 48 deterministic rules in 6 packs (shell, git, egress, persistence, secrets, packages) with a shell decomposer.
- Post-action injection probe that runs locally (no cloud), withholding injected results in Claude Code.
- `interlock scan`: static audit of MCP servers and agent settings across Claude Code, Claude Desktop, Codex, Cursor, VS Code, Kiro, Gemini CLI, and Windsurf.
- `interlock report`, `doctor`, `status`, `log`, `enforce` / `shadow`, `test`.
- Optional: Cedar mandate, open-weights judge, Amazon Bedrock Guardrails as an extra detector, DynamoDB audit store.
