# Interlock threat model

What Interlock protects, against whom, where it can see, and where it can't. If something here is wrong or missing, please report it (see `SECURITY.md`).

## 1. What is being protected

| Asset | Example of harm |
|---|---|
| Source code and history | force-push over `main`, `git clean -fdx`, history rewrites |
| Secrets on the machine | `~/.ssh`, `~/.aws`, `.env`, tokens in the environment sent off the machine |
| The machine itself | `curl | sh`, persistence in shell rc files, cron, `authorized_keys`, sudoers |
| The agent's own guard rails | an agent editing its hooks, Interlock's policy, or its instruction files |
| Future sessions | injected instructions written into `AGENTS.md` / `CLAUDE.md` or an MCP memory server |

## 2. Adversaries and failure modes

1. **An over-eager or mistaken agent.** No attacker: the agent does more than the user asked (the most common case).
2. **Indirect prompt injection.** Instructions hidden in content the agent reads: a README, an issue, a web page, an MCP tool result, a tool *description*.
3. **A malicious or compromised MCP server.** Poisoned tool descriptions, definitions that change after approval ("rug pulls"), results carrying injections.
4. **A poisoned repository.** Instruction files or MCP configs committed by someone else.

Out of scope: an attacker who already runs code as your user outside the agent (they can edit anything Interlock can), a compromised OS, and content-safety concerns (toxicity, hallucination), which other tools address.

## 3. Where Interlock sees, and what it can do there

| Enforcement point | Sees | Can |
|---|---|---|
| Agent hooks (Claude Code, Codex, Kiro, Cursor, Gemini CLI, Copilot CLI, Windsurf, Antigravity) and the OpenCode plugin | every tool call the agent proposes, and tool results where the agent reports them | refuse before execution; ask; withhold or annotate results where the agent supports it (see `adapters/*/PAYLOADS.md`) |
| In-process SDK integrations (Strands, LangChain / LangGraph, OpenAI Agents SDK) | every tool call and result inside your agent | refuse; replace results |
| MCP gateway (stdio proxy, HTTP route in the daemon) | every MCP message between the agent and a wrapped server | hide poisoned or changed tools, refuse calls, withhold results |
| `interlock scan` / the GitHub Action | MCP and agent configs, committed instruction files | report before anything runs |

Decisions are made by the daemon from deterministic rules first; an optional local model only answers narrow questions on ambiguous cases. Hostile content (tool results, file contents) is only ever read by the injection probe, never by the intent question, so an injection cannot argue its way past the intent check.

## 4. Known limits and bypasses

Stated plainly, because a security tool that overstates its coverage is dangerous:

| Limit | Why | Mitigation |
|---|---|---|
| Only actions that pass through an enforcement point are gated | a process the agent already started, a second agent without hooks, or a tool the hook matcher doesn't cover is invisible to the hooks | install for every agent (`interlock init`); route MCP through the gateway; run the agent under `interlock sandbox`, which refuses persistence and guard-rail writes at the OS level whatever path they take; `doctor` and `scan` flag unprotected agents. `interlock sandbox --egress` confines the agent's network to localhost and routes it through `interlock egress-proxy` |
| The agent runs as your user | it can technically edit hook files, the policy, or the shim | Interlock refuses writes to agent configs and its own files; the daemon re-checks its hooks every minute and records a removed hook or a modified shim in the hash-chained audit log (`interlock report` lists them), and `interlock doctor` reports them (`interlock audit verify` checks the chain) |
| Default fail mode is open | a stopped daemon should not stop all work; without the daemon a hook cannot tell a dangerous call from a safe one | set `fail_mode.default: closed` to refuse every call while the daemon is down; wrapped remote MCP servers are unreachable without it; `doctor` reports calls that ran while the daemon was down |
| Shell analysis is static | commands assembled at runtime (strings built and executed later) can hide intent | constructs that build-and-execute (eval, decode-and-run, pipe to a shell) are themselves rules; ambiguous cases ask |
| Injection detection is heuristic | a novel phrasing can score below the threshold | multiple detectors compose deny-wins (local heuristics, optional classifier, Bedrock Guardrails, the judge); toxic-flow detection catches the dangerous *combination* even when one step is missed |
| Some agents can't replace a tool result | the hook contract doesn't allow it (Kiro, Windsurf, Antigravity, Cursor for non-MCP tools) | the detection is recorded and visible in `interlock log` / `report`; warnings are added where supported |
| A repository's own `.interlock/policy.yaml` is written by whoever commits to it | a poisoned repository could try to switch rules off | repository policies only tighten yours unless you list the repository in `trust.trusted_workspaces`; `policy lint --workspace` shows what was not applied |
| Shadow mode enforces nothing | it is the default so you can see decisions first | `interlock report` shows what enforce would have done; `interlock enforce` |
| Adapters built from documentation | contracts have differed from their docs before | adapters say "built, not verified live" until payloads are captured from the real tool |

## 5. Trust boundaries in the implementation

- The daemon listens on loopback TCP and on a Unix socket created with mode 0600; every API call needs the per-install bearer token (mode 0600, compared in constant time). The HTTP MCP gateway uses a per-install route secret instead, because the agent's own `Authorization` header goes to the real server.
- Nothing leaves the machine by default. Optional integrations send data only where you configure them: Amazon Bedrock Guardrails (tool results), a DynamoDB audit table, an OpenTelemetry collector (decision metadata only, never arguments or results).
- `interlock mcp` (the advisory MCP server) is read-only: it can make an agent more careful, never approve an action or change policy.
