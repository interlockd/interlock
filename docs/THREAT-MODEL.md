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
| The agent runs as your user | it can technically edit hook files, the policy, the token, or the shim, and run `interlock` itself | Interlock refuses writes to agent configs and its own files and asks before an agent runs `interlock` commands that lower protection; the daemon verifies the calling agent's shim and hook on every request and everything else every 10 s, blocks the agent whose enforcement point changed, keeps enforcing the pinned policy and token, and records each change in the hash-chained audit log (§5). This makes tampering visible and consequential, not impossible |
| Default fail mode is open | a stopped daemon should not stop all work; without the daemon a hook cannot tell a dangerous call from a safe one | the open default covers only explained outages (`interlock stop`, a restart in progress, an HTTP error); a rejected token, a reply from the wrong daemon, or a daemon that disappeared without `interlock stop` use `fail_mode.tamper`, closed by default (§5). Set `fail_mode.default: closed` to refuse every call while the daemon is down for any reason; wrapped remote MCP servers are unreachable without it; `doctor` reports calls that ran while the daemon was down |
| Shell analysis is static | commands assembled at runtime (strings built and executed later) can hide intent | constructs that build-and-execute (eval, decode-and-run, pipe to a shell) are themselves rules; ambiguous cases ask |
| Injection detection is heuristic | a novel phrasing can score below the threshold | multiple detectors compose deny-wins (local heuristics, optional classifier, Bedrock Guardrails, the judge); toxic-flow detection catches the dangerous *combination* even when one step is missed |
| Some agents can't replace a tool result | the hook contract doesn't allow it (Kiro, Windsurf, Antigravity, Cursor for non-MCP tools) | the detection is recorded and visible in `interlock log` / `report`; warnings are added where supported |
| A repository's own `.interlock/policy.yaml` is written by whoever commits to it | a poisoned repository could try to switch rules off | repository policies only tighten yours unless you list the repository in `trust.trusted_workspaces`; `policy lint --workspace` shows what was not applied |
| Shadow mode enforces nothing | it is the default so you can see decisions first | `interlock report` shows what enforce would have done; `interlock enforce` |
| Adapters built from documentation | contracts have differed from their docs before | adapters say "built, not verified live" until payloads are captured from the real tool |

## 5. Tamper detection

The gate is only as good as the hook, shim, token, policy and daemon that `interlock init` installed. Issue #29 showed the failure this section is about: a second daemon on port 7391 rejected the real home's token, the shim read the rejection as "daemon down", `fail_mode.default: open` let every call through, and nothing told the user. The user guide (§2.2) describes the behaviour; this section states what it defends against and what it does not.

**Daemon identity.** At each start the daemon derives a 128-bit value, HMAC-SHA256 keyed by sha256 of the home's token over a fresh random nonce, writes it to `<home>/identity` (mode 0600) and sends it in an `X-Interlock-Identity` header on every reply, error replies included. The shim compares the header with the file by string equality; a reply without exactly one matching header is refused as `daemon_identity` under `fail_mode.tamper`. A 401 or 403 from whatever listens on the address is `token_rejected`, also under `fail_mode.tamper`.

| The identity defeats | It does not defeat |
|---|---|
| a daemon serving another Interlock home on the same port (#29) | a process running as you, which can read `<home>/identity` as easily as `<home>/token` (both 0600, same owner) and answer with it |
| a stale daemon from another install, or one from before the upgrade | a process with root, or one that controls your agent's process or environment |
| any other process listening on 7391 without this home's token | |
| a reply relayed from the wrong daemon through `INTERLOCK_URL` or the Unix socket | |

The value reveals neither the token nor the home path, and a value from one home does not verify for another. Against the same-user process in the right-hand column the defences are the ones the rest of this document lists. An agent's writes to Interlock's files are refused (`persistence.agent_config_write`). Its reads of the token and the identity are sensitive-path reads (`secrets.read_sensitive_path`), which go to the judge by default and are allowed and recorded without one; override that rule to `ask` or `block` to refuse them. `interlock sandbox` makes `<home>` (except `hook.log`) read-only for the agent at the OS level, but it cannot hide the token or the identity: the shim runs in the agent's own process tree and has to read both, so whatever the shim can read, code the agent runs outside the hooks can read too.

**Stop versus loss.** `interlock stop` and `uninstall` write `<home>/stop-marker.json` before signalling the daemon; `restart`, `shadow`, `enforce`, `token --rotate` and an `init` that restarts the daemon write one that expires after 120 s. A shim that cannot reach the daemon applies `fail_mode.default` only when a valid marker explains the outage; otherwise it is `daemon_lost` under `fail_mode.tamper`. The daemon removes the marker at start, writes a clean-exit mark into `daemon.json` on SIGTERM / SIGINT, and records `control.daemon_unexpected_exit` and a `control.calls_unjudged` summary when the previous run ended without either. Limit: a process running as you can write a marker, or kill the daemon inside a restart's 120 s window, and its outage then reads as expected. Outside such a window, a forced kill (SIGKILL) leaves no clean-exit mark and is recorded at the next start.

**Enforcement points.** The calling agent's shim (digest) and hook config entry are checked on every hook request; all of them, the token and the policy every 10 s. The shim reports its own path, so a hook config pointing at a copy elsewhere is `shim_relocated`. A changed shim is rewritten from the installed package; a changed hook config is reported, never edited. While an agent's enforcement point is `compromised`, every pre-tool call from that agent is blocked in enforce mode until the operator runs `interlock init` or `interlock ack`. Limits: the 10 s pass is a window for files that are not on the request path; an edit confined to a shim's version line is accepted as an upgrade leftover; on Windows, where a file's change time can't be read, an in-place edit that restores the file's size and modification time is caught by the 10 s pass, not the per-request check; an agent whose hook was removed sends no requests, so it is caught by the watch (and `status`, `doctor`), not by the per-request check.

**Policy and token pinning.** The integrity baseline (`<home>/integrity-baseline.json`) holds the sha256 of `policy.yaml`, `managed-policy.yaml` and the token, and the token's mode; `<home>/pinned/` holds byte-identical copies of the two policy files. An unexplained policy change is reported once per distinct digest, with the top-level key names that changed and never their values, and the daemon keeps enforcing the pinned copy: an agent that slips `mode: shadow` or `fail_mode: {tamper: open}` into the file changes nothing until the operator runs `interlock policy accept` (or `ack`). With no usable pinned copy at start, the daemon refuses every pre-tool call until the policy is accepted or reverted. A token whose mode widens is restored to owner-only; a replaced or deleted token is reported and the daemon keeps accepting the one it loaded. Limits: repository policies (`<repo>/.interlock/policy.yaml`) are not pinned, so a trusted workspace (`trust.trusted_workspaces`) can still loosen decisions; `fail_mode.tamper` is mirrored to `<home>/fail-mode.json` for the shims, and a change to that file alone is not detected until the daemon rewrites it at its next start (an agent's write to it is refused like any write under `<home>`; `INTERLOCK_FAIL_MODE=closed` can override the file from the environment, and only to tighten).

**Operator actions.** The operator and the agent are the same OS user, so Interlock tells them apart by how a change arrives: each state-changing `interlock` command records a `control.operator_action` first (through the daemon, or straight into the audit log when it is down), and a change explained by a matching action in the preceding 120 s raises nothing. Limit: a process running as you can run those commands, or append such a record, too. Two things narrow this. `persistence.interlock_control` asks before an agent runs `interlock ack`, `shadow`, `stop`, `restart`, `uninstall`, `policy accept`, `policy revert`, `token --rotate` or `resume` through its shell, and an action the user approved that way is marked `via: hook_session`. And every action, approved or not, stays in the hash-chained log, where `interlock audit verify` reports a removed or edited record.

**What the records contain.** Tamper events, operator actions and protection-state changes are `control` records in the existing schema: Interlock's own file paths and hook config paths, digests, fixed reason codes and timestamps; never tool arguments, file contents, token values or policy text. The plugin API and the OpenTelemetry export see the tamper kind and the protection state only. The unauthenticated health endpoint (loopback only) now also lists agent names, reason codes and policy digests.

## 6. Trust boundaries in the implementation

- The daemon listens on loopback TCP and on a Unix socket created with mode 0600; every API call needs the per-install bearer token (mode 0600, compared in constant time). The HTTP MCP gateway uses a per-install route secret instead, because the agent's own `Authorization` header goes to the real server.
- Every reply carries the daemon identity (`<home>/identity`, mode 0600, rewritten at each start), and the shims apply only replies that carry this home's value. The CLI's operator-action and acknowledgement routes are bearer-authenticated like the rest of the API; no new listening socket or route reachable from outside the machine was added.
- Nothing leaves the machine by default. Optional integrations send data only where you configure them: Amazon Bedrock Guardrails (tool results), a DynamoDB audit table, an OpenTelemetry collector (decision metadata only, never arguments or results).
- `interlock mcp` (the advisory MCP server) is read-only: it can make an agent more careful, never approve an action or change policy.
