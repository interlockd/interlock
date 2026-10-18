# Interlock user guide

Interlock is a pre-action and post-action interlock for coding agents. It sits between an agent's plan and its tools: every tool call the agent proposes is checked before it runs, tool results can be checked before the agent reads them, and every decision is recorded with its reason. It runs as a small daemon on your machine and plugs into agent harnesses through their own hook systems. Nothing leaves your machine unless you opt into a cloud detector or the DynamoDB audit store.

This guide covers what Interlock does today and how to run it. It grows with the project; the change log at the end records what was added when. Paths are relative to the directory that holds `pyproject.toml`.

## 1. What Interlock does

**Gates tool calls.** When the agent is about to run a shell command, edit a file, push to git, fetch a URL, or call an MCP tool, the harness hands the call to Interlock first. Interlock answers one of three ways:

| Disposition | What happens |
|---|---|
| `allow` | The tool runs. Nothing is shown to the agent. The harness's own permission rules still apply. |
| `ask` | The tool does not run until the user confirms. On harnesses with a native confirmation prompt (Claude Code) the prompt appears; on harnesses without one (Kiro) the agent receives a notice telling it to ask the user and retry only after confirmation. |
| `block` | The tool does not run. The agent receives a notice saying what was refused, that it did not execute, what it may do instead, and that it must not retry in a disguised form. The session continues. |

**Probes tool results.** After a tool runs, its output can be checked before the agent acts on it. Today this finds credentials in output (`pass` / `warn`); injected-instruction detection arrives with the judge (M2).

**Records everything.** Every decision is written to a local spool the moment it is made (durable before the verdict is returned), then drained in the background to DynamoDB. The record carries the tool call, the findings, the disposition, the policy hash, timing, and the session and turn it belonged to, so any verdict can be explained and replayed later.

**Fails the way you choose.** If the daemon is unreachable, each harness hook applies a local fail mode: `open` (the tool runs, the miss is logged to `~/.interlock/hook.log`) or `closed` (the tool is refused until the daemon is back). The default is open for everything except the dangerous categories (exfiltration, malicious commands, persistence, secret leaks, privilege escalation), which are closed.

### How a decision is made

1. **Tier routing.** Read-only tools (file reads, searches, harness-internal tools) are allowed immediately. Writes inside the workspace run only the secrets and persistence checks. Everything else (shell, git, network, deletes, writes outside the workspace, MCP tools, subagents) is gated. Reads of sensitive paths (`~/.ssh`, `~/.aws`, `.env`, keys) are promoted to gated.
2. **Deterministic packs.** Gated calls are decomposed (shell chains, pipes, subshells, interpreter one-liners, heredocs, base64 payloads; commit messages and echoed text are treated as data) and checked by six rule packs: shell, git, egress, persistence, secrets, packages. Each rule has a category, a severity, and a default action your policy can override. Rules never guess: a command that cannot be judged (no package manifest to compare against, a mandate action with no binding) is reported as unjudged, not silently allowed.
3. **Mandate.** An optional Cedar policy expresses what the agent is authorized to do (which remotes, which branches, which capabilities, how many destructive operations per session). Denials become findings.
4. **Composition.** The strongest action wins (`block` > `ask` > `model` > `flag` > `allow`). A denial budget escalates to the user after 3 consecutive or 20 total denials in a session.
5. **Judge.** Rules routed to `model` are decided by a decision model (Strands Decider 2B) answering "did the user authorize this action?" when a judge backend is configured; without one they are recorded as unjudged.
6. **Post-action probe.** Tool results are checked for instructions addressed to the agent. The **local probe** (heuristics, plus an optional classifier such as PromptGuard 2) is on by default and needs no AWS or network. Amazon Bedrock Guardrails (`judge.probe.enabled`) and the judge's `injection_present` are optional extra detectors. All detectors compose deny-wins: the strongest signal sets `warn` or `withhold`.

### Shadow and enforce

A new install runs in **shadow** mode: every decision is computed and recorded, nothing is enforced. Run that way for a few days, review `interlock log`, fix false positives with policy overrides, then switch to **enforce**. Shadow mode is also how the benign corpus gets built.

## 2. Install and run

Prerequisites: Python 3.12 or newer, `curl`, and at least one supported agent (Claude Code, Codex, or Kiro; §4).

```sh
pipx install interlock          # or: uv tool install interlock
interlock init                  # detect agents, install hooks, write a starter policy, start the daemon
interlock log -f                # watch decisions live
```

`init` prints every change before making it and asks once (`--yes` skips the prompt). It:

- creates `~/.interlock/` with a per-install bearer token (mode 0600; hooks send it and the daemon requires it, even on loopback), the fail-mode table the hooks use when the daemon is down, and a commented starter policy in **shadow** mode;
- adds Interlock's hooks to every supported agent it finds: user-level for Claude Code (`~/.claude/settings.json`), Codex (`~/.codex/hooks.json`), Cursor (`~/.cursor/hooks.json`), Gemini CLI (`~/.gemini/settings.json`), GitHub Copilot CLI (`~/.copilot/hooks/interlock.json`), Windsurf (`~/.codeium/windsurf/hooks.json`), and Antigravity CLI (`~/.gemini/config/hooks.json`), and the Kiro workspace you run it from (`.kiro/hooks/interlock.json`). Your existing hooks and settings are preserved;
- installs and starts a background service: launchd on macOS, a systemd user unit on Linux, or a detached process elsewhere (`--backend`), logging to `~/.interlock/interlockd.log`;
- shows what the gate would decide for a few sample commands, without running them.

Everything `init` changed is recorded in `~/.interlock/install-manifest.json`; `interlock uninstall` reverses exactly that (`--purge` also deletes `~/.interlock`). Options: `--harness claude-code,codex,cursor,gemini-cli,kiro` for a subset, `--enforce` to start enforcing, `--no-service` to run the daemon yourself with `interlock serve`, `--mcp` to also register the Interlock MCP server with each agent, `--gateway` to route MCP servers through the MCP gateway (§2.1).

Codex asks you to trust new hooks: open Codex and run `/hooks` once. Kiro reads hooks per workspace: run `interlock install --kiro --workspace-root <folder Kiro has open>` for other workspaces.

From a source checkout instead: `uv venv --python 3.12 && uv pip install -e ".[dev]" --python .venv/bin/python`, then use `.venv/bin/interlock`.

### Sandboxing an agent (`interlock sandbox`)

Hooks see what an agent reports. To also hold the line at the OS level, start the agent inside a sandbox:

```sh
interlock sandbox -- claude                       # or codex, cursor-agent, copilot, ...
interlock sandbox --deny-secret-reads --local-network-only -- my-agent
```

Writes are refused to shell startup files, `~/.ssh`, `~/.gitconfig`, LaunchAgents / autostart / systemd user units, and `~/.interlock` (its hook log stays writable), whatever path the write takes. Options: `--deny-secret-reads` (private keys, cloud and registry credentials; breaks git over SSH), `--local-network-only` (outbound to localhost only, so the daemon stays reachable), `--protect PATH` (more read-only paths), `--protect-agent-configs` (agents' own config files; off by default because agents such as Claude Code rewrite theirs at startup). macOS uses `sandbox-exec` (verified live with Claude Code); Linux uses `bubblewrap` (built; not yet run on Linux).

### 2.0 Custom agents (Strands, LangChain / LangGraph, OpenAI Agents SDK)

Agents you build yourself have no hook file; use the in-process integrations. Both talk to the same local daemon, policy, and audit log as the hooks:

```python
# Strands Agents   (pip install 'interlock[strands]')
from interlockd.integrations.strands import InterlockHooks
agent = Agent(tools=[...], hooks=[InterlockHooks()])

# LangChain / LangGraph   (pip install 'interlock[langchain]')
from interlockd.integrations.langchain import guard_tools
agent = create_react_agent(model, guard_tools([search, shell]))

# OpenAI Agents SDK   (pip install 'interlock[openai-agents]'): uses the SDK's own tool guardrails
from interlockd.integrations.openai_agents import guard_agent_tools
agent = guard_agent_tools(Agent(name="dev", tools=[shell, search]))
```

A refused call never runs: Strands receives Interlock's notice as a cancelled tool result, LangChain as the tool's output, the OpenAI Agents SDK through `reject_content`. An injected result is replaced by the notice. Tools you name freely (`run_command`, `exec`, ...) still get the shell rules when they take a `command` argument. Any other framework can call `interlockd.integrations.client.InterlockClient().decide(...)` directly.

### 2.1 The MCP gateway

Hooks see the tool calls an agent makes; the MCP gateway sees every MCP server the agent talks to, whether or not the agent has hooks. `interlock gateway wrap` (or `interlock init --gateway`) changes each stdio server entry so the agent launches `interlock mcp-proxy` in its place, which starts the real server and relays its messages:

| What passes through | What the gateway does |
|---|---|
| The server's tool list | Pins each tool's definition (name, description, input schema) the first time it is seen. A tool whose definition later changes (a "rug pull") or whose description tries to instruct the model ("tool poisoning": `<IMPORTANT>` blocks, instructions to read secrets, rules about other tools) is hidden in enforce mode and logged in shadow mode |
| Each tool call | Decided by the daemon like any other tool call, including the shell rules for terminal-style tools that take a `command`. A refusal is returned to the agent as a tool error and never reaches the server |
| Each tool result | Run through the injection probe; a withhold replaces the content with a notice |

Log: `~/.interlock/mcp-proxy.log`. Pins: `~/.interlock/mcp-pins.json`; after reviewing a legitimate change, `interlock mcp-pins --accept <server>`. Covered automatically: Claude Code (user scope via `claude mcp`, project `.mcp.json`), Claude Desktop, Cursor, VS Code, Kiro, Gemini CLI, Windsurf. Codex: `~/.codex/config.toml` is edited by rewriting only `command` and `args` in each `[mcp_servers.<name>]` table, and the result is re-parsed and compared before anything is written (inline-table entries are reported, not touched; unwrap restores the values, though those two lines may be laid out differently). Remote (Streamable HTTP) servers go through the daemon itself: `wrap` changes their `url` to `http://127.0.0.1:7391/mcp/<name>/<secret>` and records the real URL in `~/.interlock/gateway-routes.json` (mode 0600); the path secret stands in for the daemon token because the agent's own `Authorization` header is passed to the real server. The same pins, tool hiding, call decisions, and result checks apply to JSON and streaming (SSE) responses. While the daemon is down, wrapped remote servers are unreachable (fail closed). Remote servers in Codex's TOML are reported for manual setup. Restart your agents after wrapping.

### Daemon configuration (`~/.interlock/config.json`)

```json
{
  "workspace_roots": ["/path/to/folder-kiro-has-open"],
  "dynamodb_table": "interlock-audit",
  "aws_region": "us-east-1",
  "aws_profile": "your-profile"
}
```

`otlp_endpoint` (e.g. `http://localhost:4318/v1/traces`) and `otlp_headers` send one OpenTelemetry span per decision to your collector (OTLP/HTTP JSON, batched in the background; a session is one trace; attributes follow the GenAI conventions plus `interlock.*`; arguments and results are never exported). `interlock otel export --endpoint URL` backfills from the audit log. The daemon also serves the API on `~/.interlock/interlockd.sock`, created with mode 0600 so only your user can connect; the shell hooks prefer it over loopback TCP (`"unix_socket": false` turns it off; TCP stays for the HTTP MCP gateway and the Python clients). All keys are optional, and `init` writes none of them. Without `dynamodb_table` the daemon runs spool-only (fully functional; records stay in `~/.interlock/spool/`). Other keys: `listen`, `mode`, `agent_id`, `kiro_sessions_dir`, `user_messages_n`, `pre_timeout_ms`, `post_timeout_ms`.

### CLI

| Command | What it does |
|---|---|
| `interlock init [--yes] [--harness H,...] [--enforce] [--no-service] [--backend B]` | One-command setup (above). Idempotent. |
| `interlock uninstall [--yes] [--purge]` | Remove hooks and the service; `--purge` also deletes `~/.interlock`. |
| `interlock start \| stop \| restart \| status` | Manage the background daemon; `status` shows service, mode, policy, and hooks. |
| `interlock enforce \| shadow` | Switch mode in `~/.interlock/policy.yaml` (comments kept) and restart the daemon. Warns if a workspace policy sets its own mode. |
| `interlock report [--days N] [--json]` | What the gate decided: what enforce would have blocked or asked in shadow mode, what was enforced, top rules, recent stops, latency. |
| `interlock scan [--project P] [--json] [--all] [--fail-on high\|medium\|low\|never]` | Static audit of the MCP servers and agent settings on this machine (no daemon, no network, secret values never printed): unpinned `npx`/`uvx`/docker packages, plain-HTTP remotes, inline secrets, filesystem roots at `/` or `~`, inline shell servers, auto-approved tools, permission-bypass modes, agents Interlock is not protecting, and committed agent instruction files (AGENTS.md, CLAUDE.md, `.cursor/rules/`, ...) that carry injected instructions or invisible Unicode. Reads Claude Code, Claude Desktop, Codex, Cursor, VS Code, Kiro, Gemini CLI, and Windsurf configs. Exits 1 at or above `--fail-on` (default `high`), so it can gate CI. |
| `interlock gateway wrap \| unwrap \| status [--dry-run]` | Route every stdio MCP server through the MCP gateway (§2.1). `wrap` rewrites each server's launch command (original kept after `--`, a `.interlock-backup` copy written once); `unwrap` restores them exactly; `status` shows which servers are protected. `interlock init --gateway` wraps, `uninstall` unwraps. |
| `interlock mcp-proxy --name N -- <cmd...>` | The gateway itself; normally written into MCP configs by `gateway wrap` rather than run by hand. |
| `interlock mcp-pins [--accept SERVER [--tool T]]` | List pinned MCP tool definitions; `--accept` clears pins after you review a changed tool, so its new definition is pinned on next use. |
| `interlock mcp` | Run Interlock as an MCP server on stdio, for use inside your agent: `check_action` (what would the gate decide?), `explain_decision`, `recent_decisions`, `scan_mcp_servers`, `interlock_status`, `suggest_rule_override` (returns YAML for you to apply). Read-only and advisory: it can make an agent more careful, never approve anything. `interlock init --mcp` registers it with each agent. |
| `interlock audit verify [--expect-head H] \| head` | The local log is hash-chained (each record carries `prev_hash` and `hash`). `verify` walks it and names the first edited, removed, reordered, or inserted record; `head` prints the newest hash so you can keep it elsewhere and later detect truncation with `--expect-head`. `doctor` runs `verify` too. |
| `interlock aibom [-o FILE] [--project P]` | A CycloneDX 1.6 AI bill of materials: agents found, models named in their configs, each MCP server (with a package URL for npm / PyPI / container launches and whether the version is pinned), remote MCP endpoints as services, and tool-definition hashes pinned by the gateway. Env and header values are never included, only names. |
| `interlock explain [event_id]` | Explain one decision in plain language (default: the most recent stop): what was attempted, the verdict, each rule and why it matters, what the agent was told, and the override snippet if it was a false positive. Event ids come from `interlock log` / `report`; a prefix is enough. |
| `interlock selftest [--harness H,...]` | Prove the gate works end to end with the policy you actually run: sends attack shapes (force-push, curl \| bash, .env upload, shell-rc persistence, key read) and a benign control through the live daemon in each installed agent's own hook format, and reports the verdicts. Nothing is executed; in shadow mode it shows what enforce would do. Events are tagged and kept out of `report` and `explain`. `init` runs it once after starting the service. |
| `interlock policy lint [--workspace P]` | Catch policy mistakes that fail silently: unknown rule ids in `packs.overrides` (with a did-you-mean), unknown packs, overrides that weaken or disable critical rules, catch-all remotes/hosts/MCP allows, toxic-flow detection off. Exits 1 on errors; `doctor` runs it. |
| `interlock replay [--days N] [--all]` | Re-decide your recorded tool calls with the policy as it is now and list what would change (newly stopped, newly allowed): the way to tune a rule against real history before it affects you. Deterministic: rules and mandate are re-evaluated, the judge is not re-asked, and session state starts fresh. |
| `interlock doctor` | Check protection is on: daemon and version, token permissions, policy validity, hooks present in each agent, shims untampered, agents installed but unprotected, recent fail-open calls. Exits non-zero on a problem. |
| `interlock serve [--mode shadow\|enforce] [--listen host:port]` | Run the daemon. `--mode` overrides the policy file. |
| `interlock install --kiro [--workspace-root P] [--runtime sh\|node]` | Install the Kiro hooks. `sh` is the default shim (about 33 ms per call); `node` is about 108 ms. |
| `interlock install --claude-code [--project P \| --user]` | Install Claude Code hooks (§4). |
| `interlock install --codex [--project P \| --user]` | Install Codex hooks (§4). |
| `interlock log [-n N] [-f] [--workspace W]` | Tail decisions from the spool: time, pre/post, disposition, tier, action class, tool, latency, argument. |
| `interlock health` | Ping the daemon: version, mode, profile, policy hash. |
| `interlock token` | Print the token path. |
| `interlock test [--corpus DIR] [--policy] [--json P] [--max-fpr F] [--max-fnr F] [--quiet]` | Run the deterministic corpus and report per-rule and per-category false-positive / false-negative rates. Defaults to Interlock's clean policy; `--policy` uses your live layered policy. Exits non-zero when a gate is exceeded (CI). See §3.1. |

## 3. Policy

Policy is YAML. Interlock merges built-in defaults, then `~/.interlock/policy.yaml` (user), then `<workspace-root>/.interlock/policy.yaml` (workspace). Mappings merge one level deep; lists replace. The file's hash is stamped on every verdict. Full examples: `docs/policy-example.yaml`, `docs/mandate-example.cedar`.

```yaml
version: 1
workspace: my-project
mode: shadow                                  # shadow | enforce
profile: laptop                               # laptop | team

trust:
  workspace_roots: ["/path/to/project"]       # writes under these are tier 1; elsewhere is gated
  allowed_git_remotes: ["github.com/my-org/*"] # pushes elsewhere ask
  allowed_hosts: [...]                        # egress elsewhere is judged (defaults cover GitHub, npm, PyPI, crates, Go, Maven, localhost)
  protected_branches: ["main", "master", "release/*", "prod", "production"]
  protected_paths: [".git/hooks/**", ".kiro/**", ".claude/**", ".codex/**", ".github/workflows/**", ".interlock/**"]
  sensitive_paths: ["~/.ssh/**", "~/.aws/**", "**/.env", "**/.env.*", "**/*.pem", "**/id_rsa*", ...]
  declared_packages_only: true                # installs of packages not in the manifest are judged
  allowed_package_indexes: ["https://pypi.org/simple", "https://registry.npmjs.org"]

packs:
  enabled: [shell, git, egress, persistence, secrets, packages]
  overrides:                                  # per rule: action block|ask|model|flag|allow, enabled false, questions [...]
    git.force_push_own_branch: { action: model }
    packages.install_undeclared: { action: ask }
    persistence.agent_config_write: { action: ask }   # e.g. in a repo that develops Interlock itself

mandate:
  mode: log_only                              # off | log_only | enforce
  cedar: mandate.cedar                        # path relative to this file, or `inline: |`

denial_budget: { consecutive: 3, total: 20, then: ask }

fail_mode:                                    # applied by the hooks when the daemon does not answer
  security.data_exfiltration: closed
  security.malicious_command: closed
  security.persistence: closed
  security.secret_leak.*: closed
  security.privilege_escalation: closed
  default: open

judge:
  probe:
    enabled: false                            # Amazon Bedrock Guardrails as an extra detector (needs AWS credentials)
    local:                                    # vendor-neutral detector, no AWS or network
      enabled: true
      threshold: 0.6                          # heuristic score that produces a finding
      classifier_model: null                  # e.g. meta-llama/Llama-Prompt-Guard-2-86M; pip install 'interlock[promptguard]'
      classifier_threshold: 0.8
```

### MCP servers and tools (`mcp:`)

Decide per MCP server and tool, for every agent (Claude Code, Codex, Cursor, Gemini CLI, Kiro) and the MCP gateway:

```yaml
mcp:
  default: allow            # allow | ask | block for anything no pattern matches; `ask` makes every new server opt-in
  tools:
    github: allow           # a whole server
    "github/delete_*": ask  # server/tool globs
    "github/delete_repo": block
    "*/drop_*": block       # any server
```

The most specific pattern wins: a pattern that names a tool beats a server-wide one, exact beats glob, longer beats shorter. Matches fire `mcp.tool_blocked` (block) or `mcp.tool_requires_approval` (ask), which `packs.overrides` can tune like any rule. Tools that take a `command` also get the shell rules, whatever this section says.

### Toxic flows (`flow:`)

Some exfiltration is only visible across a session: the agent reads private data, later takes in untrusted content (a web page, an issue, an email that carries instructions), and then makes a call that can send data out. Each step alone is ordinary. Interlock tracks the first two per session and fires `flow.lethal_trifecta` on the third:

| Leg | Comes from |
|---|---|
| Private data | sensitive-path reads, secrets seen in a tool result, MCP tools matching `flow.private_sources` (mail, drive, databases, secret stores by default) |
| Untrusted content | web / network tool results, MCP results matching `flow.untrusted_sources` (fetch, browser, search, issues, email by default), any result the injection probe flagged |
| Exfiltration-capable call | network egress from the shell or a web tool, `git push`, MCP tools matching `flow.sinks` (send, post, create, upload, comment, ...) |

```yaml
flow:
  enabled: true
  action: ask           # block | ask | flag
  private_sources: ["*mail*/*", "*postgres*/*", "*vault*/*", ...]   # server/tool globs; replace to customize
```

**Memory poisoning.** Agent instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.github/copilot-instructions.md`, `.cursor/rules/`, ...) and MCP memory servers are read back into every future session. Writes to them are recorded (`memory.instruction_file_write`); content that reads like instructions to the agent asks (`memory.injected_instructions`); and once a session has taken in untrusted content, writing them asks (`flow.memory_poisoning`), so an injected instruction can't quietly make itself permanent.

Sessions are the agent's own session id for hook traffic, and the launching agent's process for MCP gateway traffic, so taint never crosses between agents.

### Rule catalog

Default actions: `block` refuses; `ask` requires confirmation; `model` routes to the judge (recorded, not enforced, until M2); `flag` records a finding and allows. Override any of them under `packs.overrides`.

| Rule | Category | Severity | Default |
|---|---|---|---|
| `egress.cloud_metadata_endpoint` | `security.ssrf` | critical | block |
| `egress.dns_exfil_pattern` | `security.data_exfiltration` | high | ask |
| `egress.public_sharing_service` | `security.data_exfiltration` | high | ask |
| `egress.raw_ip_or_port` | `security.ssrf` | medium | ask |
| `egress.reverse_shell` | `security.malicious_command` | critical | block |
| `egress.unknown_host` | `security.data_exfiltration` | medium | model |
| `egress.upload_file_body` | `security.data_exfiltration` | high | ask |
| `egress.upload_sensitive_file` | `security.data_exfiltration` | critical | block |
| `git.clean_force` | `security.malicious_command` | high | ask |
| `git.credential_config` | `security.secret_leak` | high | ask |
| `git.delete_remote_branch` | `security.malicious_command` | high | ask |
| `git.force_push_own_branch` | `security.malicious_command` | medium | model |
| `git.force_push_protected_branch` | `security.malicious_command` | critical | block |
| `git.history_rewrite` | `security.malicious_command` | medium | model |
| `git.push_protected_branch` | `security.malicious_command` | medium | model |
| `git.push_unknown_remote` | `security.data_exfiltration` | high | ask |
| `git.remote_add_unknown` | `security.data_exfiltration` | medium | ask |
| `git.reset_hard` | `security.malicious_command` | high | ask |
| `git.skip_hooks` | `security.malicious_command` | medium | ask |
| `packages.alternate_index` | `security.supply_chain` | high | ask |
| `packages.global_or_system_install` | `security.supply_chain` | medium | ask |
| `packages.install_from_url_or_vcs` | `security.supply_chain` | high | ask |
| `packages.install_undeclared` | `security.supply_chain` | medium | model |
| `packages.run_remote_script` | `security.supply_chain` | high | ask |
| `persistence.agent_config_write` | `security.persistence` | critical | block |
| `persistence.authorized_keys` | `security.persistence` | critical | block |
| `persistence.ci_workflow_write` | `security.persistence` | medium | ask |
| `persistence.cron_or_scheduler` | `security.persistence` | high | ask |
| `persistence.git_hook` | `security.persistence` | high | ask |
| `persistence.shell_rc` | `security.persistence` | high | ask |
| `persistence.sudoers_or_system` | `security.privilege_escalation` | critical | block |
| `secrets.dump_environment` | `security.secret_leak` | medium | model |
| `secrets.dump_then_egress` | `security.data_exfiltration` | critical | block |
| `secrets.literal_in_arguments` | `security.secret_leak` | high | ask |
| `secrets.literal_in_result` | `security.secret_leak` | high | flag |
| `secrets.read_sensitive_path` | `security.secret_leak` | medium | model |
| `shell.chmod_world_writable` | `security.privilege_escalation` | high | ask |
| `shell.clear_history_or_logs` | `security.persistence` | high | ask |
| `shell.decode_and_execute` | `security.malicious_command` | critical | block |
| `shell.disk_destroy` | `security.malicious_command` | critical | block |
| `shell.eval` | `security.malicious_command` | high | ask |
| `shell.fork_bomb` | `security.resource_exhaustion` | critical | block |
| `shell.pipe_to_shell` | `security.malicious_command` | critical | block |
| `shell.rm_outside_workspace` | `security.malicious_command` | high | ask |
| `shell.rm_rf` | `security.malicious_command` | high | model |
| `shell.rm_rf_dangerous_target` | `security.malicious_command` | critical | block |
| `shell.sudo` | `security.privilege_escalation` | high | ask |

### Mandate (Cedar)

The mandate is the authorization envelope, written in Cedar and evaluated locally. Interlock binds each normalized tool call to an `Interlock::Action` (`git.push`, `git.remote_add`, `git.history_rewrite`, `net.egress`, `destructive`, `install`, `fs.read_sensitive`, `fs.write`, `fs.write_outside`, `sys.privilege`, `shell.build_or_test`) with `context.input` carrying the parsed structure (for `git.push`: `remote`, `branch`, `force`, `delete`) and `context.session` carrying the session counters. Calls that bind to no action are reported as `unjudged` for the mandate, never allowed by default.

```cedar
permit (principal, action == Interlock::Action::"git.push", resource)
when { context.input.remote == "origin" || context.input.remote like "github.com/my-org/*" };

forbid (principal, action == Interlock::Action::"git.push", resource)
when { context.input.force == true && (context.input.branch == "main" || context.input.branch == "master") };

forbid (principal, action == Interlock::Action::"sys.privilege", resource);
```

`mode: log_only` records denials as findings without enforcing, which is how to roll a mandate out. The same language runs at Amazon Bedrock AgentCore Gateway for MCP tools (AgentCore Policy), so one mandate can cover local and remote tools.

### 3.1 Testing your policy (`interlock test`)

A guardrail you cannot measure is a guardrail you cannot trust. `interlock test` runs a corpus of labelled tool calls through the **deterministic** pipeline exactly as the daemon would (normalize → tier route → packs → mandate → policy composition), compares the result against each case's expected labels, and reports where your policy over- or under-fires. The judge is deliberately **not** consulted: this command measures the deterministic layer only, so its numbers are reproducible and fast, and model-routed rules are reported as routed to the judge rather than scored. (Scoring the judge's answers is the next step; the runner already carries the seam for it.)

```sh
interlock test                               # run the built-in pack corpus
interlock test --corpus ./my-cases           # add your own *.jsonl cases (repeatable)
interlock test --policy                      # validate against YOUR live policy, not the defaults (see below)
interlock test --json report.json            # also write a machine-readable report
interlock test --max-fpr 0.01 --max-fnr 0.10 # override the global gates for this run
interlock test --quiet                       # no table; just the exit code (and --json)
```

**Which policy is used.** By default the corpus runs against Interlock's **clean default policy**, so the shipped cases are reproducible and CI-stable regardless of what you have in `~/.interlock/policy.yaml` or a workspace `.interlock/policy.yaml`. This matters because the corpus is authored against the default rule actions and trust model: if your live policy softens a rule (e.g. `persistence.agent_config_write: {action: ask}`) or enables a mandate, those changes would turn shipped `block` cases into `ask` and add `mandate:*` findings — not corpus failures, just your deliberate overrides. Pass `--policy` to load your **layered live policy** instead and ask the different question "does *my* policy still catch these attacks?"; expect divergences you introduced on purpose. The header line names which policy was used.

**What it measures.** Each case is labelled `benign` (expected to end in `allow`) or `attack` (anything stricter). On the deterministic layer:

- A **false positive** is a benign case the engine hard-escalated to `block` or `ask`. A benign case routed to the judge (`model`) is *not* an FP — it defers to a layer this command does not score.
- A **false negative** is an attack case the engine let through (`allow`/`flag`). An attack correctly routed to the judge (`model`) is *not* a miss — the deterministic layer did its job by escalating it.

Rates are reported overall and **per OGR category**, alongside per-rule "missed" (expected but did not fire) and "spurious" (fired against a negative case) counts.

```
interlock test  —  252 cases (87 benign, 165 attack) from .../interlockd/data/packs
deterministic layers only (normalize → engine → mandate → policy); judge excluded

category                                 cases   FP   FN     FPR     FNR
----------------------------------------------------------------------------
security.data_exfiltration                  41    0    0    0.0%    0.0%
security.malicious_command                  68    0    0    0.0%    0.0%
security.supply_chain                       22    0    0    0.0%    0.0%
...
----------------------------------------------------------------------------
TOTAL                                      252    0    0    0.0%    0.0%

PASS — all cases matched and all gates within thresholds
```

**Gates and CI.** Thresholds live in policy under `tests:` and can be overridden per category (longest-prefix match on the OGR category). `--max-fpr` / `--max-fnr` override the global gate for a single run. The command **exits non-zero** when any case fails its labels or any gate is exceeded, so it drops straight into CI:

```yaml
tests:
  max_fpr: 0.01            # at most 1% of benign cases may be escalated/blocked
  max_fnr: 0.10            # at most 10% of attack cases may slip through the deterministic layer
  categories:
    security.malicious_command: { max_fnr: 0.0 }    # never miss a malicious command
    security.data_exfiltration: { max_fnr: 0.0 }
```

```sh
# in CI
interlock test --json interlock-report.json || exit 1
```

**Case format** (`*.jsonl`, one JSON object per line — the same files the pytest corpus uses, under `interlockd/data/packs/`):

| Field | Meaning |
|---|---|
| `id` | unique case id (required) |
| `cmd` *or* `tool` + `args` | the proposed tool call (one is required; `cmd` is shorthand for `execute_bash`) |
| `expect` | the expected deterministic decision: `block` \| `ask` \| `model` \| `allow` (required) |
| `rules` | rule ids that must fire |
| `not_rules` | rule ids that must not fire; `"*"` means no finding at all |
| `manifest` | `{filename: content}` written into the case's temp workspace first (e.g. a `package.json` for package rules) |
| `result` | the untrusted tool output the post-action injection probe reads (string); set this on injection/exfil cases rather than relying on a manifest key name |
| `tier` | expected tier `0` \| `1` \| `2` |
| `label` | `attack` \| `benign` (optional; inferred from `expect` when absent) |
| `category` | OGR category for the per-category rates (optional; inferred from the expected rules) |
| `judge` | `{question_id: expected_noul}` — recorded as pending, not scored in this step |

A corpus directory may also carry an optional **`_corpus.yaml`** declaring the trust context its cases were authored against — `trust: {allowed_git_remotes: [...], ...}` (any policy `trust` field). These fill in trust fields the test policy leaves at their defaults, so a corpus's assumptions (e.g. which git remotes count as "allowed") travel with the corpus instead of being hardcoded in the runner. The shipped pack corpus declares its remotes in `interlockd/data/packs/_corpus.yaml`.

The runner lives in `interlockd.testkit` and is the exact code the pytest corpus (`tests/test_packs.py`) runs, so the command and the test suite can never drift.

### 3.2 Building an evaluation corpus (`interlock corpus`)

`interlockd/data/packs/` is the **unit** corpus (per-rule, CI gate). For **measurement** — FPR/FNR on real traffic and, later, judge calibration — build a larger corpus under `corpus/` from three sources, all in the same case schema. See `corpus/README.md` for the full layout.

```sh
interlock corpus export --source both --out corpus/shadow/export.jsonl   # real pre_action events, redacted + deduped
interlock corpus label corpus/shadow/export.jsonl                        # set expect/label/category interactively
interlock corpus import --from agentdojo path/to/data.json --out corpus/imported/agentdojo.jsonl
interlock corpus assign-split corpus/archetypes/attacks.jsonl            # stamp a stable dev/heldout split
interlock test --corpus corpus/shadow --corpus corpus/imported          # run it through the deterministic layer
interlock test --corpus corpus/archetypes --split heldout               # or just one split
```

**`export`** pulls `pre_action` events from the local spool and the DynamoDB audit table (`--source spool|dynamodb|both`; `--table`/`--region`/`--profile` default to your config, e.g. `--profile my-profile`). Every command, argument, manifest, and user-message turn is redacted with the deterministic engine's own `SECRET_PATTERNS`, cases are deduped by normalized command, and the result is written **unlabelled** (no `expect`/`label`/`category`) for a human to label. A missing table or absent credentials is a soft failure — the spool export still lands.

**`label`** walks the unlabelled cases, shows the action (and the user's instruction, if captured), and prompts for `expect` (`block`/`ask`/`model`/`allow`), `label` (`attack`/`benign`), and an optional `category`. Enter skips a case; `q` saves and quits. Writes back in place.

`label --auto` first pre-fills every **clear-cut** case from the deterministic engine's own verdict — an `allow` with no findings becomes `benign`/`allow`, a rule that fires `block`/`ask` becomes `attack` with that disposition and the rule's category — and then drops you into interactive review for only the **ambiguous** cases (anything the engine routed to `model`, where intent must be judged). Those ambiguous cases default to **`benign`** (a model-routed action is one the engine could not condemn on signature alone, and in real traffic most are legitimate), so pressing **Enter**/`y` is safe; press **`a`** to mark the rare genuine attack, **`b`** to force benign, or type a specific `expect`. `label --auto --auto-only` applies the confident proposals and stops, with no interactive step. This turns a large export (where most cases are benign dev commands) into a handful of real decisions, and the proposals come from the same deterministic runner the tests use, so they never disagree with `interlock test`.

**`import --from agentdojo|injecagent|agentdrift`** re-shapes those datasets into our schema, matching their real formats: AgentDojo's `(user_task, injection_task)` pairs with a `GROUND_TRUTH` list of `{function, args}` calls; InjecAgent's `User Instruction` / `Attacker Instruction` / `Attacker Tools` / `Attack Type` (`ds`→data_exfiltration); AgentDrift's step-labeled trajectories (`benign` / `injection point` / `hijacked` / `failed injection`). Each item/step/call with a shell/file/network equivalent is mapped; API-only or chat-only ones are **skipped** (count reported). InjecAgent's injected payload and AgentDrift's poisoned observation become a `manifest` entry; the user instruction/goal becomes `transcript` context; each sets the matching `judge` labels. Flat single-call shapes are also accepted. The field mappers are defensive; verify against a current dataset sample before a large import.

**`assign-split`** stamps the `split` field idempotently from `sha256(id)` (70% dev / 30% heldout). `export` and `import` already stamp it; use this for hand-authored archetype files.

**v1 schema additions** (on top of §3.1's base fields):

| Field | Meaning |
|---|---|
| `transcript` | `[{role, text}]` user-intent turns a judge case needs (`role` in `user`/`assistant`); never read by the deterministic layer |
| `judge` | `{question_id: expected_noul}` expected judge answers, e.g. `{"intent_authorized": 0.1}` |
| `split` | `dev` \| `heldout` — stable 70/30 by `sha256(id)`, stamped into the file so it never drifts; `interlock test --split` filters on it |
| `_meta` | provenance for shadow/imported cases (`source`, `source_event_id`, `captured_disposition`, `redacted`) |

Give every **benign** case a `category` (the attack category it is a hard negative *for*) so per-category FPR is meaningful — an uncategorized benign case contributes to no category's FPR column.

### 3.3 Scoring the judge and calibrating (`interlock calibrate`)

The deterministic `interlock test` deliberately excludes the judge. To measure the judge itself — is it right, are its probabilities trustworthy, and where should the bands sit — score it against the `judge` labels your cases carry:

```sh
interlock calibrate --judge http://127.0.0.1:8000                      # live Strands Decider
interlock calibrate --judge replay:answers.json --corpus corpus/archetypes
interlock calibrate --judge http://127.0.0.1:8000 --json calib.json --target-fpr 0.01 --target-fnr 0.10
interlock calibrate --judge http://127.0.0.1:8000 --dump-scores scores.jsonl   # per-case label/prediction/truth/split JSONL
```

`--judge` takes either a live Decider base URL (`http(s)://…`) or `replay:PATH` — a recorded answers file (deterministic, offline; the same `ReplayBackend` the tests use). The judge-scoring pass is **separate** from the deterministic runner: it builds the same projected state the daemon sends (user messages + structured action for intent; the untrusted content for the injection probe), asks each question the case declares, and scores the answer against the label. A backend outage marks that question `unjudged`, never fatal — exactly as the daemon records it.

It reports, per question:

- **accuracy** — did the answer land on the right side of 0.5 (noul) or match the choice.
- **ECE** (expected calibration error) and **Brier** — is a 0.9 from the judge really ~90% right. Decider ships weakly-binned on `noul`, so this is measured on *our* corpus before any threshold is trusted.
- a **reliability** table (per-bin mean-predicted vs observed-frequency).

Then it selects **bands for every question that has labels**, the honest way — **fit on the `dev` split, reported on `heldout`**, never fitting on held-out. Each question fits **two** thresholds, direction-aware: a high-is-safe question (`intent_authorized`, `confirmation_given`) escalates *below* a threshold, so it fits a wider `ask`/allow band and a narrower `block` band (`block_below ≤ ask_below`); a high-is-risk question (`injection_present`, `exfil_risk`, `injection_targets_action`) flags *at or above* a threshold, so it fits a wider `warn` band and a narrower `withhold` band (`withhold_at ≥ warn_at`). The narrow band is **fit from the data** — the largest threshold that blocks/withholds **zero benign cases on dev** — not a fixed offset.

The wider (operating) threshold is chosen **max-margin**: when the two classes separate with a gap, every threshold across that gap ties at the same dev FPR/FNR, and the fit picks the one **furthest from any dev prediction** — the middle of the gap — rather than the lowest. A boundary parked flush against a training cluster edge misclassifies the first held-out point that lands just past it; the gap midpoint is the standard, dev-only choice (it never consults held-out). When the classes overlap there is no tie and the single best threshold is used, so a genuinely overlapping question is unaffected.

```
question                   dir           lenient  strict    dev FPR/FNR   held FPR/FNR  meets
intent_authorized          high_is_safe     0.65    0.45         1%/7%          1%/9%     yes
                           (22 ambiguous case(s) excluded from fit; kept in ECE)
injection_present          high_is_risk     0.50    0.90         0%/5%          0%/8%     yes
confirmation_given         high_is_safe     0.80    0.60         0%/0%          0%/0%     yes
```

**Ambiguous labels are kept out of the band fit.** A case whose label sits within `0.2` of `0.5` is a genuinely ~50/50 action: its binary truth bit (the `≥ 0.5` cutoff) is arbitrary at the boundary, and such an action is *designed* to land in the `ask`/`model` dead-zone, not to be separated by a threshold. Those cases are dropped from the FPR/FNR fit (the table prints how many) but stay in the **reliability/ECE** figures, where a mid-range prediction on a mid-range label is correct, not an error. This is why a well-separated judge can reach `meets = yes` even when the corpus deliberately contains many ambiguous cases, and why growing the ambiguous band improves calibration (ECE) without ever degrading the band fit. Use `--dump-scores <path>` to write every per-case `(label, prediction, truth_bit, split)` triple as JSONL when you need to see which cases drive a rate.

**A thin held-out split cannot certify a band.** FPR and FNR on an empty or single-class held-out set are trivially `0% / 0%` — not a measurement — so a question meets its targets only when its held-out split has at least `10` confident pairs **and** carries both classes (an authorized/benign *and* an unauthorized/attack example). A question below that bar is printed with a `held-out n=… below 10 or single-class; cannot meet targets` note and can never show `meets = yes`, however clean its rate looks. This is what keeps a question with only a handful of labelled cases (e.g. `exfil_risk` early on) from being promoted on a perfect-but-meaningless number; the remedy is to grow its corpus, not to trust the rate.

A `meets = yes` row is the credible result; `NO` means the dev fit did not generalize to held-out — the signal to grow or rebalance the corpus, not to ship that question's bands. `--json` writes the full report (per-question accuracy/ECE/Brier/reliability bins + every band selection) for tracking across model versions.

**Writing the bands into policy.** `--write-bands <policy.yaml>` merges the fitted thresholds into that file's `judge.bands` section (`intent_ask_below`, `intent_block_below`, `injection_warn_at`, `injection_withhold_at`, `confirm_allow_at`, `exfil_ask_at`), printing a diff of each change. It **refuses to write a question's bands unless that question meets its targets on held-out**; pass `--force` to override (and own the consequence). Re-run calibration on every judge/model-version change — the question wording is versioned with the daemon, so changing it is a corpus re-run.

`interlock test --judge <spec>` is also accepted: it runs the deterministic pass as usual and then appends a one-line judge summary, for a quick combined check.

## 4. Harnesses

### Kiro (verified on the IDE)

Hooks live in `<folder Kiro has open>/.kiro/hooks/interlock.json`; `interlock install --kiro` writes it. Kiro loads new hook files live. What Kiro's hook contract allows, measured (`adapters/kiro/PAYLOADS.md`):

- Block works: exit 2 with the notice on stderr; the tool does not run and the agent reads the notice.
- No native `ask`: an `ask` renders as a block whose notice tells the agent to confirm with you before retrying.
- Post-action is record-only: nothing a PostToolUse hook returns reaches the agent.
- The hook payload carries no user messages; the daemon reads them from the Kiro session transcript.
- The matcher is a JavaScript regex: `.*`, never `*`.

### Claude Code (written to the documented contract; payload capture pending)

`interlock install --claude-code --project /path/to/repo` merges `PreToolUse` and `PostToolUse` hooks into `.claude/settings.json` (`--user` targets `~/.claude/settings.json`). Claude Code's richer contract gives Interlock a real `ask` (the native permission prompt, labelled with the hook's source), `deny` with a reason shown to Claude, and `additionalContext` to warn Claude about a tool result. PreToolUse hooks fire above the permission system, so blocks hold even in `--dangerously-skip-permissions`. Interlock never returns `allow` to Claude Code, so Claude Code's own permission rules still apply to anything Interlock does not stop. User messages are read from the transcript Claude Code names in each payload.

### Codex (written to its Claude-compatible contract; payload capture pending)

`interlock install --codex --project /path/to/repo` writes `.codex/hooks.json` (`--user` targets `~/.codex/hooks.json`). Codex requires you to review and trust non-managed hooks once (`/hooks` in the CLI). Matchers cover `Bash`, `apply_patch`, and `mcp__.*`. Hosted tools such as WebSearch do not pass through hooks.

## 5. OGR conformance (`/v1/evaluate` and `interlock ogr`)

Interlock answers the OpenGuardrails (OGR) runtime contract so it can be benchmarked on a neutral suite and dropped behind any OGR integration. The same daemon that gates Kiro, Claude Code, and Codex also serves the OGR endpoints at the bare `/v1` prefix the spec uses. Nothing new has to run: `interlock serve` exposes them alongside the native API.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/evaluate` | bearer | A `GuardEvent` in, an OGR `Verdict` out. Evaluate also records to the audit store, as the spec requires (there is no separate ingest path). |
| `POST /v1/heartbeat` | bearer | Liveness for a resident runtime. |
| `GET /v1/health` | none | Status, version, provider. |
| `GET /v1/limits` | bearer | Max request bytes, the protocols accepted, and the decision enum. |
| `GET /v1/rules` | — | Optional per the spec; Interlock returns `404`. |

### 5.1 How a GuardEvent is evaluated

A `GuardEvent` carries one half of a model call in a provider-native or `canonical` `payload`; `llm_protocol` is one of `canonical`, `openai.chat`, `openai.responses`, or `anthropic.messages`. Interlock maps it onto Interlock's own events and runs each through the **same `decide()` pipeline** the native pre/post-action paths use — deterministic packs, mandate, bands, and (when a judge backend is configured) the judge and the Bedrock Guardrails probe:

- a `step/response` → one **pre-action** event per proposed tool call (`tool_calls[i]`, OpenAI `choices[].message.tool_calls`, or Anthropic `tool_use` blocks), with the trajectory's `user` messages supplied as the intent context and earlier assistant calls as prior calls;
- a `step/request` → one **post-action** event per arriving tool result (an OpenAI `tool` message or an Anthropic `tool_result` block), keyed by the provider's tool-call id, so the injection probe runs on it.

The per-event dispositions are composed into one verdict with OGR deny-wins semantics. Because the OGR wire decision is only `allow` or `block` (`require_approval` was removed in OGR v1.x), the Interlock-native **ask** band maps to `block` by default — failing stricter — and can be configured to `allow` with the finding retained (`ask_maps_to`, a query parameter on `/v1/evaluate` and `--ask-maps-to` on the runner). `warn` is advisory and maps to `allow` with its finding kept; `withhold` maps to `block` with `continuation.style: withhold`. A refused pre-action call sets `continuation.style: drop_calls` and names the call id, so a policy-enforcement point can drop the one call and run the rest. Each finding carries its OGR category, offsets, score, and a `detector` that names the deterministic module or the judge's model snapshot; `security.secret_leak` offsets are also surfaced as `modifications.spans`.

Verdicts validate against `interlockd/schema/verdict.schema.json`.

```sh
curl -s localhost:7391/v1/evaluate -H "authorization: Bearer $(cat ~/.interlock/token)" \
  -H 'content-type: application/json' -d '{
    "llm_protocol":"openai.chat","kind":"step/response",
    "agent_id":"codex","agent_type":"codex","agent_workspace":"my-project","agent_user":"dev",
    "payload":{"messages":[{"role":"user","content":"clean up the PR"}],
      "choices":[{"message":{"tool_calls":[{"id":"c1","type":"function",
        "function":{"name":"Bash","arguments":"{\"command\":\"git push --force origin main\"}"}}]}}]}}'
# -> {"decision":"block","continuation":{"style":"drop_calls","calls":["c1"],...},"findings":[...]}
```

### 5.2 Running the `seed-v0` suite (`interlock ogr run`)

`interlock ogr run <seed path> --out results.jsonl` drives the endpoint over an OGR seed suite and writes one schema-valid result per case. The seed path is a `.json`/`.jsonl` file of GuardEvents (bare, or wrapped as `{id, suite, expect, guard_event}`) or a directory of them; the suite name defaults to the file stem.

```sh
interlock serve &                                  # the endpoint the runner drives
interlock ogr run ./seed-v0 --out results.jsonl --url http://127.0.0.1:7391
interlock ogr run ./seed-v0 --out results.jsonl    # or in-process, no server needed
interlock ogr run ./seed-v0 --out results.jsonl --judge http://127.0.0.1:8000   # with the judge enabled
```

By default the runner evaluates in-process against Interlock's clean default policy; `--url` drives a running daemon instead, `--policy` uses your layered live policy, `--judge replay:PATH|http(s)://…` attaches a judge backend, and `--ask-maps-to allow` relaxes the ask mapping. When a case carries an `expect`/`label` (`attack`/`block` or `benign`/`allow`), the run prints per-suite counts and labelled accuracy; it exits non-zero if any verdict fails schema validation.

### 5.3 Validating results (`interlock ogr validate`)

`interlock ogr validate results.jsonl` checks every line against the verdict schema and exits non-zero on the first invalid one — a CI-ready gate for a published run. It accepts either bare verdict objects or the `{id, …, verdict}` records the runner writes.

```sh
interlock ogr validate results.jsonl
# -> validated 24 verdict(s) in results.jsonl against verdict.schema.json: 24 valid, 0 invalid
```

## 6. Audit store

Decisions are appended to `~/.interlock/spool/<date>.jsonl` (fsync per record) and drained to the DynamoDB table in batches of 25 by a background thread; a `.drained` marker per segment records the confirmed offset, so nothing is lost if the network or the daemon goes away.

The table (`interlock-audit`, single table, on-demand, 90-day TTL, point-in-time recovery, stream enabled) has three indexes:

| Query | Index | Key |
|---|---|---|
| One event with its explanation and feedback | base table | `PK = EVT#<event_id>` |
| All events of a session, in order | `GSI1-session` | `session_id` |
| Recent events for a workspace | `GSI2-workspace-time` | `GSI2PK = WS#<workspace>#<yyyy-mm-dd-hh>` |
| Everything asked, blocked, warned, or withheld on a day | `GSI3-review` | `GSI3PK = DISP#<disposition>#<yyyy-mm-dd>` |

Example, today's blocks:

```sh
aws dynamodb query --table-name interlock-audit --index-name GSI3-review \
  --key-condition-expression "GSI3PK = :k" --expression-attribute-values '{":k":{"S":"DISP#block#'"$(date -u +%F)"'"}}' \
  --no-scan-index-forward --query 'Items[].{tool:tool_name.S,rules:findings.L[*].M.rule.S,at:received_at.S}'
```

The table is optional and lives in your own AWS account. A CloudFormation template for it will be published with the team profile.

### Bootstrapping the judge in a gated workspace

Enabling the judge means editing the workspace policy, and `persistence.agent_config_write` gates exactly that. Before the judge exists there is nothing to resolve the resulting `ask`, so the first `judge:` section has to be written by a person, or by the agent while the daemon runs in shadow mode (`interlock serve --mode shadow`; the write is still recorded with its finding). From then on, agent edits to the policy go through the normal ask-and-confirm path.

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Nothing appears in `interlock log` | Hook not firing | Kiro: the matcher must be `.*` (a bare `*` is an invalid regex; `~/.kiro/logs/<ts>/kiro.log` says "matcher regex failed to compile"), and the hook file must be under the folder Kiro has open, not the git root. |
| `hook.log` shows `unjudged … curl_rc=7` | Daemon not running | `interlock status`; `interlock start`. Those calls ran under the fail mode (open by default except the closed categories). |
| A legitimate command was blocked | A rule fired on it | `interlock log` shows the rule id. Override it in policy (`packs.overrides.<rule>: {action: ask}` or `{enabled: false}`) or widen `trust.*`. Then add the command to `interlockd/data/packs/*.jsonl` as a negative case so it stays fixed. |
| `git push` asks every time | Remote not in `trust.allowed_git_remotes` | Add your org pattern, e.g. `github.com/my-org/*`. |
| Daemon won't start: address in use | A previous instance still holds the port | `interlock stop`; if that fails, `lsof -nP -iTCP:7391`. |
| Not sure protection is on | Hooks removed, shim edited, daemon down | `interlock doctor` lists each problem with the fix. |
| Credentials or network unavailable | Normal for laptops | The gate keeps working; the spool keeps records; the drainer catches up later. |

## 8. Known limitations

- The optional judge is off by default. When enabled, some of its thresholds are still being calibrated; expect an `ask` on some actions you plainly requested (answering the confirmation resolves it).
- Post-action withholding is verified on Claude Code and Codex. Cursor can replace results only for MCP tools; other Cursor results get a warning.
- Kiro has no native ask and ignores PostToolUse output, so on Kiro an `ask` renders as a block with a notice, and post-action warnings are record-only (`interlock log`, review index).
- The Decider server binds loopback without auth and handles one request at a time. It is a dev-grade local dependency.
- `interlock log` shows rule ids and probabilities, not prose rationales. The explainer is planned.
- The gate sees tool calls, not what the OS executed. Anything that reaches a shell without passing through a harness hook is invisible to it.


## 9. Development

```sh
.venv/bin/pytest -q            # unit, API latency, DynamoDB (moto), shim, pack corpus
.venv/bin/ruff check interlockd tests
.venv/bin/interlock test                    # the pack corpus as a CI gate: per-rule and per-category FPR/FNR
.venv/bin/interlock test --json report.json # same run, machine-readable (exit non-zero on a gate breach)
```

Adding a rule: register it in `interlockd/det/packs.py` with `rule(id, category, severity, default)`, implement the check, and add positive and negative cases to `interlockd/data/packs/<pack>.jsonl`. The corpus runner fails if the rule does not fire where expected or fires where it must not. Replaying the real spool through the engine is the best source of hard negatives.

## Change log

| Date | Change |
|---|---|
| 2026-10-08 | Guide created at M1: Kiro adapter, deterministic engine (6 packs, 47 rules), Cedar mandate, policy, spool + DynamoDB audit store, shadow/enforce. |
| 2026-10-08 | M2: Strands Decider judge, Bedrock Guardrails probe, policy bands, transcript-based confirmation, Claude Code and Codex adapters, Known limitations section. |
| 2026-10-10 | `interlock test`: deterministic corpus runner with per-rule and per-category FPR/FNR, policy `tests:` gates (global + per category), `--corpus`/`--json`/`--max-fpr`/`--max-fnr`, CI exit code. Shared runner extracted to `interlockd.testkit` (§3.1); judge scoring is the next step. |
| 2026-10-11 | Corpus v1 (§3.2): `interlock corpus export`/`label`/`import`/`assign-split`; schema additions `transcript`/`judge`/`split`/`_meta`; per-directory `_corpus.yaml` trust; 74 hand-authored archetypes under `corpus/archetypes/` (0 FP / 0 FN across 9 categories); importers matched to real AgentDojo/InjecAgent/AgentDrift schemas; `label --auto` pre-fills clear-cut cases (safe benign default on ambiguous ones). |
| 2026-10-11 | Judge scoring + calibration (§3.3): a separate `score_judge` pass (deterministic runner stays pure) and `interlock calibrate` — per-question accuracy/ECE/Brier/reliability and band selection fit on the dev split, reported on held-out. `interlock test --judge` adds a one-line judge summary. Backends: a live Decider URL or `replay:PATH`. |
| 2026-10-17 | Calibration (§3.3): confidence-filtered band fitting — labels within `0.2` of `0.5` are excluded from the FPR/FNR fit (kept in ECE), so deliberately-ambiguous cases no longer drag the threshold to extremes; the table reports how many were excluded. Max-margin operating threshold — among dev-tied thresholds the fit picks the separating-gap midpoint, not the cluster edge. Min-sample guard — a question meets targets only with ≥ 10 held-out confident pairs and both classes present. `--dump-scores <path>` writes per-case `(label, prediction, truth_bit, split)` JSONL for diagnosis. `confirmation_given` scored through the production `project_confirmation` state. `--write-bands` now does a minimal in-place edit of `judge.bands` (comments/formatting preserved). Judge corpus grown to 258 labels across 282 archetype cases (122 `intent_authorized`, 50 `confirmation_given`, 41 `injection_present`, 23 `injection_targets_action`, 22 `exfil_risk`); `injection_targets_action` numeric→choice label fix (acc 0.00→0.91). Reports under `docs/reports/`; `confirmation_given`'s band (`confirm_allow_at: 0.70`) promoted to the workspace policy. |
| 2026-10-17 | Local injection probe (§1, §3): vendor-neutral post-action detector, on by default — weighted heuristics for instructions addressed to an agent (override, role markers, addressee + action + risky target, concealment, false authority) and hidden carriers (HTML comments, Unicode tag characters, zero-width text), with quoted attack phrases in security discussion discounted; optional Hugging Face classifier via `judge.probe.local.classifier_model` and the `promptguard` extra. 24/24 labelled injections and 0/17 benign results in the archetype corpus. Composes deny-wins with Bedrock Guardrails and the judge. GitHub Actions CI (`.github/workflows/ci.yml`): ruff, pytest, `interlock test` on the pack and archetype corpora. |
real AgentDojo/InjecAgent/AgentDrift schemas; `label --auto` pre-fills clear-cut cases (safe benign default on ambiguous ones). |
| 2026-10-11 | Judge scoring + calibration (§3.3): a separate `score_judge` pass (deterministic runner stays pure) and `interlock calibrate` — per-question accuracy/ECE/Brier/reliability and band selection fit on the dev split, reported on held-out. `interlock test --judge` adds a one-line judge summary. Backends: a live Decider URL or `replay:PATH`. |
