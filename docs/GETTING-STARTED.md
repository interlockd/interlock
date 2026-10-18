# Getting started

This guide takes about ten minutes. You install Interlock, watch what it would block, switch to enforcing, and then optionally add a team policy, MCP servers, your own agents, and CI. Every step can be undone with `interlock uninstall`.

## 1. Install

```sh
pipx install interlockd        # or: uv tool install interlockd
interlock init
```

`init` lists everything it will change and asks first. It then:

- finds the coding agents you have (Claude Code, Codex, Cursor, Copilot CLI, Gemini CLI, Windsurf, Antigravity, OpenCode, Kiro);
- adds a small hook to each one;
- creates `~/.interlock/`, holding a 0600 token, the audit log and a starter policy;
- starts the daemon as a background service (launchd on macOS, systemd on Linux).

Use `--harness claude-code,codex` to set up only some agents, and `--no-service` to skip the background service.

You start in **shadow** mode: every decision is recorded and nothing is blocked. Restart any agent that was already running so it loads the hook. Codex also asks you to review and trust the hook once with `/hooks`.

## 2. Check it is working

```sh
interlock status       # daemon, mode, policy, which agents have hooks
interlock selftest     # sends attack shapes through the live daemon in each agent's hook format; nothing runs
```

```
  ✓ claude-code  force-push to main               block  (should stop) git.force_push_protected_branch
  ✓ claude-code  pipe a download into a shell     block  (should stop) egress.unknown_host, shell.pipe_to_shell
  ✓ claude-code  upload .env to a paste site      block  (should stop) egress.unknown_host, egress.upload_sensitive_file
  ✓ claude-code  persistence in ~/.zshrc          block  (should stop) persistence.shell_rc, shell.pipe_to_shell
  ✓ claude-code  ordinary test run                allow  (should pass)
```

## 3. Work as usual, then look

Use your agent normally for a while. Then:

```sh
interlock log -f       # decisions as they happen
interlock report       # what enforce mode would have blocked, and which rules fired
interlock explain      # the latest stop in plain language: why, what the agent was told, how to override it
```

```
Interlock would have refused a Bash call from claude-code (shadow mode: nothing was enforced):
  git push --force origin main

Why:
  - git.force_push_protected_branch (critical): Force-pushing a protected branch rewrites shared history ...

If this was wrong, override the rule in ~/.interlock/policy.yaml:
  packs:
    overrides:
      git.force_push_protected_branch: { action: ask }     # or enabled: false
```

If a rule is too noisy for you, override it in `~/.interlock/policy.yaml` and run `interlock restart`. `interlock policy lint` catches typos and warns about overrides that weaken critical rules.

## 4. Enforce

```sh
interlock enforce
```

Refused calls now don't run. The agent receives the reason and is told not to retry in a disguised form. Tool results that carry injected instructions are withheld wherever the agent allows that. Claude Code, Codex and Copilot CLI allow it; [ADAPTERS.md](ADAPTERS.md) lists each agent. `interlock shadow` switches back. `interlock pause` refuses every agent action until `interlock resume`.

`interlock doctor` checks that protection is really on. It reports missing or edited hooks, agents you have installed that aren't protected, calls that ran while the daemon was down, and whether the audit log is intact.

## 5. Optional: share a policy with your team

Commit a policy as `.interlock/policy.yaml` in a repository, starting from [examples/policies/strict-team.yaml](../examples/policies/strict-team.yaml). Everyone running Interlock gets it for calls made inside that repository, with no restart needed. A repository's policy can only make your own stricter, so a poisoned repository can't switch rules off. `interlock policy lint --workspace .` shows what applies.

## 6. Optional: MCP servers

```sh
interlock scan              # audit MCP and agent configs: unpinned packages, inline secrets, broad roots, auto-approved tools
interlock gateway wrap      # route every MCP server through Interlock (unwrap undoes it)
```

The gateway pins each server's tool definitions, so a definition that changes after approval is caught. It also hides poisoned tools, gates each call with the same rules as the shell, and withholds injected results. It works with any MCP client, including ones without hooks. Restart your agents after wrapping.

## 7. Optional: your own agents

Install the extra for your framework, for example `pip install 'interlockd[langchain]'`, then wrap the tools:

```python
from interlockd.integrations.langchain import guard_tools

agent = create_react_agent(model, guard_tools([shell]))
```

The Claude Agent SDK (`guard_options(options)`), Strands, the OpenAI Agents SDK, Google ADK and CrewAI work the same way. See [examples/agents/](../examples/agents/).

## 8. Optional: stronger containment

Hooks only see what an agent reports. To limit an agent at the OS level as well:

```sh
interlock egress-proxy &                                       # decides every outbound host
interlock sandbox --egress http://127.0.0.1:7392 -- claude     # rc files, ~/.ssh and Interlock's files can't be written; network only via the proxy
```

## 9. Optional: CI

`interlock scan --fail-on high` and `interlock test` both exit non-zero on a problem. [examples/github-workflow.yml](../examples/github-workflow.yml) runs them in GitHub Actions and uploads SARIF.

## Removing it

```sh
interlock uninstall           # removes hooks and the service; keeps ~/.interlock (add --purge to delete it)
```

Next: [USER-GUIDE.md](USER-GUIDE.md) for every command and policy option, [THREAT-MODEL.md](THREAT-MODEL.md) for what Interlock can and can't see, [PERFORMANCE.md](PERFORMANCE.md) for latency.
