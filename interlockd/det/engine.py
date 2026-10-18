"""Deterministic engine entry point: route a normalized event through the packs the policy enables."""

from __future__ import annotations

from ..models import InterlockEvent
from ..paths import is_protected, is_sensitive, is_under, normalize_path
from ..policy import Policy
from ..tiers import (
    DESTRUCTIVE_TOOLS,
    IN_WORKSPACE_WRITE_TOOLS,
    NETWORK_TOOLS,
    PATH_KEYS,
    SHELL_TOOLS,
    TierResult,
)
from . import DetResult
from .mcp import check_mcp_policy
from .packs import (
    R_EGRESS_SHARE,
    R_EGRESS_UNKNOWN,
    R_SECRET_IN_RESULT,
    R_SECRET_READ,
    _host_allowed,
    _host_of,
    check_egress,
    check_git,
    check_packages,
    check_persistence_file_op,
    check_persistence_shell,
    check_secrets_shell,
    check_shell,
    scan_secrets,
)
from .shellparse import parse

HARM = {"read": 0, "harness": 0, "build_or_test": 0, "edit_in_workspace": 0, "edit_outside_workspace": 2, "edit_protected": 3,
        "install_or_configure": 2, "vcs_history_or_remote": 2, "network_egress": 2, "destructive": 2, "credential_access": 3,
        "shell": 1, "subagent": 1, "mcp": 1, "other": 1}


def harm_for(res: DetResult) -> int:
    """0 recoverable locally · 1 recoverable with effort · 2 hard to reverse · 3 irreversible or affects others."""
    h = HARM.get(res.action_class, 1)
    sev = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for f in res.findings:
        h = max(h, sev.get(f.severity, 1))
    return min(h, 3)


def _command_of(event: InterlockEvent) -> str | None:
    a = event.tool_call.arguments
    for k in ("command", "cmd", "script", "commandLine"):
        v = a.get(k)
        if isinstance(v, str) and v.strip():
            return v
    if isinstance(a.get("args"), list) and a.get("args"):
        return " ".join(str(x) for x in a["args"])
    return None


def evaluate(event: InterlockEvent, policy: Policy, tier: TierResult) -> DetResult:
    res = DetResult(action_class=tier.action_class)
    cwd = event.context.cwd
    enabled = set(policy.packs.enabled)
    name = event.tool_call.name
    args = event.tool_call.arguments
    roots = policy.trust.workspace_roots or ([cwd] if cwd else [])

    if event.kind == "post_action":
        if "secrets" in enabled and event.result is not None:
            scan_secrets(event.result.content, "result.content", res, policy, R_SECRET_IN_RESULT)
        res.harm = harm_for(res)
        return res

    if tier.action_class == "mcp" or event.context.mcp_server:
        check_mcp_policy(event, res, policy)
    # MCP tools that run commands (terminal / shell servers) get the same shell analysis as the agent's own shell;
    # only explicit command keys count, since a generic `args` list means something else on most MCP tools
    mcp_cmd = next((args[k] for k in ("command", "cmd", "script", "commandLine")
                    if isinstance(args.get(k), str) and args[k].strip()), None) if tier.action_class == "mcp" else None
    if name in SHELL_TOOLS or mcp_cmd is not None:
        cmd = _command_of(event) if mcp_cmd is None else mcp_cmd
        if cmd is not None:
            parsed = parse(cmd)
            res.normalized["commands"] = parsed.commands()[:20]
            if res.action_class == "shell":
                res.action_class = "build_or_test" if parsed.commands() and all(
                    c in BUILD_TOOLS for c in parsed.commands()) else "shell"
            if "shell" in enabled:
                check_shell(parsed, res, policy, cwd)
            if "git" in enabled:
                check_git(parsed, res, policy)
            if "egress" in enabled:
                check_egress(parsed, res, policy, cwd)
            if "persistence" in enabled:
                check_persistence_shell(parsed, res, policy, cwd)
            if "secrets" in enabled:
                check_secrets_shell(parsed, res, policy, cwd)
            if "packages" in enabled:
                check_packages(parsed, res, policy, cwd)
    elif name in IN_WORKSPACE_WRITE_TOOLS or name in DESTRUCTIVE_TOOLS or tier.paths:
        for p in tier.paths or [normalize_path(args[k], cwd) for k in PATH_KEYS if isinstance(args.get(k), str)]:
            where = "tool_call.arguments.path"
            if "persistence" in enabled and name in IN_WORKSPACE_WRITE_TOOLS:
                check_persistence_file_op(p, res, policy, cwd, where)
            if "secrets" in enabled and is_sensitive(p, policy.trust.sensitive_paths):
                res.add(policy, R_SECRET_READ, path=where, subject=p)
            if name in DESTRUCTIVE_TOOLS and roots and not is_under(p, roots):
                from .packs import R_RM_OUTSIDE
                res.add(policy, R_RM_OUTSIDE, path=where, subject=p)
            if name in IN_WORKSPACE_WRITE_TOOLS and is_protected(p, roots, policy.trust.protected_paths) and not res.findings:
                from .packs import R_PERSIST_AGENT_CONFIG
                res.add(policy, R_PERSIST_AGENT_CONFIG, path=where, subject=p)
        content = args.get("content") or args.get("new_str") or args.get("file_text") or ""
        if "secrets" in enabled and isinstance(content, str) and content:
            from .packs import R_SECRET_IN_ARGS
            scan_secrets(content, "tool_call.arguments.content", res, policy, R_SECRET_IN_ARGS)
    elif name in NETWORK_TOOLS and "egress" in enabled:
        url = args.get("url") or args.get("query") or ""
        host = _host_of(str(url)) if url else None
        if host:
            res.normalized["egress_hosts"] = [host]
            if any(s in host for s in ("gist.github.com", "pastebin", "transfer.sh", "webhook.site")):
                res.add(policy, R_EGRESS_SHARE, path="tool_call.arguments.url", subject=host)
            elif not _host_allowed(host, policy.trust.allowed_hosts):
                res.add(policy, R_EGRESS_UNKNOWN, path="tool_call.arguments.url", subject=host)

    res.harm = harm_for(res)
    return res


BUILD_TOOLS = {"npm", "pnpm", "yarn", "bun", "node", "python", "python3", "pytest", "uv", "pip", "make", "cmake", "cargo", "go",
               "mvn", "gradle", "./gradlew", "tsc", "eslint", "ruff", "black", "mypy", "prettier", "jest", "vitest", "ls", "cat",
               "echo", "pwd", "which", "env", "head", "tail", "grep", "rg", "find", "wc", "sort", "uniq", "diff", "git", "sed", "awk",
               "cd", "true", "test", "sleep", "date", "docker", "kubectl"}
