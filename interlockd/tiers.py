"""Tier router (design §4.3): read-only, in-workspace mutation, or gated.

Tool-name tables cover Kiro's built-in tools and the Claude Code / Codex names the later adapters send.
Unknown tools are gated. Reads of sensitive paths are promoted to the gated tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import InterlockEvent
from .paths import is_protected, is_sensitive, is_under, normalize_path

HARNESS_TOOLS = {
    "todo_list", "update_session_information", "create_artifact", "user_input", "validate_spec_format",
    "analyze_requirements", "disclose_context", "kiro_powers", "fetch_cloud_config",
}
READ_ONLY_TOOLS = {
    "read_file", "read_code", "grep_search", "file_search", "list_directory", "fs_read", "read", "list_dir",
    "Read", "Grep", "Glob", "LS",
    "read_many_files", "glob", "search_file_content",                       # Gemini CLI
}
IN_WORKSPACE_WRITE_TOOLS = {
    "fs_write", "str_replace", "fs_append", "write", "smart_relocate", "create_file",
    "Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch",
    "write_file", "replace",                                                 # Gemini CLI
}
DESTRUCTIVE_TOOLS = {"delete_file", "remove_file", "Delete"}
SHELL_TOOLS = {"execute_bash", "shell", "Bash", "PowerShell", "control_bash_process", "exec_command",
               "Shell", "run_shell_command"}                                 # Cursor, Gemini CLI
NETWORK_TOOLS = {"web_fetch", "remote_web_search", "WebFetch", "WebSearch", "web_search", "google_web_search"}
SUBAGENT_TOOLS = {"invoke_sub_agent", "Task", "spawn_agent"}

PATH_KEYS = ("path", "file_path", "filePath", "target", "destination", "source", "notebook_path")


@dataclass
class TierResult:
    tier: int
    action_class: str
    reason: str
    paths: list[str] = field(default_factory=list)


def _paths_from_args(args: dict[str, Any], cwd: str | None) -> list[str]:
    out: list[str] = []
    for k in PATH_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v:
            out.append(normalize_path(v, cwd))
    return out


def route(event: InterlockEvent, *, workspace_roots: list[str], protected: list[str], sensitive: list[str]) -> TierResult:
    name = event.tool_call.name
    args = event.tool_call.arguments
    cwd = event.context.cwd
    roots = workspace_roots or ([cwd] if cwd else [])

    if name in HARNESS_TOOLS:
        return TierResult(0, "harness", "harness-internal tool")

    if name in READ_ONLY_TOOLS:
        paths = _paths_from_args(args, cwd)
        hot = [p for p in paths if is_sensitive(p, sensitive)]
        if hot:
            return TierResult(2, "credential_access", "read of a sensitive path", hot)
        return TierResult(0, "read", "read-only tool", paths)

    if name in IN_WORKSPACE_WRITE_TOOLS:
        paths = _paths_from_args(args, cwd)
        if not paths:
            return TierResult(2, "edit_in_workspace", "write tool without a path argument")
        if any(is_protected(p, roots, protected) for p in paths):
            return TierResult(2, "edit_protected", "write to a protected path", paths)
        if any(is_sensitive(p, sensitive) for p in paths):
            return TierResult(2, "credential_access", "write to a sensitive path", paths)
        if all(is_under(p, roots) for p in paths):
            return TierResult(1, "edit_in_workspace", "write inside the workspace", paths)
        return TierResult(2, "edit_outside_workspace", "write outside the workspace", paths)

    if name in DESTRUCTIVE_TOOLS:
        return TierResult(2, "destructive", "delete tool", _paths_from_args(args, cwd))
    if name in SHELL_TOOLS:
        return TierResult(2, "shell", "shell command; parsed by the deterministic engine")
    if name in NETWORK_TOOLS:
        return TierResult(2, "network_egress", "network tool")
    if name in SUBAGENT_TOOLS:
        return TierResult(2, "subagent", "subagent spawn")
    if name.startswith(("@", "mcp_", "MCP:")):                              # Claude/Codex mcp__, Gemini mcp_, Cursor MCP:
        return TierResult(2, "mcp", "MCP tool")
    return TierResult(2, "other", "unknown tool")
