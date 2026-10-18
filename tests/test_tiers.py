from conftest import PRE_BASH, PRE_READ

from interlockd.config import DEFAULT_PROTECTED, DEFAULT_SENSITIVE
from interlockd.normalize.kiro import normalize_kiro
from interlockd.tiers import route

ROOTS = ["/ws/proj"]


def _route(payload):
    return route(normalize_kiro(payload), workspace_roots=ROOTS, protected=DEFAULT_PROTECTED, sensitive=DEFAULT_SENSITIVE)


def test_read_in_workspace_is_tier0():
    r = _route(PRE_READ)
    assert (r.tier, r.action_class) == (0, "read")
    assert r.paths == ["/ws/proj/src/a.py"]  # relative path resolved against cwd


def test_read_of_sensitive_path_is_gated():
    r = _route({**PRE_READ, "tool_input": {"path": "~/.ssh/id_rsa"}})
    assert (r.tier, r.action_class) == (2, "credential_access")
    r = _route({**PRE_READ, "tool_input": {"path": "/ws/proj/.env"}})
    assert (r.tier, r.action_class) == (2, "credential_access")


def test_write_in_workspace_is_tier1():
    r = _route({**PRE_READ, "tool_name": "fs_write", "tool_input": {"path": "tests/test_a.py", "content": "x"}})
    assert (r.tier, r.action_class) == (1, "edit_in_workspace")


def test_write_outside_workspace_is_gated():
    r = _route({**PRE_READ, "tool_name": "fs_write", "tool_input": {"path": "/etc/hosts", "content": "x"}})
    assert (r.tier, r.action_class) == (2, "edit_outside_workspace")


def test_write_to_agent_config_is_protected():
    r = _route({**PRE_READ, "tool_name": "fs_write", "tool_input": {"path": ".kiro/hooks/interlock.json", "content": "{}"}})
    assert (r.tier, r.action_class) == (2, "edit_protected")
    r = _route({**PRE_READ, "tool_name": "str_replace", "tool_input": {"path": "/ws/proj/.git/hooks/pre-commit"}})
    assert (r.tier, r.action_class) == (2, "edit_protected")


def test_shell_delete_network_mcp_unknown_are_gated():
    assert _route(PRE_BASH).tier == 2 and _route(PRE_BASH).action_class == "shell"
    assert _route({**PRE_READ, "tool_name": "delete_file", "tool_input": {"path": "a"}}).action_class == "destructive"
    assert _route({**PRE_READ, "tool_name": "web_fetch", "tool_input": {"url": "https://x"}}).action_class == "network_egress"
    assert _route({**PRE_READ, "tool_name": "@postgres/query", "tool_input": {"sql": "x"}}).action_class == "mcp"
    assert _route({**PRE_READ, "tool_name": "something_new", "tool_input": {}}).action_class == "other"


def test_harness_tools_are_tier0():
    r = _route({**PRE_READ, "tool_name": "todo_list", "tool_input": {"command": "create"}})
    assert (r.tier, r.action_class) == (0, "harness")
