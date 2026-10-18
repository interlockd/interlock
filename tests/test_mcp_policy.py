"""MCP server / tool policy: name parsing across harnesses, most-specific-wins resolution, engine integration."""

from __future__ import annotations

import pytest

from interlockd.det.mcp import resolve, split_mcp_name
from interlockd.models import AdapterInfo, Context, InterlockEvent, ToolCall
from interlockd.policy import Policy
from interlockd.testkit import run_case


def _ev(name, server=None):
    return InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="t"), tool_call=ToolCall(name=name),
                          context=Context(mcp_server={"name": server} if server else None))


@pytest.mark.parametrize("name,server,known,want", [
    ("mcp__github__create_issue", None, [], ("github", "create_issue")),
    ("mcp__my-server__do_a_thing", None, [], ("my-server", "do_a_thing")),
    ("MCP:create_issue", "github", [], ("github", "create_issue")),
    ("mcp_github_create_issue", None, ["github"], ("github", "create_issue")),
    ("mcp_my_db_query", None, ["my_db"], ("my_db", "query")),           # known server resolves the underscore ambiguity
    ("create_issue", "github", [], ("github", "create_issue")),
    ("Bash", None, [], None),
])
def test_split(name, server, known, want):
    assert split_mcp_name(_ev(name, server), known) == want


def test_resolve_most_specific_wins():
    p = Policy()
    p.mcp.tools = {"github": "allow", "github/delete_*": "ask", "github/delete_repo": "block", "*/drop_*": "block"}
    assert resolve(p, "github", "create_issue") == ("allow", "github")
    assert resolve(p, "github", "delete_branch") == ("ask", "github/delete_*")
    assert resolve(p, "github", "delete_repo") == ("block", "github/delete_repo")
    assert resolve(p, "postgres", "drop_table") == ("block", "*/drop_*")
    assert resolve(p, "postgres", "query") == ("allow", None)
    p.mcp.default = "ask"
    assert resolve(p, "unknown", "anything") == ("ask", None)


def test_engine_applies_mcp_policy(tmp_path):
    p = Policy()
    p.mcp.tools = {"github/delete_repo": "block", "slack/*": "ask"}
    block = run_case({"id": "a", "tool": "mcp__github__delete_repo", "args": {"repo": "x"}}, tmp_path, policy=p)
    assert block.decision == "block" and "mcp.tool_blocked" in block.fired
    ask = run_case({"id": "b", "tool": "mcp__slack__post_message", "args": {"text": "hi"}}, tmp_path, policy=p)
    assert ask.decision == "ask" and "mcp.tool_requires_approval" in ask.fired
    ok = run_case({"id": "c", "tool": "mcp__github__create_issue", "args": {}}, tmp_path, policy=p)
    assert "mcp.tool_blocked" not in ok.fired and ok.decision in (None, "allow")
    # no mcp policy at all: nothing fires (the default is allow)
    none = run_case({"id": "d", "tool": "mcp__github__delete_repo", "args": {}}, tmp_path, policy=Policy())
    assert not {"mcp.tool_blocked", "mcp.tool_requires_approval"} & none.fired


def test_policy_yaml_round_trip(tmp_path):
    from interlockd.policy import load_policy

    (tmp_path / "policy.yaml").write_text("mcp:\n  default: ask\n  tools:\n    github: allow\n    'github/delete_*': block\n")
    pol = load_policy(None, home=tmp_path)
    assert pol.mcp.default == "ask" and pol.mcp.tools["github/delete_*"] == "block"
