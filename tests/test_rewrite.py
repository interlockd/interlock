"""Argument rewrites (opt-in `rewrites:`): `git push --force` offered as `--force-with-lease`, only on harnesses whose
reply can carry changed arguments (Claude Code), never in place of a block. Contract tests; not verified live."""

from __future__ import annotations

import json
import urllib.request

import pytest

from interlockd.api import ApiServer
from interlockd.det.rewrite import propose
from interlockd.models import Verdict
from interlockd.normalize.claude_code import normalize_claude_code
from interlockd.policy import Policy
from interlockd.render import render_claude_code

LEASE = ["git.force_with_lease"]


def _pre(command: str, **extra) -> dict:
    return {"session_id": "s1", "transcript_path": None, "cwd": "/ws/proj", "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_use_id": "toolu_1", "tool_input": {"command": command, "description": "push", **extra}}


@pytest.mark.parametrize("cmd,expected", [
    ("git push --force origin feature/x", "git push --force-with-lease origin feature/x"),
    ("git push -f origin HEAD", "git push --force-with-lease origin HEAD"),
    ("git push origin feature/x --force", "git push origin feature/x --force-with-lease"),
])
def test_force_becomes_force_with_lease(cmd, expected):
    changed, why = propose(normalize_claude_code(_pre(cmd)), LEASE)
    assert changed == {"command": expected} and "--force-with-lease" in why


@pytest.mark.parametrize("cmd", [
    "git push origin feature/x",                              # no force
    "git push --force-with-lease origin feature/x",           # already safe
    "git push origin +feature/x",                             # +refspec: not rewritable by flag
    "git push --force origin x && rm -rf build",              # chained
    "git push --force origin $(git branch --show-current)",   # substitution
    "git fetch --force origin",                               # not a push
    "echo git push --force",
])
def test_no_rewrite(cmd):
    assert propose(normalize_claude_code(_pre(cmd)), LEASE) is None


def _daemon(settings, rewrites):
    from interlockd.pipeline import Daemon
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(rewrites=rewrites)
    pol.mode = "enforce"
    pol.trust.workspace_roots = ["/ws/proj"]
    return Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)


def test_pipeline_offers_the_rewrite_only_when_enabled_and_never_over_a_block(settings):
    d = _daemon(settings, LEASE)
    v = d.decide(normalize_claude_code(_pre("git push --force origin feature/x")))
    assert v.disposition == "ask" and v.updated_arguments == {"command": "git push --force-with-lease origin feature/x"}
    assert any(f.category == "x.interlock.rewrite" for f in v.findings)
    # a force push to a protected branch stays a block
    v = d.decide(normalize_claude_code(_pre("git push --force origin main")))
    assert v.disposition == "block" and v.updated_arguments is None
    # off by default
    v = _daemon(settings, []).decide(normalize_claude_code(_pre("git push --force origin feature/x")))
    assert v.updated_arguments is None and v.disposition != "ask"


@pytest.mark.parametrize("agent_type", ["codex", "claude-agent-sdk"])
def test_harnesses_without_a_verified_rewrite_keep_the_original_call(settings, agent_type):
    v = _daemon(settings, LEASE).decide(normalize_claude_code(_pre("git push --force origin feature/x"), agent_type=agent_type))
    assert v.updated_arguments is None


def test_render_updated_input_is_the_whole_input():
    v = Verdict(event_id="e", disposition="ask", reason="--force rewritten", mode="enforce", tier=2, action_class="shell",
                updated_arguments={"command": "git push --force-with-lease origin x"})
    tool_input = {"command": "git push --force origin x", "description": "push", "timeout": 60}
    out = render_claude_code(v, kind="pre_action", tool_input=tool_input)["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"
    assert out["updatedInput"] == {**tool_input, "command": "git push --force-with-lease origin x"}
    assert "updatedInput" not in render_claude_code(v, kind="pre_action", tool_input=tool_input, harness="codex")["hookSpecificOutput"]
    assert render_claude_code(v.model_copy(update={"mode": "shadow"}), kind="pre_action", tool_input=tool_input) is None


def test_api_reply_carries_updated_input(settings):
    s = ApiServer(_daemon(settings, LEASE), "tok", "127.0.0.1", 0)
    s.start_background()
    try:
        host, port = s.address
        body = {"adapter": {"name": "claude-code", "version": "t"}, "payload": _pre("git push -f origin feature/x", timeout=30)}
        req = urllib.request.Request(f"http://{host}:{port}/interlock/v1/hooks/claude-code?format=claude-code",
                                     data=json.dumps(body).encode(), method="POST")
        req.add_header("authorization", "Bearer tok"); req.add_header("content-type", "application/json")
        with urllib.request.urlopen(req, timeout=5) as r:
            out = json.loads(r.read().decode())["hookSpecificOutput"]
    finally:
        s.shutdown()
    assert out["permissionDecision"] == "ask"
    assert out["updatedInput"] == {"command": "git push --force-with-lease origin feature/x", "description": "push", "timeout": 30}


def test_a_repository_policy_cannot_turn_rewrites_on():
    from interlockd.policy.workspace import tighten

    pol, ignored = tighten(Policy(), {"rewrites": LEASE})
    assert pol.rewrites == [] and "rewrites" in ignored
