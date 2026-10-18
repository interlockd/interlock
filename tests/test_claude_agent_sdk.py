"""Claude Agent SDK integration: the hooks guard_options() installs, driven with payloads captured from Claude Code
(the SDK hands its hooks the same shape), against a real daemon. Skipped when claude-agent-sdk is not installed."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("claude_agent_sdk")

from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

from interlockd.api import ApiServer
from interlockd.integrations.claude_agent_sdk import guard_options, make_hooks
from interlockd.integrations.client import InterlockClient

FIX = Path(__file__).parent / "fixtures" / "claude-code"


def _fixture(name, tmp_path):
    p = json.loads((FIX / name).read_text())
    p["cwd"], p["transcript_path"] = str(tmp_path), str(tmp_path / "none.jsonl")
    return p


@pytest.fixture
def client(settings, tmp_path):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    api = ApiServer(d, "tok", "127.0.0.1", 0); api.start_background()
    yield InterlockClient(url="http://{}:{}".format(*api.address), token="tok", agent_type="claude-agent-sdk"), d
    api.shutdown()


def test_pre_and_post_against_the_daemon(client, tmp_path):
    c, d = client
    pre, post = make_hooks(c)
    out = asyncio.run(pre(_fixture("pre-bash-block.json", tmp_path), "t1", {"signal": None}))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "[interlock]" in out["hookSpecificOutput"]["permissionDecisionReason"]
    ok = _fixture("pre-bash-block.json", tmp_path); ok["tool_input"] = {"command": "ls"}
    assert asyncio.run(pre(ok, "t2", {"signal": None})) == {}                 # no opinion: the SDK's own permissions decide
    out = asyncio.run(post(_fixture("post-read-inject.json", tmp_path), "t3", {"signal": None}))
    hso = out["hookSpecificOutput"]
    assert "evil" in json.dumps(_fixture("post-read-inject.json", tmp_path))
    assert hso["hookEventName"] == "PostToolUse" and "updatedToolOutput" in hso and "evil" not in json.dumps(hso["updatedToolOutput"])
    recs = list(d.spool.iter_records())
    assert {r["adapter"] for r in recs} == {"claude-agent-sdk"}


def test_guard_options_keeps_user_hooks_and_is_idempotent(client):
    c, _ = client

    async def mine(i, t, ctx):
        return {}

    opts = ClaudeAgentOptions(hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[mine])]})
    guard_options(guard_options(opts, c), c)
    assert len(opts.hooks["PreToolUse"]) == 2 and opts.hooks["PreToolUse"][1].hooks == [mine]
    assert len(opts.hooks["PostToolUse"]) == 1


def test_daemon_down(monkeypatch, tmp_path):
    pre, _ = make_hooks(InterlockClient(url="http://127.0.0.1:9", token="tok"))
    p = _fixture("pre-bash-block.json", tmp_path)
    assert asyncio.run(pre(p, "t", {"signal": None})) == {}                    # fail open by default
    monkeypatch.setenv("INTERLOCK_FAIL_MODE", "closed")
    out = asyncio.run(pre(p, "t", {"signal": None}))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
