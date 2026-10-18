"""Kill switch: pause refuses every action (any mode, per agent, timed), resume lifts it, a corrupt file fails closed."""

from __future__ import annotations

import json
import os
import time

import pytest

from interlockd.control import pause, resume
from interlockd.models import AdapterInfo, Context, Identity, InterlockEvent, ToolCall
from interlockd.pipeline import Daemon
from interlockd.policy import Policy
from interlockd.render import render_claude_code
from interlockd.store.memory import MemoryRepository
from interlockd.store.spool import Spool


@pytest.fixture
def daemon(settings):
    pol = Policy(); pol.mode = "shadow"                                   # shadow: pause must still enforce
    return Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)


def ev(agent="claude-code", cmd="ls"):
    return InterlockEvent(kind="pre_action", adapter=AdapterInfo(name=agent), identity=Identity(agent_type=agent),
                          tool_call=ToolCall(name="Bash", arguments={"command": cmd}), context=Context(cwd="/ws"))


def test_pause_blocks_everything_even_in_shadow(daemon, settings):
    assert daemon.decide(ev()).disposition == "allow"
    pause(settings.home, reason="incident 42")
    v = daemon.decide(ev())
    assert v.disposition == "block" and v.mode == "enforce" and "incident 42" in v.notice
    assert any(f.rule == "control.paused" for f in v.findings)
    out = render_claude_code(v, kind="pre_action")                       # rendered, despite the policy being shadow
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert resume(settings.home) and daemon.decide(ev()).disposition == "allow"
    assert not resume(settings.home)


def test_pause_one_agent_and_timed(daemon, settings):
    pause(settings.home, agents=["codex"])
    assert daemon.decide(ev("codex")).disposition == "block" and daemon.decide(ev("claude-code")).disposition == "allow"
    pause(settings.home, minutes=0.0005)                                  # ~30 ms
    time.sleep(0.1); os.utime(settings.home / "pause.json")               # same content, newer mtime: re-read
    assert daemon.decide(ev()).disposition == "allow"                     # expired


def test_corrupt_pause_file_fails_closed(daemon, settings):
    (settings.home / "pause.json").write_text("{not json")
    assert daemon.decide(ev()).disposition == "block"


def test_cli(settings, monkeypatch, capsys):
    from interlockd.cli import main

    monkeypatch.setenv("INTERLOCK_HOME", str(settings.home))
    assert main(["pause", "--agent", "mcp-proxy", "--minutes", "5", "--reason", "drill"]) == 0
    st = json.loads((settings.home / "pause.json").read_text())
    assert st["agents"] == ["mcp-proxy"] and st["until"] and st["reason"] == "drill"
    assert "paused mcp-proxy" in capsys.readouterr().out
    assert main(["resume"]) == 0 and not (settings.home / "pause.json").exists()
