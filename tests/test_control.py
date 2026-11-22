"""Kill switch: pause refuses every action (any mode, per agent, timed), resume lifts it, a corrupt file fails closed."""

from __future__ import annotations

import json
import os
import stat
import time

import pytest

from interlockd import statefile
from interlockd.control import PauseState, pause, resume
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
    (settings.home / "pause.json").write_text("{not json", encoding="utf-8")
    assert daemon.decide(ev()).disposition == "block"


def test_cli(settings, monkeypatch, capsys):
    from interlockd.cli import main

    monkeypatch.setenv("INTERLOCK_HOME", str(settings.home))
    assert main(["pause", "--agent", "mcp-proxy", "--minutes", "5", "--reason", "drill"]) == 0
    st = PauseState(settings.home).current()
    assert st["agents"] == ["mcp-proxy"] and st["until"] and st["reason"] == "drill"
    assert stat.S_IMODE((settings.home / "pause.json").stat().st_mode) == 0o600
    assert "paused mcp-proxy" in capsys.readouterr().out
    assert main(["resume"]) == 0 and not (settings.home / "pause.json").exists()


def test_pause_file_is_a_flat_escape_free_state_file(settings):
    """Free-text reasons and odd agent names survive the round trip without any JSON escape on disk."""
    reason, agents = 'incident "42", café\\x\n50%', ["a,b", "claude-code", "ünï"]
    state = pause(settings.home, agents=agents, minutes=5, reason=reason)
    path = settings.home / "pause.json"
    raw = path.read_text(encoding="ascii")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and "\\" not in raw and raw.endswith("}\n")
    assert statefile.read_state(path, {"since": str, "agents": str, "reason": str}) is not None
    view = PauseState(settings.home).current()
    assert view == state and view["reason"] == reason and view["agents"] == sorted(agents)
    pause(settings.home)                                                  # no expiry: the key is absent
    assert "until" not in json.loads(path.read_text(encoding="ascii"))
    assert PauseState(settings.home).current()["until"] is None


def test_legacy_pause_file_still_honoured(daemon, settings):
    """A pause.json from the previous release (list, null, umask mode) keeps working after an upgrade."""
    path = settings.home / "pause.json"
    path.write_text(json.dumps({"since": "2026-01-01T00:00:00+00:00", "agents": ["codex"], "until": None,
                                "reason": "legacy"}, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o644)
    assert PauseState(settings.home).current() == {"since": "2026-01-01T00:00:00+00:00", "agents": ["codex"],
                                                   "until": None, "reason": "legacy"}
    assert daemon.decide(ev("codex")).disposition == "block" and daemon.decide(ev("claude-code")).disposition == "allow"


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX permission bits")
def test_group_writable_pause_file_fails_closed(daemon, settings):
    """A pause file others could have written is not trusted to narrow the pause: every agent is refused."""
    pause(settings.home, agents=["codex"])
    os.chmod(settings.home / "pause.json", 0o620)
    errors = []
    st = PauseState(settings.home, on_error=lambda f, why: errors.append(why)).current()
    assert st["reason"] == "pause file unreadable" and st["agents"] == [] and errors == ["state_permissions:mode"]
    assert daemon.decide(ev("claude-code")).disposition == "block"


def test_pause_write_failure_raises(settings, monkeypatch):
    monkeypatch.setattr(statefile.os, "replace", lambda *a: (_ for _ in ()).throw(OSError(28, "full")))
    with pytest.raises(OSError, match="pause.json"):
        pause(settings.home)
    assert not (settings.home / "pause.json").exists()
