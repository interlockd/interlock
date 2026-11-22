"""`interlock ack` (Requirements 11.5, 11.8, 11.9; 9.12 for an unreadable state document).

Every test runs against a sandboxed HOME / INTERLOCK_HOME. The daemon-up cases use an in-process ApiServer on a free
port of their own; nothing here talks to the daemon or the service manager of the machine running the suite.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from interlockd import cli, integrity, operator
from interlockd import identity as identity_mod
from interlockd.api import ApiServer
from interlockd.cli import main
from interlockd.config import Settings
from interlockd.pipeline import Daemon
from interlockd.policy import pin as policy_pin
from interlockd.protection import FILE as STATE_FILE
from interlockd.protection import ProtectionState
from interlockd.store.spool import Spool

POLICY = "# my policy\nmode: enforce\nprofile: laptop\n"
EDITED = "# my policy\nmode: shadow\nprofile: laptop\n"
TOKEN = "test-token-ack"
AT = "2026-10-17T10:00:00Z"


class FakeService:
    """Stands in for ServiceManager: `runs_here` only; ack never stops or restarts the daemon."""

    def __init__(self, running: bool = False):
        self.running = running

    def runs_here(self) -> bool:
        return self.running


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    user = tmp_path / "user"
    h = user / ".interlock"
    h.mkdir(parents=True)
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setenv("USERPROFILE", str(user))
    monkeypatch.setenv("INTERLOCK_HOME", str(h))
    monkeypatch.chdir(proj)
    (h / "policy.yaml").write_text(POLICY, encoding="utf-8")
    (h / "token").write_text(TOKEN + "\n", encoding="utf-8")
    (h / "token").chmod(0o600)
    base = integrity.Baseline.from_disk(h, None)
    base.save(h)
    policy_pin.pin(h, "policy", baseline=base)
    return h


@pytest.fixture
def svc(monkeypatch):
    fake = FakeService()
    monkeypatch.setattr(cli, "_service", lambda s, backend=None: fake)
    return fake


def _settings() -> Settings:
    return Settings.load(None)


def _control(record: str) -> list[dict]:
    s = _settings()
    if not s.spool_dir.exists():
        return []
    return [r for r in Spool(s.spool_dir).iter_records(reverse=False)
            if r.get("kind") == "control" and r["arguments"].get("record") == record]


def _persisted(home: Path, *reasons: tuple[str, str]) -> None:
    ps = ProtectionState(home, Spool(_settings().spool_dir), None, lambda: "enforce", harnesses=list)
    for subject, reason in reasons:
        ps.add_reason(subject, reason, "", AT)


def _state_reasons(home: Path) -> set[str]:
    return set(json.loads((home / STATE_FILE).read_text("utf-8"))["reasons"])


# ---- nothing to acknowledge / declined (11.9) ---------------------------------------------------------------------

def test_nothing_to_acknowledge_changes_nothing(home, svc, capsys):
    before = (home / integrity.BASELINE).read_bytes()
    assert main(["ack", "-y"]) == 0
    assert "nothing acknowledged" in capsys.readouterr().out
    assert _control("operator_action") == [] and _control("operator_ack") == []
    assert (home / integrity.BASELINE).read_bytes() == before


@pytest.mark.parametrize("answer", [None, "", "n", "sure"])
def test_declining_changes_nothing(home, svc, monkeypatch, capsys, answer):
    _persisted(home, ("home", "policy_modified"))
    (home / "policy.yaml").write_text(EDITED, encoding="utf-8")
    baseline, state = (home / integrity.BASELINE).read_bytes(), (home / STATE_FILE).read_bytes()
    if answer is not None:                          # an interactive "no" (Enter alone is not an explicit yes)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda prompt: answer)
    assert main(["ack"]) == 0                       # answer None: not a terminal and no --yes
    out = capsys.readouterr().out
    assert "policy_modified" in out and "nothing acknowledged" in out
    assert _control("operator_action") == [] and _control("operator_ack") == []
    assert (home / integrity.BASELINE).read_bytes() == baseline and (home / STATE_FILE).read_bytes() == state


# ---- daemon down: the persisted document --------------------------------------------------------------------------

def test_ack_while_down_lists_records_rebaselines_and_clears(home, svc, capsys):
    _persisted(home, ("claude-code", "shim_modified"), ("home", "policy_modified"), ("home", "token_permissions"))
    (home / "policy.yaml").write_text(EDITED, encoding="utf-8")
    assert main(["ack", "-y"]) == 0
    out = capsys.readouterr().out
    for line in ("claude-code", "shim_modified", "policy_modified", "token_permissions", AT):
        assert line in out                                                   # 11.5: what, where, since when
    assert "policy.yaml" in out and "changed: mode" in out                   # the re-pin is shown, not silent
    [action] = [r for r in _control("operator_action") if r["arguments"]["action"] == "ack"]
    [ack] = _control("operator_ack")
    assert action["received_at"] <= ack["received_at"]                       # recorded before the change (11.1)
    assert set(ack["arguments"]["reasons"]) == {"claude-code:shim_modified", "home:policy_modified",
                                                "home:token_permissions"}
    assert _state_reasons(home) == set()
    base = integrity.Baseline.load(home)
    edited = (home / "policy.yaml").read_bytes()
    assert base.policy_file_sha256 == hashlib.sha256(edited).hexdigest()
    assert (home / "pinned" / "policy.yaml").read_bytes() == edited          # digest and copy moved together
    assert Spool(_settings().spool_dir).verify()["ok"]


def test_ack_replaces_an_unreadable_state_document(home, svc, capsys):
    (home / STATE_FILE).write_text("{not json", encoding="utf-8")
    (home / STATE_FILE).chmod(0o600)
    assert main(["ack", "-y"]) == 0
    assert "state_unreadable" in capsys.readouterr().out
    [ack] = _control("operator_ack")
    assert ack["arguments"]["reasons"] == ["home:state_unreadable"]
    assert _state_reasons(home) == set()                                     # the file was replaced (9.12)


def test_a_running_daemon_that_does_not_identify_itself_is_not_bypassed(home, svc, capsys):
    _persisted(home, ("home", "policy_modified"))
    svc.running = True
    assert main(["ack", "-y"]) == 1
    assert "nothing acknowledged" in capsys.readouterr().err
    assert _control("operator_action") == [] and _state_reasons(home) == {"home__policy_modified"}


# ---- daemon up: the health snapshot and the ack route (11.8) -----------------------------------------------------

@pytest.fixture
def daemon_up(home, svc):
    s = _settings()
    daemon = Daemon(s, spool=Spool(s.spool_dir))
    daemon.protection = ProtectionState(home, daemon.spool, None, lambda: "enforce", harnesses=lambda: ["claude-code"])
    daemon.operator_actions = operator.OperatorActions(daemon.spool)
    server = ApiServer(daemon, TOKEN, "127.0.0.1", 0)
    server.start_background()
    identity_mod.write(home, server.identity)
    (home / "daemon.json").write_text(json.dumps({"listen": f"127.0.0.1:{server.address[1]}"}), encoding="utf-8")
    yield daemon
    server.shutdown()


def test_ack_through_the_daemon_while_compromised(home, daemon_up, capsys):
    ps = daemon_up.protection
    ps.add_reason("claude-code", "hook_removed", "", AT)
    ps.add_reason("home", "token_modified", "", AT)
    assert ps.aggregate() == "compromised"
    assert main(["ack", "-y"]) == 0
    out = capsys.readouterr().out
    assert "hook_removed" in out and "token_modified" in out and "interlock restart" in out
    assert ps.reasons() == [] and ps.aggregate() == "protected"
    [action] = [r for r in _control("operator_action") if r["arguments"]["action"] == "ack"]
    assert daemon_up.operator_actions.explains("token")["event_id"] == action["event_id"]   # delivered via daemon
    [ack] = _control("operator_ack")
    assert set(ack["arguments"]["reasons"]) == {"claude-code:hook_removed", "home:token_modified"}
    assert ack["mode"] == daemon_up.mode                                    # written by the daemon, not the CLI


def test_ack_through_the_daemon_with_nothing_unresolved(home, daemon_up, capsys):
    assert main(["ack", "-y"]) == 0
    assert "nothing acknowledged" in capsys.readouterr().out
    assert _control("operator_action") == [] and _control("operator_ack") == []
