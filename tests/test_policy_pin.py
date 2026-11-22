"""Policy pinning (Requirement 7): pin and diff, once-per-digest recording, restore, managed pin, in-session accept,
deny-all without a pinned copy, and a failed pin leaving the previous pin in place."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
import yaml

from interlockd import records
from interlockd.config import Settings
from interlockd.integrity import Baseline
from interlockd.models import AdapterInfo, Capabilities, Context, InterlockEvent, ToolCall
from interlockd.operator import OperatorActions
from interlockd.pipeline import Daemon
from interlockd.policy import Policy
from interlockd.policy import managed as mp
from interlockd.policy import pin as pp
from interlockd.protection import HOME, ProtectionState
from interlockd.store.spool import Spool

POLICY = "# my policy\nmode: enforce\nprofile: laptop\n"
MARKER = "MARKER-5f1c"


class Env:
    """A Home with a policy file, a baseline, protection state, operator actions and a guard (no daemon)."""

    def __init__(self, home: Path, policy: str | None = POLICY, *, pin_now: bool = True):
        self.home = home
        if policy is not None:
            (home / "policy.yaml").write_text(policy, encoding="utf-8")
        self.spool = Spool(home / "spool", fsync=False)
        self.baseline = Baseline(created_at="2026-10-17T09:00:00Z", version="0")
        self.baseline.save(home)
        self.protection = ProtectionState(home, self.spool, None, lambda: "enforce", harnesses=list)
        self.operator = OperatorActions(self.spool)
        self.guard = pp.PolicyGuard(home, lambda: self.baseline, self.protection, self.operator, spool=self.spool)
        if pin_now and policy is not None:
            pp.pin(home, "policy", baseline=self.baseline)

    def control(self, record: str) -> list[dict]:
        return [r for r in self.spool.iter_records(reverse=False)
                if r.get("kind") == "control" and r["arguments"]["record"] == record]

    def reasons(self) -> set[str]:
        return {r.reason for r in self.protection.reasons() if r.subject == HOME}

    def write(self, text: str, name: str = "policy.yaml") -> None:
        (self.home / name).write_text(text, encoding="utf-8")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---- pin and diff ------------------------------------------------------------------------------------------------


def test_pin_keeps_a_byte_identical_private_copy_and_saves_the_digest(home):
    env = Env(home, pin_now=False)
    digest = pp.pin(home, "policy", baseline=env.baseline)
    copy = home / pp.PINNED_DIR / "policy.yaml"
    assert copy.read_bytes() == POLICY.encode()
    assert digest == _sha(POLICY) == env.baseline.policy_file_sha256
    assert Baseline.load(home).policy_file_sha256 == digest
    if os.name == "posix":
        assert stat.S_IMODE(copy.stat().st_mode) == 0o600
        assert stat.S_IMODE(copy.parent.stat().st_mode) == 0o700
    assert pp.pinned_copy(home, "policy", digest) == POLICY.encode()
    assert pp.pinned_copy(home, "policy", "0" * 64) is None          # a copy that is not the pin is not used


def test_top_level_diff_names_keys_only():
    a = yaml.safe_dump({"mode": "enforce", "profile": "laptop", "trust": {"x": 1}}).encode()
    b = yaml.safe_dump({"mode": MARKER, "trust": {"x": 1}, "fail_mode": {"default": MARKER}}).encode()
    d = pp.top_level_diff(a, b)
    assert d == {"added": ["fail_mode"], "removed": ["profile"], "changed": ["mode"], "unparseable": False}
    assert MARKER not in json.dumps(d)
    assert pp.top_level_diff(a, b"mode: [unclosed\n")["unparseable"] is True
    assert pp.top_level_diff(a, None) == {"added": [], "removed": ["mode", "profile", "trust"], "changed": [],
                                          "unparseable": False}


# ---- PolicyGuard.check -------------------------------------------------------------------------------------------


def test_no_pin_pins_and_records_baseline_set(home):
    env = Env(home, pin_now=False)
    env.guard.check()
    assert env.baseline.policy_file_sha256 == _sha(POLICY)
    sets = env.control("policy_baseline_set")
    assert [r["arguments"]["sha256"] for r in sets] == [_sha(POLICY)]
    assert not env.control("policy_modified") and not env.reasons()


def test_unexplained_change_is_recorded_once_per_digest_without_content(home):
    env = Env(home)
    env.write(POLICY.replace("mode: enforce", "mode: shadow") + f"fail_mode: {{default: {MARKER}}}\n")
    for _ in range(3):
        env.guard.check()
    mods = env.control("policy_modified")
    assert len(mods) == 1
    args = mods[0]["arguments"]
    assert args["pinned_sha256"] == _sha(POLICY)
    assert (args["added"], args["changed"], args["removed"]) == (["fail_mode"], ["mode"], [])
    assert MARKER not in json.dumps(mods[0])
    assert mods[0]["findings"][0]["rule"] == "control.policy_modified"
    assert env.reasons() == {"policy_modified"}
    assert env.baseline.policy_file_sha256 == _sha(POLICY)              # the pin did not move

    env.write("mode: shadow\n")                                           # a second, different digest
    env.guard.check()
    env.guard.check()
    assert len(env.control("policy_modified")) == 2
    assert len(env.control("protection_state")) == 1                      # the reason was already open


def test_restoring_the_file_clears_the_reason_and_records_restored(home):
    env = Env(home)
    env.write("mode: shadow\n")
    env.guard.check()
    env.write(POLICY)
    env.guard.check()
    restored = env.control("policy_restored")
    assert [r["arguments"]["sha256"] for r in restored] == [_sha(POLICY)]
    assert not env.reasons()
    env.guard.check()
    assert len(env.control("policy_restored")) == 1                       # nothing to restore any more


def test_change_explained_by_an_operator_action_is_pinned(home):
    env = Env(home)
    env.operator.add(records.operator_action("policy_accept"))
    new = "mode: shadow\n"
    env.write(new)
    env.guard.check()
    assert env.baseline.policy_file_sha256 == _sha(new)
    assert (home / pp.PINNED_DIR / "policy.yaml").read_text() == new
    assert not env.control("policy_modified") and not env.reasons()


def test_a_missing_pinned_copy_is_recreated_while_the_file_matches(home):
    env = Env(home)
    (home / pp.PINNED_DIR / "policy.yaml").unlink()
    env.guard.check()
    assert pp.pinned_copy(home, "policy", _sha(POLICY)) == POLICY.encode()


def test_failed_pin_leaves_the_previous_pin_and_records_failure(home):
    env = Env(home)
    env.write("mode: shadow\n")
    (home / "integrity-baseline.json.tmp").mkdir()                        # the baseline cannot be saved
    with pytest.raises(OSError):
        pp.pin(home, "policy", baseline=env.baseline)
    assert env.baseline.policy_file_sha256 == _sha(POLICY)
    assert Baseline.load(home).policy_file_sha256 == _sha(POLICY)
    assert (home / pp.PINNED_DIR / "policy.yaml").read_text() == POLICY
    assert [p.name for p in (home / pp.PINNED_DIR).iterdir()] == ["policy.yaml"]   # no temp file left

    env.operator.add(records.operator_action("policy_accept"))
    env.guard.check()
    failed = [r for r in env.control("policy_baseline_set") if r["arguments"]["failed"]]
    assert len(failed) == 1
    assert env.baseline.policy_file_sha256 == _sha(POLICY)


# ---- start-up load and deny-all ----------------------------------------------------------------------------------


def _settings(home: Path, workspace: Path | None = None) -> Settings:
    s = Settings(home=home)
    s.workspace_roots = [str(workspace)] if workspace else []
    return s


def test_load_for_daemon_uses_disk_when_it_matches_the_pin(home):
    env = Env(home)
    load = pp.load_for_daemon(_settings(home), env.baseline)
    assert (load.source, load.policy.mode) == ("disk", "enforce")


def test_load_for_daemon_enforces_the_pinned_copy_when_the_file_changed(home):
    env = Env(home)
    env.write("mode: shadow\n")
    load = pp.load_for_daemon(_settings(home), env.baseline)
    assert (load.source, load.policy.mode) == ("pinned", "enforce")
    assert load.on_disk_sha256 == _sha("mode: shadow\n") and load.pinned_sha256 == _sha(POLICY)


@pytest.mark.parametrize("damage", ["absent", "tampered", "unparseable"])
def test_deny_all_without_a_usable_pinned_copy(home, damage):
    env = Env(home)
    copy = home / pp.PINNED_DIR / "policy.yaml"
    if damage == "absent":
        copy.unlink()
    elif damage == "tampered":
        copy.write_text("mode: shadow\n")
    else:                                   # pinned digest names an unparseable copy
        copy.write_text("mode: [unclosed\n")
        env.baseline.policy_file_sha256 = _sha("mode: [unclosed\n")
    env.write("mode: shadow\n# edited\n")
    load = pp.load_for_daemon(_settings(home), env.baseline)
    assert load.source == "deny_all" and load.policy.mode == "enforce"

    s = _settings(home)
    d = Daemon(s, spool=env.spool, policy=load.policy)
    env.guard.adopt(load)
    d.policy_guard = env.guard
    ev = InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="claude-code"), session_hint="s1",
                        tool_call=ToolCall(name="Read", arguments={"file_path": "/ws/a.py"}),
                        context=Context(cwd="/ws"))
    v = d.decide(ev)                                       # even a tier-0 read is refused
    assert (v.disposition, v.mode) == ("block", "enforce")
    assert "policy_modified" in v.notice and "interlock policy accept" in v.notice
    assert any(f.rule == "control.policy_modified" for f in v.findings)


def test_deny_all_lifts_once_the_file_is_accepted(home):
    env = Env(home)
    (home / pp.PINNED_DIR / "policy.yaml").unlink()
    env.write("mode: shadow\n")
    load = pp.load_for_daemon(_settings(home), env.baseline)
    reloaded = []
    env.guard._reload = lambda: reloaded.append(True)
    env.guard.adopt(load)
    env.guard.check()
    assert env.guard.lockdown and env.reasons() == {"policy_modified"}
    env.operator.add(records.operator_action("policy_accept"))
    env.guard.check()
    assert reloaded == [True] and not env.guard.lockdown and not env.reasons()


def test_without_a_baseline_the_pinned_copy_is_the_pin(home):
    Env(home)
    (home / "integrity-baseline.json").unlink()
    (home / "policy.yaml").write_text("mode: shadow\n")
    load = pp.load_for_daemon(_settings(home), None)
    assert (load.source, load.policy.mode) == ("pinned", "enforce")


# ---- managed policy ----------------------------------------------------------------------------------------------


MANAGED = yaml.safe_dump({"mode": "enforce"})


def test_managed_change_serves_the_pinned_copy_until_the_console_sync(home, monkeypatch):
    monkeypatch.setattr(mp, "STAT_TTL_S", 0.0)
    env = Env(home)
    env.write(MANAGED, mp.FILE_NAME)
    m = mp.ManagedPolicy(home)
    m.set_guard(env.guard)
    pol, prov = m.resolve(Policy())
    assert pol.mode == "enforce" and env.baseline.managed_policy_file_sha256 == _sha(MANAGED)   # first sight: pinned

    loosened = yaml.safe_dump({"profile": "team"})
    env.write(loosened, mp.FILE_NAME)
    for _ in range(2):
        pol, prov = m.resolve(Policy())
        assert pol.mode == "enforce"                                       # still the pinned floor
        assert prov["path"].endswith(f"{pp.PINNED_DIR}/{mp.FILE_NAME}")
    mods = env.control("policy_modified")
    assert len(mods) == 1 and mods[0]["arguments"]["policy_kind"] == "managed"
    assert mods[0]["findings"][0]["rule"] == "control.managed_policy_modified"
    assert env.reasons() == {"managed_policy_modified"}

    env.operator.add(records.operator_action("console_sync"))
    env.guard.check()                                                      # HookWatch pass: pins the sync
    pol, prov = m.resolve(Policy())
    assert pol.mode == "shadow" and prov["path"] == str(mp.managed_path(home))
    assert not env.reasons()


def test_managed_policy_without_a_guard_is_unchanged(home, monkeypatch):
    monkeypatch.setattr(mp, "STAT_TTL_S", 0.0)
    (home / mp.FILE_NAME).write_text(MANAGED)
    pol, prov = mp.ManagedPolicy(home).resolve(Policy())
    assert pol.mode == "enforce" and prov["path"] == str(mp.managed_path(home))


# ---- in-session accept (7.8) -------------------------------------------------------------------------------------


def _write_event(kind: str, home: Path, cwd: Path, content: str) -> InterlockEvent:
    return InterlockEvent(kind=kind, adapter=AdapterInfo(name="claude-code"), session_hint="sess-pin",
                          tool_call=ToolCall(name="Write", id="tc-1",
                                             arguments={"file_path": str(home / "policy.yaml"), "content": content}),
                          context=Context(cwd=str(cwd)), capabilities=Capabilities(ask=True))


@pytest.fixture
def dot_home(tmp_path) -> Path:
    h = tmp_path / ".interlock"       # inside the workspace: `.interlock/**` is a protected path
    h.mkdir()
    return h


def _session_daemon(home: Path, env: Env, action: str) -> Daemon:
    pol = Policy.model_validate({"mode": "enforce",
                                 "packs": {"overrides": {"persistence.agent_config_write": {"action": action}}}})
    d = Daemon(_settings(home, home.parent), spool=env.spool, policy=pol)
    d.policy_guard = env.guard
    return d


def test_an_approved_in_session_write_is_pinned(dot_home):
    env = Env(dot_home)
    d = _session_daemon(dot_home, env, "ask")
    new = "mode: enforce\nprofile: team\n"
    pre = d.decide(_write_event("pre_action", dot_home, dot_home.parent, new))
    assert pre.disposition == "ask"
    env.write(new)                                   # the tool ran: the Operator answered allow
    env.guard.check()                                # a watch pass before the post hook does not raise an alarm
    assert not env.control("policy_modified")
    d.decide(_write_event("post_action", dot_home, dot_home.parent, new))
    assert env.baseline.policy_file_sha256 == _sha(new)
    assert (dot_home / pp.PINNED_DIR / "policy.yaml").read_text() == new
    acts = env.control("operator_action")
    assert len(acts) == 1
    a = acts[0]["arguments"]
    assert (a["action"], a["via"], a["caused_by"], a["confirmed"]) == ("policy_accept", "hook_session",
                                                                       pre.event_id, True)
    env.guard.check()
    assert not env.control("policy_modified") and not env.reasons()


def test_a_write_that_was_not_asked_is_reported(dot_home):
    env = Env(dot_home)
    d = _session_daemon(dot_home, env, "allow")
    new = "mode: shadow\n"
    pre = d.decide(_write_event("pre_action", dot_home, dot_home.parent, new))
    assert pre.disposition == "allow"
    env.write(new)
    d.decide(_write_event("post_action", dot_home, dot_home.parent, new))
    assert env.baseline.policy_file_sha256 == _sha(POLICY)
    assert not env.control("operator_action")
    env.guard.check()
    assert len(env.control("policy_modified")) == 1 and env.reasons() == {"policy_modified"}


# ---- daemon wiring -----------------------------------------------------------------------------------------------


def test_attach_integrity_reports_a_modified_policy_before_serving(home):
    from interlockd.cli import attach_integrity

    Env(home)                                          # pinned POLICY, baseline saved
    (home / "integrity-baseline.json").unlink()        # a deleted baseline must not accept the edit
    (home / "policy.yaml").write_text("mode: shadow\n")
    s = _settings(home)
    load = pp.load_for_daemon(s, Baseline.load(home))
    d = Daemon(s, spool=Spool(s.spool_dir, fsync=False), policy=load.policy)
    attach_integrity(d, home, None, policy_load=load)
    assert d.policy_guard.source == "pinned" and d.mode == "enforce"
    assert d.baseline.policy_file_sha256 == _sha(POLICY)
    assert {r.reason for r in d.protection.reasons()} == {"policy_modified"}
    assert d.managed_policy.guard is d.policy_guard


# ---- `interlock policy accept | revert | diff` (7.5-7.7, 7.11) ----------------------------------------------------
#
# The CLI runs against the sandboxed Home through INTERLOCK_HOME, with a fake service that reports no running daemon:
# nothing here talks to the machine's own daemon or service manager.

class _NoDaemon:
    def runs_here(self) -> bool:
        return False


@pytest.fixture
def cli_env(home, tmp_path, monkeypatch) -> Env:
    from interlockd import cli

    user = tmp_path / "user"
    user.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setenv("USERPROFILE", str(user))
    monkeypatch.setenv("INTERLOCK_HOME", str(home))
    monkeypatch.chdir(proj)
    monkeypatch.setattr(cli, "_service", lambda s, backend=None: _NoDaemon())
    env = Env(home)
    env.protection.add_reason(HOME, "policy_modified", "", "2026-10-17T10:00:00Z")
    return env


def _cli(*argv: str) -> int:
    from interlockd.cli import main

    return main(list(argv))


def _actions(env: Env) -> list[dict]:
    return [r for r in env.control("operator_action")]


def _persisted_reasons(home: Path) -> set[str]:
    return set(json.loads((home / "protection-state.json").read_text("utf-8"))["reasons"])


EDITED = "# my policy\nmode: shadow\nprofile: laptop\n"


def test_policy_accept_pins_the_file_records_both_digests_and_clears(cli_env, capsys):
    home = cli_env.home
    cli_env.write(EDITED)
    assert _cli("policy", "accept") == 0
    assert _sha(POLICY)[:12] in capsys.readouterr().out
    assert Baseline.load(home).policy_file_sha256 == _sha(EDITED)
    assert (home / pp.PINNED_DIR / "policy.yaml").read_text() == EDITED
    [action] = _actions(cli_env)
    assert action["arguments"]["action"] == "policy_accept" and not action["arguments"]["failed"]
    [pinned] = [r for r in cli_env.control("policy_baseline_set") if r["arguments"].get("caused_by")]
    assert pinned["arguments"]["caused_by"] == action["event_id"]
    assert pinned["arguments"]["previous_sha256"] == _sha(POLICY)
    assert pinned["arguments"]["sha256"] == _sha(EDITED)
    assert EDITED not in json.dumps(pinned)                                  # digests only (7.9)
    assert _persisted_reasons(home) == set()
    assert cli_env.spool.verify()["ok"]


def test_policy_accept_refuses_a_file_that_does_not_load(cli_env, capsys):
    cli_env.write("mode: [unterminated\n")
    assert _cli("policy", "accept") == 1
    assert "does not load" in capsys.readouterr().err
    assert Baseline.load(cli_env.home).policy_file_sha256 == _sha(POLICY)
    assert _actions(cli_env) == [] and _persisted_reasons(cli_env.home) == {"home__policy_modified"}


def test_failed_policy_accept_keeps_the_pin_and_opens_no_grace(cli_env, monkeypatch, capsys):
    home = cli_env.home
    cli_env.write(EDITED)

    def boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(pp, "pin", boom)
    assert _cli("policy", "accept") == 1
    assert "the policy pin was not updated" in capsys.readouterr().err       # 7.11
    assert Baseline.load(home).policy_file_sha256 == _sha(POLICY)
    assert (home / pp.PINNED_DIR / "policy.yaml").read_text() == POLICY
    first, second = _actions(cli_env)
    assert second["arguments"]["failed"] and second["arguments"]["caused_by"] == first["event_id"]
    ops = OperatorActions(cli_env.spool)
    ops.seed()
    assert ops.explains("policy") is None             # the daemon will not pin the edit on the failed accept's behalf
    assert _persisted_reasons(home) == {"home__policy_modified"}


def test_policy_revert_restores_the_pin_and_keeps_a_dated_backup(cli_env, capsys):
    home = cli_env.home
    cli_env.write(EDITED)
    assert _cli("policy", "revert") == 0
    assert (home / "policy.yaml").read_bytes() == POLICY.encode()            # byte-for-byte
    [backup] = list(home.glob("policy.yaml.*.rejected"))
    assert backup.read_text() == EDITED and str(backup) in capsys.readouterr().out
    if os.name == "posix":
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    [action] = _actions(cli_env)
    assert action["arguments"]["action"] == "policy_revert"
    [restored] = cli_env.control("policy_restored")
    assert restored["arguments"]["rejected_sha256"] == _sha(EDITED)
    assert restored["arguments"]["sha256"] == _sha(POLICY)
    assert restored["arguments"]["caused_by"] == action["event_id"]
    assert Baseline.load(home).policy_file_sha256 == _sha(POLICY)            # the pin did not move
    assert _persisted_reasons(home) == set()
    cli_env.write("mode: enforce\n")                                         # a second revert the same day
    assert _cli("policy", "revert") == 0
    assert len(list(home.glob("policy.yaml.*.rejected"))) == 2               # never overwrites a backup


def test_policy_revert_without_a_pinned_copy_changes_nothing(cli_env, capsys):
    home = cli_env.home
    cli_env.write(EDITED)
    (home / pp.PINNED_DIR / "policy.yaml").unlink()
    assert _cli("policy", "revert") == 1
    assert "no pinned copy" in capsys.readouterr().err
    assert (home / "policy.yaml").read_text() == EDITED
    assert _actions(cli_env) == [] and not list(home.glob("*.rejected"))


def test_policy_diff_is_read_only(cli_env, capsys):
    home = cli_env.home
    assert _cli("policy", "diff") == 0
    assert "matches its pin" in capsys.readouterr().out
    cli_env.write(EDITED + "extra: 1\n")
    files = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    assert _cli("policy", "diff") == 1
    out = capsys.readouterr().out
    assert "-mode: enforce" in out and "+mode: shadow" in out
    assert "added: extra" in out and "changed: mode" in out
    assert {p: p.read_bytes() for p in home.rglob("*") if p.is_file()} == files
    assert _actions(cli_env) == []
