"""Repository policies: picked up per call from the working directory; tighten-only unless the repo is trusted."""

from __future__ import annotations

import os

import pytest
import yaml

from interlockd.models import AdapterInfo, Context, InterlockEvent, ToolCall
from interlockd.pipeline import Daemon
from interlockd.policy import Policy
from interlockd.policy.workspace import find_repo_policy, tighten
from interlockd.store.memory import MemoryRepository
from interlockd.store.spool import Spool


@pytest.fixture(autouse=True)
def _repo_policies_on(monkeypatch):
    monkeypatch.setenv("INTERLOCK_REPO_POLICIES", "1")


def _repo(tmp_path, data, name="repo"):
    root = tmp_path / name
    (root / ".interlock").mkdir(parents=True)
    (root / ".interlock" / "policy.yaml").write_text(yaml.safe_dump(data))
    (root / "src").mkdir()
    return root


def _daemon(settings, mode="shadow", **trust):
    pol = Policy(); pol.mode = mode
    for k, v in trust.items():
        setattr(pol.trust, k, v)
    return Daemon(settings, spool=Spool(settings.spool_dir, fsync=False), repo=MemoryRepository(), policy=pol)


def _bash(d, cwd, cmd):
    ev = InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="claude-code"), session_hint=f"s{os.urandom(3).hex()}",
                        tool_call=ToolCall(name="Bash", arguments={"command": cmd}), context=Context(cwd=str(cwd)))
    return d.decide(ev)


def test_tighten_takes_only_stricter_settings():
    base = Policy()
    base.mcp.tools = {"github/*": "block"}
    p, ignored = tighten(base, {
        "mode": "enforce",
        "packs": {"enabled": ["shell"], "overrides": {
            "shell.sudo": {"action": "block"},                                # ask -> block: taken
            "git.force_push_protected_branch": {"enabled": False},            # disabling: ignored
            "shell.pipe_to_shell": {"action": "allow"},                       # softening: ignored
            "no.such_rule": {"action": "block"}}},
        "trust": {"allowed_hosts": ["github.com", "evil.example"], "protected_branches": ["develop"],
                  "allowed_git_remotes": ["github.com/acme/*"], "workspace_roots": ["/"]},
        "mcp": {"tools": {"github/delete_repo": "ask", "fs/*": "block"}},
        "judge": {"primary": {"type": "replay"}}, "fail_mode": {"security.persistence": "open"}, "mandate": {"mode": "log_only"},
        "profile": "laptop",                                                  # restates the default: not reported
    })
    assert p.mode == "enforce" and "profile" not in ignored
    assert p.rule_action("shell.sudo", "ask") == "block"
    assert p.rule_action("git.force_push_protected_branch", "block") == "block"
    assert p.rule_action("shell.pipe_to_shell", "block") == "block"
    assert set(p.packs.enabled) == set(base.packs.enabled)                    # packs can't be turned off
    assert p.trust.allowed_hosts == ["github.com"] and "develop" in p.trust.protected_branches
    assert p.trust.allowed_git_remotes == ["github.com/acme/*"] and p.trust.workspace_roots == []
    assert p.mcp.tools == {"github/*": "block", "fs/*": "block"}               # the `ask` could shadow your block
    for k in ("packs.overrides.git.force_push_protected_branch", "packs.overrides.shell.pipe_to_shell",
              "packs.overrides.no.such_rule", "packs.enabled (turning packs off)", "trust.workspace_roots",
              "mcp.tools['github/delete_repo']", "judge", "fail_mode", "mandate"):
        assert k in ignored, k


def test_repo_policy_applies_per_call(settings, tmp_path):
    repo = _repo(tmp_path, {"mode": "enforce", "packs": {"overrides": {"shell.sudo": {"action": "block"}}}})
    d = _daemon(settings)
    v = _bash(d, repo / "src", "sudo ls")
    assert v.mode == "enforce" and v.disposition == "block"
    rec = next(d.spool.iter_records(limit=1))
    assert rec["workspace_policy"]["path"] == str((repo / ".interlock" / "policy.yaml").resolve())
    assert rec["policy_sha256"] != d.policy_sha256
    other = tmp_path / "elsewhere"; other.mkdir()
    v = _bash(d, other, "sudo ls")
    assert v.mode == "shadow" and v.disposition == "ask"                      # your policy, untouched
    assert "workspace_policy" not in next(d.spool.iter_records(limit=1))


def test_poisoned_repo_cannot_loosen(settings, tmp_path):
    repo = _repo(tmp_path, {"mode": "shadow", "packs": {"enabled": [], "overrides": {
        "git.force_push_protected_branch": {"enabled": False}}}, "trust": {"allowed_hosts": ["*"]}})
    d = _daemon(settings, mode="enforce")
    v = _bash(d, repo, "git push --force origin main")
    assert v.mode == "enforce" and v.disposition == "block"
    assert "git.force_push_protected_branch" in {f.rule for f in v.findings}


def test_trusted_repo_applies_in_full_and_changes_are_picked_up(settings, tmp_path):
    repo = _repo(tmp_path, {"packs": {"overrides": {"shell.sudo": {"action": "allow"}}}})
    d = _daemon(settings, mode="enforce", trusted_workspaces=[str(tmp_path / "re*")])
    assert _bash(d, repo, "sudo ls").disposition == "allow"
    f = repo / ".interlock" / "policy.yaml"
    f.write_text(yaml.safe_dump({"packs": {"overrides": {"shell.sudo": {"action": "block"}}}, "trust": {"x": 1}}))
    os.utime(f, ns=(1, 1))                                                     # a different mtime, whatever the clock
    assert _bash(d, repo, "sudo ls").disposition == "ask"                     # `trust.x` does not validate: ignored whole
    f.write_text(yaml.safe_dump({"packs": {"overrides": {"shell.sudo": {"action": "block"}}}}))
    os.utime(f, ns=(2, 2))
    assert _bash(d, repo, "sudo ls").disposition == "block"


def test_lookup_stops_at_home_and_skips_interlock_state(settings, tmp_path):
    home = tmp_path / "home"
    _repo(home, {"mode": "enforce"}, name=".")                                 # ~/.interlock/policy.yaml is not a repo
    assert find_repo_policy(home / "src", stop=home) is None
    from interlockd.config import Settings

    s = Settings(home=tmp_path / "u" / ".interlock"); s.home.mkdir(parents=True)
    (s.home / "policy.yaml").write_text("mode: enforce\n")                     # Interlock's own state, one level up
    assert _bash(_daemon(s), tmp_path / "u", "sudo ls").mode == "shadow"
