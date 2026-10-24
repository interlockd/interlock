"""Path forms across platforms, simulated on any OS: forward slashes with the drive kept, matched without case on
macOS and Windows (whose default file systems ignore it), shown with the case the agent used."""

from __future__ import annotations

import pytest

from interlockd import paths


@pytest.fixture
def win(monkeypatch):
    monkeypatch.setattr(paths, "WINDOWS", True)
    monkeypatch.setattr(paths, "CASE_INSENSITIVE", True)
    monkeypatch.setattr(paths.os.path, "expanduser", lambda p: p.replace("~", r"C:\Users\Me", 1) if p.startswith("~") else p)


def test_canonical_form(win):
    assert paths.normalize_path(r"C:\Users\Me\.CLAUDE\settings.json", None) == "C:/Users/Me/.CLAUDE/settings.json"
    assert paths.normalize_path(r"src\..\src\a.py", r"C:\WS\Proj") == "C:/WS/Proj/src/a.py"
    assert paths.normalize_path("~/.ssh/id_ed25519", None) == "C:/Users/Me/.ssh/id_ed25519"
    assert paths.normalize_path("C:/ws/proj/b.py", "D:\\other") == "C:/ws/proj/b.py"     # drive path is absolute
    assert paths.home() == "C:/Users/Me"


def test_roots_patterns_and_case(win):
    p = paths.normalize_path(r"C:\WS\Proj\.Kiro\Settings\hooks.json", None)
    assert paths.is_under(p, [r"c:\ws\proj"]) and not paths.is_under(p, [r"C:\WS\Pro"])
    assert paths.is_protected(p, [r"C:\WS\Proj"], [".kiro/**"])
    assert paths.is_sensitive(paths.normalize_path(r"C:\WS\Proj\.ENV", None), ["**/.env"])
    assert paths.is_sensitive(paths.normalize_path(r"C:\Users\Me\.SSH\config", None), ["~/.ssh/**"])
    assert paths.is_protected(paths.normalize_path(r"C:\WS\Proj\.github\Workflows\ci.yml", None), [r"C:\WS\Proj"],
                              [".github/workflows/**"])


def _persist(raw: str) -> set[str]:
    from interlockd.det import DetResult
    from interlockd.det.packs import _persistence_path_check
    from interlockd.policy import Policy

    res = DetResult()
    _persistence_path_check(paths.normalize_path(raw, None), res, Policy(), [], "args.path")
    return {f.rule for f in res.findings}


def test_windows_persistence_paths(win, monkeypatch):
    monkeypatch.setattr("interlockd.det.packs.home_dir", paths.home)
    assert "persistence.cron_or_scheduler" in _persist(
        r"C:\Users\Me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat")
    assert "persistence.shell_rc" in _persist(r"C:\Users\Me\Documents\PowerShell\Microsoft.PowerShell_profile.ps1")
    assert "persistence.agent_config_write" in _persist(r"C:\Users\Me\.Claude\settings.json")


def test_case_variants_are_caught_on_case_insensitive_systems(monkeypatch, tmp_path):
    """macOS (default APFS) and Windows ignore case: ~/.CLAUDE/settings.json is the real ~/.claude/settings.json."""
    monkeypatch.setattr(paths, "CASE_INSENSITIVE", True)
    home = str(tmp_path)
    monkeypatch.setattr("interlockd.det.packs.home_dir", lambda: home)
    assert "persistence.agent_config_write" in _persist(f"{home}/.CLAUDE/settings.json")
    assert "persistence.git_hook" in _persist(f"{home}/proj/.GIT/hooks/pre-commit")
    assert "persistence.ci_workflow_write" in _persist(f"{home}/proj/.GitHub/Workflows/ci.yml")
    assert "persistence.authorized_keys" in _persist(f"{home}/.SSH/authorized_keys")
    assert paths.is_sensitive(paths.normalize_path(f"{home}/.AWS/credentials", None), [f"{home}/.aws/**"])
    assert paths.is_under(paths.normalize_path(f"{home}/Proj/a.py", None), [f"{home}/proj"])
