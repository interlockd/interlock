"""Claude Code agent worktrees (<repo>/.claude/worktrees/<name>/) are checkouts: their files are workspace files, their
own agent configuration and the parent .claude/ stay protected. Plus the writers the persistence pack decomposes."""

from __future__ import annotations

import os

import pytest

from interlockd import paths
from interlockd.det import DetResult
from interlockd.det.packs import _persistence_path_check
from interlockd.det.shellparse import interpreter_programs, interpreter_write_targets, parse
from interlockd.policy import Policy
from interlockd.testkit import run_case
from interlockd.tiers import route

AC = "persistence.agent_config_write"


def _persist(path: str, roots: list[str]) -> set[str]:
    res = DetResult()
    _persistence_path_check(path, res, Policy(), roots, "args.path")
    return {f.rule for f in res.findings}


@pytest.fixture
def repo(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr("interlockd.det.packs.home_dir", lambda: paths.canon(str(home)))
    monkeypatch.setattr(paths, "home", lambda: paths.canon(str(home)))
    r = tmp_path / "repo"
    wt = r / ".claude" / "worktrees" / "feat"
    (wt / "src").mkdir(parents=True)
    (wt / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (r / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    return paths.canon(os.path.realpath(r)), paths.canon(os.path.realpath(home))


def test_worktree_source_files_are_workspace_files(repo):
    r, _ = repo
    assert AC not in _persist(f"{r}/.claude/worktrees/feat/src/a.py", [r])
    assert AC not in _persist(f"{r}/.claude/worktrees/feat/src/new_module.py", [r])   # not created yet
    assert AC not in _persist(f"{r}/.claude/worktrees/feat/.vscode/settings.json", [r])


def test_agent_config_stays_protected_in_and_around_worktrees(repo):
    r, home = repo
    for p in (f"{r}/.claude/settings.json", f"{r}/.claude/hooks/x.sh", f"{r}/.claude/commands/a.md",
              f"{r}/.claude/agents/a.md", f"{r}/.claude/worktrees/settings.json", f"{r}/.claude/worktrees/feat",
              f"{r}/.claude/worktrees/feat/.claude/settings.json", f"{r}/.claude/worktrees/feat/.kiro/hooks/a.json",
              f"{r}/.claude/worktrees/feat/.claude/worktrees/in/.claude/settings.local.json",
              f"{home}/.claude/worktrees/feat/src/a.py"):
        assert AC in _persist(p, [r]), p
    # an unnormalized path never gets the exemption
    assert paths.agent_worktree(f"{r}/.claude/worktrees/feat/../../settings.json") is None


def test_symlinks_are_followed(repo):
    r, home = repo
    wt = f"{r}/.claude/worktrees/feat"
    try:
        os.symlink(f"{r}/.claude/settings.json", f"{wt}/evil.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need extra privileges here (Windows without developer mode)")
    os.symlink(f"{home}/.claude", f"{wt}/cfg")
    os.symlink(f"{wt}/src/a.py", f"{wt}/alias.py")
    assert AC in _persist(f"{wt}/evil.json", [r])          # lands in the parent .claude/
    assert AC in _persist(f"{wt}/cfg/settings.json", [r])  # lands in the user's ~/.claude/
    assert AC not in _persist(f"{wt}/alias.py", [r])       # lands on a source file of the same worktree


def test_tier_routing_treats_worktree_files_as_workspace_writes(repo):
    from interlockd.config import DEFAULT_PROTECTED, DEFAULT_SENSITIVE
    from interlockd.models import AdapterInfo, Context, Identity, InterlockEvent, ToolCall

    r, _ = repo

    def tier(path: str) -> str:
        ev = InterlockEvent(kind="pre_action", adapter=AdapterInfo(name="test"), identity=Identity(agent_type="test"),
                            tool_call=ToolCall(name="fs_write", arguments={"path": path, "content": "x"}),
                            context=Context(cwd=r))
        return route(ev, workspace_roots=[r], protected=DEFAULT_PROTECTED, sensitive=DEFAULT_SENSITIVE).action_class

    assert tier(f"{r}/.claude/worktrees/feat/src/a.py") == "edit_in_workspace"
    assert tier(f"{r}/.claude/worktrees/feat/.claude/settings.json") == "edit_protected"
    assert tier(f"{r}/.claude/settings.json") == "edit_protected"


def test_an_explicit_worktrees_pattern_is_honored(tmp_path):
    pol = Policy()
    pol.trust.protected_paths = [*pol.trust.protected_paths, ".claude/worktrees/**"]
    case = {"id": "x", "tool": "fs_write", "args": {"path": ".claude/worktrees/feat/src/a.py", "content": "x"}}
    assert AC in run_case(case, tmp_path, policy=pol).fired
    assert AC not in run_case(case, tmp_path).fired


def test_windows_form(monkeypatch):
    monkeypatch.setattr(paths, "WINDOWS", True)
    monkeypatch.setattr(paths, "CASE_INSENSITIVE", True)
    monkeypatch.setattr(paths.os.path, "expanduser", lambda p: p.replace("~", r"C:\Users\Me", 1) if p.startswith("~") else p)
    monkeypatch.setattr("interlockd.det.packs.home_dir", paths.home)
    root = r"C:\WS\Proj"
    src = paths.normalize_path(r"C:\WS\Proj\.Claude\Worktrees\feat\src\a.py", None)
    cfg = paths.normalize_path(r"C:\WS\Proj\.claude\worktrees\feat\.CLAUDE\settings.json", None)
    assert AC not in _persist(src, [root])
    assert AC in _persist(cfg, [root])
    assert AC in _persist(paths.normalize_path(r"C:\Users\Me\.claude\worktrees\x\a.py", None), [root])


@pytest.mark.parametrize("program,expected", [
    ("open('.claude/settings.json','w').write('{}')", [".claude/settings.json"]),
    ("open(\".claude/settings.json\", mode=\"a\")", [".claude/settings.json"]),
    ("from pathlib import Path; Path('a/b.json').write_text('x')", ["a/b.json"]),
    ("import shutil; shutil.copy('x', '.kiro/settings/mcp.json')", [".kiro/settings/mcp.json"]),
    ("require('fs').appendFileSync('.claude/hooks/x.sh', 'curl')", [".claude/hooks/x.sh"]),
    ("fs.renameSync('tmp.json', '.claude/settings.json')", [".claude/settings.json"]),
    ("File.write('.claude/x', 'y')", [".claude/x"]),
    ("open(my $f, '>', '.claude/settings.json')", [".claude/settings.json"]),
    ("open(F, \">>.claude/settings.json\")", [".claude/settings.json"]),
    ("file_put_contents('.kiro/a.json', '{}');", [".kiro/a.json"]),
    # reads and mentions are not writes
    ("print(open('.claude/settings.json').read())", []),
    ("json.load(open('.claude/settings.json', 'r'))", []),
    ("console.log(require('fs').readFileSync('.claude/settings.json'))", []),
    ("print('.claude/settings.json')", []),
])
def test_interpreter_write_targets(program, expected):
    assert interpreter_write_targets(program) == expected


def test_interpreter_programs_cover_one_liners_nesting_and_heredocs():
    progs = interpreter_programs(parse("bash -c \"node -e 'x()'\" && python3 - <<'EOF'\ny()\nEOF\nsh -c 'echo hi'"))
    assert "x()" in progs and any("y()" in p for p in progs)
    assert not any("echo hi" in p for p in progs)                # shell programs are decomposed, not scanned here
