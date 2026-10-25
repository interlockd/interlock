import json
from pathlib import Path

import pytest

from interlockd.config import Settings
from interlockd.pipeline import Daemon
from interlockd.store.memory import MemoryRepository
from interlockd.store.spool import Spool

SESSION = "sess_test-0001"

# Real shapes from adapters/kiro/PAYLOADS.md
PRE_BASH = {
    "session_id": SESSION, "hook_event_name": "PreToolUse", "cwd": "/ws/proj",
    "tool_name": "execute_bash",
    "tool_input": {"command": "git status --short", "description": "Check status", "cwd": None,
                   "run_in_background": False, "timeout": None},
}
POST_BASH = {**PRE_BASH, "hook_event_name": "PostToolUse", "tool_response": "Output:\n M a.py\n\nExit Code: 0"}
PRE_READ = {"session_id": SESSION, "hook_event_name": "PreToolUse", "cwd": "/ws/proj",
            "tool_name": "read_file", "tool_input": {"path": "src/a.py", "offset": None, "limit": None}}


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "interlock"
    h.mkdir()
    return h


@pytest.fixture
def kiro_sessions(tmp_path: Path) -> Path:
    base = tmp_path / "kiro-sessions" / "wshash"
    d = base / SESSION
    d.mkdir(parents=True)
    rows = [
        {"id": "1", "timestamp": "t", "payload": {"type": "user", "content": "first instruction"}},
        {"id": "2", "timestamp": "t", "payload": {"type": "assistant", "content": "ok"}},
        {"id": "3", "timestamp": "t", "payload": {"type": "tool_call", "toolName": "execute_bash", "args": {}}},
        {"id": "4", "timestamp": "t", "payload": {"type": "user", "content": "clean up the PR"}},
    ]
    (d / "messages.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    (d / "session.json").write_text(json.dumps({"id": SESSION, "autopilot": True, "rootPaths": ["/ws"]}), encoding="utf-8")
    return base.parent


@pytest.fixture
def settings(home: Path, kiro_sessions: Path) -> Settings:
    s = Settings(home=home)
    s.kiro_sessions_dir = kiro_sessions
    s.workspace_roots = ["/ws/proj"]
    return s


@pytest.fixture
def daemon(settings: Settings) -> Daemon:
    return Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository())


@pytest.fixture(autouse=True)
def _no_real_service_manager(monkeypatch):
    """No test may drive the machine's real launchd / systemd / Windows Run key: a leaked job runs a sandbox daemon on
    the developer's real port (it happened: token rotation restarted "its" service because the developer's own daemon
    answered on 7391). Tests pass a fake runner, or use the process backend on a port of their own."""
    from interlockd import service

    real = service._run

    read_only = {"print", "list", "status", "is-active", "is-enabled", "show", "query"}

    def guarded(cmd):
        tool = Path(cmd[0]).name if cmd else ""
        if tool in ("launchctl", "systemctl", "reg", "reg.exe", "schtasks", "schtasks.exe"):
            verb = next((c for c in cmd[1:] if not c.startswith("-")), "")
            if verb not in read_only:
                raise AssertionError(f"a test tried to run {' '.join(cmd[:3])} against the real service manager")
        return real(cmd)
    monkeypatch.setattr(service, "_run", guarded)


@pytest.fixture(autouse=True)
def _no_update_check(monkeypatch):
    """Tests never call PyPI, and never pick up a repository policy from wherever the suite is run."""
    monkeypatch.setenv("INTERLOCK_NO_UPDATE_CHECK", "1")
    monkeypatch.setenv("INTERLOCK_REPO_POLICIES", "0")


# Native Windows runs everything except these: the POSIX sh shims (Windows uses the Python shim, tests/test_shim_py.py),
# Unix sockets, and the OS sandbox (macOS/Linux; see cli.WINDOWS_UNSUPPORTED).
POSIX_ONLY = {"test_shim_sh.py": "the POSIX sh shim", "test_unix_socket.py": "Unix sockets",
              "test_sandbox.py": "the OS sandbox is macOS/Linux"}
# single tests that run the sh shim directly
POSIX_ONLY_TESTS = {"test_shim_prints_daemon_json", "test_shim_per_harness", "test_shims",
                    "test_launchd_unit_and_sequence",          # launchd: macOS
                    "test_status_without_judge"}               # the local judge: macOS/Linux


def pytest_collection_modifyitems(config, items):
    import sys

    if sys.platform != "win32":
        return
    for item in items:
        reason = POSIX_ONLY.get(item.path.name) or ("the POSIX sh shim" if item.originalname in POSIX_ONLY_TESTS else None)
        if reason:
            item.add_marker(pytest.mark.skip(reason=f"not on native Windows: {reason}"))


def installed_shim_name() -> str:
    """The shim file `init` installs on this platform (see cli.hook_runtime)."""
    from interlockd.cli import hook_runtime

    return "interlock-hook.py" if hook_runtime() == "py" else "interlock-hook.sh"
