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
def _no_update_check(monkeypatch):
    """Tests never call PyPI, and never pick up a repository policy from wherever the suite is run."""
    monkeypatch.setenv("INTERLOCK_NO_UPDATE_CHECK", "1")
    monkeypatch.setenv("INTERLOCK_REPO_POLICIES", "0")


# Native Windows runs the daemon core and SDKs; these need macOS/Linux (WSL2 on Windows), see cli.WINDOWS_UNSUPPORTED.
POSIX_ONLY = {"test_shim_sh.py": "POSIX shell hook shims", "test_unix_socket.py": "Unix sockets",
              "test_sandbox.py": "the OS sandbox is macOS/Linux", "test_cursor_gemini.py": "hook shims and init",
              "test_gateway.py": "gateway wrap", "test_capture.py": "capture", "test_onboard.py": "init and launchd/systemd"}
# single tests that run hook shims or `interlock init` / `install` / `judge`
POSIX_ONLY_TESTS = {"test_shim_prints_daemon_json", "test_installers_merge_existing_settings", "test_shims",
                    "test_install_and_uninstall", "test_install_uninstall", "test_init_mcp_registers_and_uninstall_removes",
                    "test_status_without_judge", "test_doctor_after_init_then_tamper",
                    "test_doctor_flags_loose_token_and_bad_policy"}


def pytest_collection_modifyitems(config, items):
    import sys

    if sys.platform != "win32":
        return
    for item in items:
        reason = POSIX_ONLY.get(item.path.name) or ("hook shims or init" if item.originalname in POSIX_ONLY_TESTS else None)
        if reason:
            item.add_marker(pytest.mark.skip(reason=f"not on native Windows: {reason}"))
