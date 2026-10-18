"""`interlock sandbox`: OS-level refusal of persistence and guard-rail writes (macOS sandbox-exec, real runs)."""

from __future__ import annotations

import platform
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from interlockd.sandbox import bwrap_args, command, macos_profile

mac = pytest.mark.skipif(platform.system() != "Darwin" or not shutil.which("sandbox-exec"), reason="macOS sandbox-exec only")


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    for d in (".ssh", ".interlock", "Library/LaunchAgents", "proj"):
        (h / d).mkdir(parents=True)
    (h / ".ssh" / "id_ed25519").write_text("PRIVATE")
    (h / ".interlock" / "token").write_text("tok\n")
    (h / ".interlock" / "hook.log").write_text("")
    return h


def _sh(home, script, **opts):
    return subprocess.run(command(["sh", "-c", script], home=home, **opts), capture_output=True, text=True, timeout=30, check=False)


@mac
def test_protected_writes_refused_ordinary_work_allowed(home):
    for target in ("~/.zshrc", "~/.ssh/authorized_keys", "~/.interlock/policy.yaml", "~/Library/LaunchAgents/evil.plist"):
        t = target.replace("~", str(home))
        r = _sh(home, f"echo x >> '{t}'")
        assert r.returncode != 0 and "not permitted" in r.stderr, target
        assert not Path(t).exists() or Path(t).read_text() == "", target
    r = _sh(home, f"echo ok > '{home}/proj/file.txt' && echo log >> '{home}/.interlock/hook.log' && cat '{home}/.interlock/token'")
    assert r.returncode == 0 and r.stdout.strip() == "tok"            # project writes, the hook log, and the token work
    assert (home / "proj" / "file.txt").read_text() == "ok\n"
    assert _sh(home, f"cat '{home}/.ssh/id_ed25519'").stdout == "PRIVATE"   # reads allowed by default (git over SSH)


@mac
def test_deny_secret_reads(home):
    r = _sh(home, f"cat '{home}/.ssh/id_ed25519'", deny_secret_reads=True)
    assert r.returncode != 0 and "PRIVATE" not in r.stdout


@mac
def test_local_network_only(home):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): ...
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"hi")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        r = _sh(home, f"curl -s -m 5 http://127.0.0.1:{port}/", local_network_only=True)
        assert r.stdout == "hi"                                         # the daemon stays reachable
        r = _sh(home, "curl -s -m 5 -o /dev/null -w '%{http_code}' https://example.com/", local_network_only=True)
        assert r.stdout in ("000", "")                                  # anything else is refused
    finally:
        srv.shutdown()


def test_profile_and_bwrap_shapes(home):
    prof = macos_profile(home, deny_secret_reads=True, local_network_only=True, extra_write_protected=["/etc/hosts"])
    assert prof.startswith("(version 1)\n(allow default)") and "(deny network-outbound)" in prof and "hook.log" in prof
    args = bwrap_args(home, deny_secret_reads=True)
    assert args[:3] == ["bwrap", "--dev-bind", "/"] and "--ro-bind" in args and str(home / ".ssh") in args and args[-1] == "--"
    assert ["--ro-bind", "/dev/null", str(home / ".ssh" / "id_ed25519")] == args[args.index(str(home / ".ssh" / "id_ed25519")) - 2:args.index(str(home / ".ssh" / "id_ed25519")) + 1]


def test_agent_configs_opt_in(home):
    assert ".claude/settings.json" not in macos_profile(home)                       # agents rewrite these at startup
    assert ".claude/settings.json" in macos_profile(home, protect_agent_configs=True)


def _bwrap_works() -> bool:
    if platform.system() != "Linux" or not shutil.which("bwrap"):
        return False
    return subprocess.run(["bwrap", "--dev-bind", "/", "/", "true"], capture_output=True, timeout=10, check=False).returncode == 0


linux = pytest.mark.skipif(not _bwrap_works(), reason="Linux bubblewrap with user namespaces only")


@linux
def test_linux_protected_writes_refused(home):
    (home / ".zshrc").write_text("")                                    # bwrap protects existing paths
    (home / ".ssh" / "authorized_keys").write_text("")
    for target in (home / ".zshrc", home / ".ssh" / "authorized_keys", home / ".interlock" / "token"):
        r = _sh(home, f"echo x >> '{target}'")
        assert r.returncode != 0, target
    r = _sh(home, f"echo ok > '{home}/proj/file.txt' && echo log >> '{home}/.interlock/hook.log' && cat '{home}/.interlock/token'")
    assert r.returncode == 0 and r.stdout.strip() == "tok" and (home / "proj" / "file.txt").read_text() == "ok\n"


@linux
def test_linux_deny_secret_reads(home):
    r = _sh(home, f"cat '{home}/.ssh/id_ed25519'", deny_secret_reads=True)
    assert "PRIVATE" not in r.stdout
