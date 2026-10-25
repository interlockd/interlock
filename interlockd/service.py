"""Run the daemon as a background service: launchd (macOS), systemd --user (Linux), the per-user Run key (Windows), or a
detached process.

One `ServiceManager` per Interlock home. The service runs `<python> -m interlockd serve` with INTERLOCK_HOME set,
logs to `<home>/interlockd.log`, and restarts on crash under launchd/systemd. The detached-process backend is the
fallback (containers, CI, a Linux box without a user systemd) and records its pid in `<home>/interlockd.pid`.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Backend = Literal["launchd", "systemd", "winrun", "process"]
WINDOWS = sys.platform == "win32"
DEFAULT_HOME = Path("~/.interlock").expanduser()


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"     # HKCU: per-user, no admin rights needed


class WinRunKey:
    """The current user's Run key: programs Windows starts at sign-in. Tests substitute a dict-backed fake."""

    def get(self, name: str) -> str | None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
                return str(winreg.QueryValueEx(k, name)[0])
        except OSError:
            return None

    def set(self, name: str, value: str) -> None:
        import winreg

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)

    def delete(self, name: str) -> None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except OSError:
            pass


def detect_backend() -> Backend:
    if WINDOWS:
        return "winrun"
    if platform.system() == "Darwin" and shutil.which("launchctl"):
        return "launchd"
    if platform.system() == "Linux" and shutil.which("systemctl"):
        r = _run(["systemctl", "--user", "show-environment"])
        if r.returncode == 0:
            return "systemd"
    return "process"


@dataclass
class ServiceStatus:
    backend: Backend
    installed: bool
    running: bool
    pid: int | None = None
    detail: str = ""


class ServiceManager:
    def __init__(self, home: Path, *, listen: str = "127.0.0.1:7391", backend: Backend | None = None,
                 python: str | None = None, runner: Callable[[list[str]], subprocess.CompletedProcess] = _run,
                 run_key: Any | None = None):
        self.home = Path(home).expanduser()
        self.listen = listen
        self.backend: Backend = backend or detect_backend()
        self.python = python or sys.executable
        self._run = runner
        # one service per home, so a test or second install never collides with the default one
        suffix = "" if self.home.resolve() == DEFAULT_HOME.resolve() else "." + hashlib.sha256(
            str(self.home.resolve()).encode()).hexdigest()[:8]
        self.label = f"dev.interlock.daemon{suffix}"
        self.unit = f"interlockd{suffix}.service"
        self.run_key = run_key if run_key is not None else (WinRunKey() if self.backend == "winrun" else None)

    # ---- paths
    @property
    def log_path(self) -> Path:
        return self.home / "interlockd.log"

    @property
    def pid_path(self) -> Path:
        return self.home / "interlockd.pid"

    @property
    def unit_path(self) -> Path:
        if self.backend == "launchd":
            return Path.home() / "Library" / "LaunchAgents" / f"{self.label}.plist"
        if self.backend == "systemd":
            return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd" / "user" / self.unit
        return self.pid_path

    def command(self) -> list[str]:
        return [self.python, "-m", "interlockd", "--home", str(self.home), "serve", "--listen", self.listen]

    def logon_command(self) -> str:
        """What the Run key starts at sign-in: `interlock start` with the process backend, under pythonw (no console
        window), which detaches the daemon with its log."""
        pyw = Path(self.python).with_name("pythonw.exe")
        exe = str(pyw) if pyw.exists() else self.python
        return subprocess.list2cmdline([exe, "-m", "interlockd", "--home", str(self.home), "start", "--backend", "process"])

    # ---- unit files
    def _plist(self) -> str:
        args = "\n".join(f"    <string>{a}</string>" for a in self.command())
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{self.label}</string>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>INTERLOCK_HOME</key><string>{self.home}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>{self.log_path}</string>
  <key>StandardErrorPath</key><string>{self.log_path}</string>
</dict>
</plist>
"""

    def _systemd_unit(self) -> str:
        cmd = " ".join(f'"{a}"' if " " in a else a for a in self.command())
        return f"""[Unit]
Description=Interlock pre/post-action gate for AI agents
After=default.target

[Service]
Environment=INTERLOCK_HOME={self.home}
ExecStart={cmd}
Restart=on-failure
RestartSec=5
StandardOutput=append:{self.log_path}
StandardError=append:{self.log_path}

[Install]
WantedBy=default.target
"""

    # ---- lifecycle
    def install(self) -> Path:
        """Write the unit (launchd/systemd) or the Run-key entry (winrun). The process backend has nothing to install."""
        self.home.mkdir(parents=True, exist_ok=True)
        if self.backend == "winrun":
            self.run_key.set(self.label, self.logon_command())
        elif self.backend == "launchd":
            self.unit_path.parent.mkdir(parents=True, exist_ok=True)
            self.unit_path.write_text(self._plist(), encoding="utf-8")
        elif self.backend == "systemd":
            self.unit_path.parent.mkdir(parents=True, exist_ok=True)
            self.unit_path.write_text(self._systemd_unit(), encoding="utf-8")
            self._run(["systemctl", "--user", "daemon-reload"])
            self._run(["systemctl", "--user", "enable", self.unit])
        return self.unit_path

    def start(self) -> None:
        if self.backend == "launchd":
            if not self.unit_path.exists():
                self.install()
            domain = f"gui/{os.getuid()}"
            # bootout is asynchronous, so a bootstrap right after a stop can fail for a moment: retry briefly
            for _ in range(15):
                if self._run(["launchctl", "bootstrap", domain, str(self.unit_path)]).returncode == 0:
                    break
                if self._run(["launchctl", "kickstart", f"{domain}/{self.label}"]).returncode == 0:
                    break   # already loaded
                time.sleep(0.2)
        elif self.backend == "systemd":
            if not self.unit_path.exists():
                self.install()
            self._run(["systemctl", "--user", "start", self.unit])
        else:
            if self.backend == "winrun" and self.run_key.get(self.label) is None:
                self.install()                           # started at sign-in from now on; run it now as well
            if self._pid_alive():
                return
            self.home.mkdir(parents=True, exist_ok=True)
            log = open(self.log_path, "ab")  # noqa: SIM115  handed to the child
            env = {**os.environ, "INTERLOCK_HOME": str(self.home)}
            if WINDOWS:   # no console window, not tied to the terminal that started it
                detach = {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                          | subprocess.CREATE_NO_WINDOW}
            else:
                detach = {"start_new_session": True}
            p = subprocess.Popen(self.command(), stdout=log, stderr=log, stdin=subprocess.DEVNULL, env=env, **detach)
            self.pid_path.write_text(str(p.pid), encoding="utf-8")

    def stop(self) -> None:
        if self.backend == "launchd":
            self._run(["launchctl", "bootout", f"gui/{os.getuid()}/{self.label}"])
            # bootout returns before the job is torn down; a bootstrap before then fails with EIO
            for _ in range(50):
                if not self._launchd_loaded():
                    break
                time.sleep(0.2)
        elif self.backend == "systemd":
            self._run(["systemctl", "--user", "stop", self.unit])
        # Windows: a venv's python.exe is a launcher that runs the interpreter as a child, so the daemon's own pid
        # (daemon.json) is the one to stop. os.kill is TerminateProcess there (a detached process has no console for
        # Ctrl-Break); the spool fsyncs every record, so nothing decided is lost. Pids are reused quickly on Windows,
        # hence the image check.
        pids = [self._read_pid()] + ([self._daemon_json_pid()] if WINDOWS else [])
        for pid in dict.fromkeys(p for p in pids if p):
            if self._alive(pid) and (not WINDOWS or _win_is_python(pid)):
                try:
                    os.kill(pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    # it exited meanwhile (on Windows, terminating a process that is already exiting, e.g. the
                    # daemon once its venv launcher has gone, is "access denied"); wait below, as for a clean exit
                    pass
                for _ in range(30):
                    if not self._alive(pid):
                        break
                    time.sleep(0.1)
        if self.pid_path.exists():
            self.pid_path.unlink()

    def restart(self) -> None:
        if self.backend == "launchd":   # kill and relaunch in place; no unload/load race
            r = self._run(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{self.label}"])
            if r.returncode == 0:
                return
        if self.backend == "systemd":
            self._run(["systemctl", "--user", "restart", self.unit])
            return
        self.stop()
        self.start()

    def uninstall(self) -> None:
        self.stop()
        if self.backend == "winrun":
            self.run_key.delete(self.label)
        if self.backend == "systemd":
            self._run(["systemctl", "--user", "disable", self.unit])
        if self.backend in ("launchd", "systemd") and self.unit_path.exists():
            self.unit_path.unlink()
            if self.backend == "systemd":
                self._run(["systemctl", "--user", "daemon-reload"])

    def status(self) -> ServiceStatus:
        if self.backend == "winrun":
            installed, detail = self.run_key.get(self.label) is not None, f"HKCU\\{RUN_KEY}\\{self.label}"
        else:
            installed, detail = (self.unit_path.exists() if self.backend != "process" else True), str(self.unit_path)
        return ServiceStatus(self.backend, installed, self.healthy(), self._read_pid(), detail=detail)

    # ---- health
    def healthy(self, timeout: float = 1.0) -> bool:
        host, _, port = self.listen.rpartition(":")
        try:
            with urllib.request.urlopen(f"http://{host or '127.0.0.1'}:{port}/interlock/v1/health", timeout=timeout) as r:
                return r.status == 200
        except Exception:  # noqa: BLE001
            return False

    def wait_healthy(self, seconds: float = 8.0) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.healthy(timeout=0.5):
                return True
            time.sleep(0.2)
        return False

    def _launchd_loaded(self) -> bool:
        return self._run(["launchctl", "print", f"gui/{os.getuid()}/{self.label}"]).returncode == 0

    # ---- pid helpers
    def _read_pid(self) -> int | None:
        try:
            return int(self.pid_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None

    def _daemon_json_pid(self) -> int | None:
        try:
            return int(json.loads((self.home / "daemon.json").read_text(encoding="utf-8"))["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    @staticmethod
    def _alive(pid: int) -> bool:
        if WINDOWS:
            return _win_alive(pid)      # os.kill(pid, 0) would terminate the process on Windows
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _pid_alive(self) -> bool:
        pid = self._read_pid()
        return bool(pid and self._alive(pid))


# ---- Windows process helpers (ctypes, no extra dependency)
_PROCESS_QUERY_LIMITED_INFORMATION, _STILL_ACTIVE = 0x1000, 259


def _win_open(pid: int):
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return k32, k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)


def _win_alive(pid: int) -> bool:
    import ctypes

    k32, h = _win_open(pid)
    if not h:
        return False
    try:
        code = ctypes.c_ulong()
        return bool(k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == _STILL_ACTIVE
    finally:
        k32.CloseHandle(h)


def _win_is_python(pid: int) -> bool:
    """True when pid runs a Python executable (the daemon), so a reused pid is never terminated."""
    import ctypes

    k32, h = _win_open(pid)
    if not h:
        return False
    try:
        buf, size = ctypes.create_unicode_buffer(32768), ctypes.c_ulong(32768)
        if not k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return False
        return Path(buf.value).name.lower().startswith("python")
    finally:
        k32.CloseHandle(h)
