"""Run the daemon as a background service: launchd (macOS), systemd --user (Linux), or a detached process.

One `ServiceManager` per Interlock home. The service runs `<python> -m interlockd serve` with INTERLOCK_HOME set,
logs to `<home>/interlockd.log`, and restarts on crash under launchd/systemd. The detached-process backend is the
fallback (containers, CI, a Linux box without a user systemd) and records its pid in `<home>/interlockd.pid`.
"""

from __future__ import annotations

import hashlib
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
from typing import Literal

Backend = Literal["launchd", "systemd", "process"]
DEFAULT_HOME = Path("~/.interlock").expanduser()


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def detect_backend() -> Backend:
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
                 python: str | None = None, runner: Callable[[list[str]], subprocess.CompletedProcess] = _run):
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
        """Write the unit (launchd/systemd). The process backend has nothing to install."""
        self.home.mkdir(parents=True, exist_ok=True)
        if self.backend == "launchd":
            self.unit_path.parent.mkdir(parents=True, exist_ok=True)
            self.unit_path.write_text(self._plist())
        elif self.backend == "systemd":
            self.unit_path.parent.mkdir(parents=True, exist_ok=True)
            self.unit_path.write_text(self._systemd_unit())
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
            if self._pid_alive():
                return
            self.home.mkdir(parents=True, exist_ok=True)
            log = open(self.log_path, "ab")  # noqa: SIM115  handed to the child
            env = {**os.environ, "INTERLOCK_HOME": str(self.home)}
            p = subprocess.Popen(self.command(), stdout=log, stderr=log, stdin=subprocess.DEVNULL, env=env,
                                 start_new_session=True)
            self.pid_path.write_text(str(p.pid))

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
        pid = self._read_pid()
        if pid and self._alive(pid):
            os.kill(pid, signal.SIGTERM)
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
        if self.backend == "systemd":
            self._run(["systemctl", "--user", "disable", self.unit])
        if self.backend in ("launchd", "systemd") and self.unit_path.exists():
            self.unit_path.unlink()
            if self.backend == "systemd":
                self._run(["systemctl", "--user", "daemon-reload"])

    def status(self) -> ServiceStatus:
        installed = self.unit_path.exists() if self.backend != "process" else True
        return ServiceStatus(self.backend, installed, self.healthy(), self._read_pid(), detail=str(self.unit_path))

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
            return int(self.pid_path.read_text().strip())
        except (OSError, ValueError):
            return None

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _pid_alive(self) -> bool:
        pid = self._read_pid()
        return bool(pid and self._alive(pid))
