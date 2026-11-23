"""Desktop notifications when protection becomes compromised (Requirements 6.6, 6.7).

Off by default; enabled by the policy key `notify.desktop: true`. `DesktopNotifier` is a `ProtectionState`
subscriber: it receives every snapshot, works out which subjects have just entered `compromised`, and posts one OS
notification per such transition.

Granularity: one notification per *subject* transition, where a subject is a harness (its reasons:
`shim_modified`, `hook_removed`, ...) or the Home (its reasons: `token_modified`, `policy_modified`, ...). A harness
state only turns `compromised` through its own reasons, so the Home is tracked as its own subject; otherwise a
rewritten token or policy would never notify. A second reason on a subject that is already compromised does not
notify again; the subject has to leave `compromised` (ack, init, repair) and re-enter it. The state restored at
start (`seed`) is the baseline, so a daemon restart does not repeat notifications for reasons already reported.

Message content is fixed text plus the harness name (or "home") and one reason code, both validated against fixed
patterns; never a path, a tool argument or file content.

Posting runs in one daemon worker thread fed by a bounded queue, so the subscriber (called under the protection
lock, before the verdict leaves) only enqueues. Commands run with list argv, no shell, and a short timeout:

- macOS: `osascript` with an `on run argv` handler; the text arrives as argv items, never inside the script.
- Linux and other POSIX: `notify-send`.
- Windows: `powershell -EncodedCommand` with a fixed script; the text arrives through environment variables and is
  added to the toast XML with `CreateTextNode`, never interpolated into the script.

A failed post records `control.notify_failed` with a fixed reason code and never changes or delays a verdict. A
missing tool or unsupported platform is recorded once per daemon run, not on every transition.
"""

from __future__ import annotations

import base64
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import Any

from . import records
from .protection import HARNESS_REASONS, HOME, HOME_REASONS

TIMEOUT_S = 5.0
QUEUE_MAX = 16
TITLE = "Interlock"
_HARNESS = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}\Z")
_ENV_TITLE, _ENV_TEXT = "INTERLOCK_NOTIFY_TITLE", "INTERLOCK_NOTIFY_TEXT"

_APPLESCRIPT = ("on run argv", "display notification (item 1 of argv) with title (item 2 of argv)", "end run")
# Fixed script; the title and text come from the environment. The AppUserModelID is Windows PowerShell's own,
# which Windows accepts for toasts without registering a new app id.
_PS_SCRIPT = "\n".join((
    "$ErrorActionPreference = 'Stop'",
    ("[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]"
     " > $null"),
    ("$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
     "[Windows.UI.Notifications.ToastTemplateType]::ToastText02)"),
    "$n = $t.GetElementsByTagName('text')",
    f"$n.Item(0).AppendChild($t.CreateTextNode($env:{_ENV_TITLE})) > $null",
    f"$n.Item(1).AppendChild($t.CreateTextNode($env:{_ENV_TEXT})) > $null",
    "$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe'",
    ("[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show("
     "[Windows.UI.Notifications.ToastNotification]::new($t))"),
))

log = logging.getLogger("interlockd.notify")


def message(subject: str, reason: str) -> str:
    """The notification text: fixed words, the harness name (or "home") and one reason code."""
    if subject == HOME:
        return f"Protection of the Interlock home is compromised ({reason}). Run interlock doctor."
    return f"Protection for {subject} is compromised ({reason}). Run interlock doctor."


_NOTIFY_SEND_PLATFORMS = ("linux", "freebsd", "openbsd", "netbsd", "dragonfly", "sunos", "aix", "cygwin")


def command(platform: str, title: str, text: str) -> tuple[str, list[str], dict[str, str] | None] | None:
    """(tool, argv, extra environment) for the platform, or None when the platform has no notifier."""
    if platform == "darwin":
        argv = ["osascript"]
        for line in _APPLESCRIPT:
            argv += ["-e", line]
        return "osascript", argv + [text, title], None
    if platform == "win32":
        encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
        argv = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-EncodedCommand", encoded]
        return "powershell", argv, {_ENV_TITLE: title, _ENV_TEXT: text}
    if platform.startswith(_NOTIFY_SEND_PLATFORMS):          # by the platform given, not the host running this
        return "notify-send", ["notify-send", "--app-name", TITLE, "--", title, text], None
    return None


def _latest(reasons: Any) -> str:
    """The most recently detected reason code of a snapshot reason list, validated against the fixed set."""
    best: tuple[str, str] | None = None
    for r in reasons if isinstance(reasons, list) else []:
        if not isinstance(r, dict):
            continue
        code, at = r.get("reason"), r.get("detected_at")
        if not isinstance(code, str) or code not in HARNESS_REASONS | HOME_REASONS:
            code = "unknown"
        cand = (at if isinstance(at, str) else "", code)
        if best is None or cand > best:
            best = cand
    return best[1] if best else "unknown"


def compromised_subjects(snapshot: dict[str, Any]) -> dict[str, str]:
    """{subject: latest reason} for every compromised harness and for the Home when it has its own reasons."""
    out: dict[str, str] = {}
    harnesses = snapshot.get("harnesses") if isinstance(snapshot, dict) else None
    for h, st in (harnesses or {}).items():
        if isinstance(st, dict) and st.get("state") == "compromised":
            out[h if isinstance(h, str) and _HARNESS.match(h) else "unknown"] = _latest(st.get("reasons"))
    home = snapshot.get("home_reasons") if isinstance(snapshot, dict) else None
    if home:
        out[HOME] = _latest(home)
    return out


class DesktopNotifier:
    """`ProtectionState` subscriber posting one OS notification per transition into `compromised`."""

    def __init__(self, record: Callable[[dict[str, Any]], None], *, meta: Callable[[], records.Meta] | None = None,
                 enabled: Callable[[], bool] | None = None, platform: str | None = None,
                 timeout_s: float = TIMEOUT_S):
        self._record = record
        self._meta = meta or records.Meta
        self._enabled = enabled or (lambda: True)
        self.platform = platform or sys.platform
        self.timeout_s = timeout_s
        self._lock = threading.Lock()
        self._compromised: set[str] = set()
        self._reported_once: set[str] = set()     # reason codes recorded at most once per run
        self._queue: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=QUEUE_MAX)
        self._worker: threading.Thread | None = None

    def seed(self, snapshot: dict[str, Any]) -> None:
        """Take the current (restored) state as the baseline: no notification for what is already compromised."""
        with self._lock:
            self._compromised = set(compromised_subjects(snapshot))

    def __call__(self, snapshot: dict[str, Any]) -> None:
        """Subscriber entry point. Only computes transitions and enqueues; never blocks."""
        now = compromised_subjects(snapshot)
        with self._lock:
            entered = [(s, r) for s, r in sorted(now.items()) if s not in self._compromised]
            self._compromised = set(now)
        if not entered:
            return
        try:
            on = bool(self._enabled())
        except Exception:  # a broken policy provider means "off", never a failed verdict
            log.exception("cannot read notify.desktop")
            on = False
        if not on:
            return
        for item in entered:
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                self._fail("queue_full")
        self._ensure_worker()

    def join(self, timeout: float | None = None) -> bool:
        """Wait until every queued notification has been handled (tests, shutdown). True when drained."""
        done = threading.Event()

        def wait() -> None:
            self._queue.join()
            done.set()

        threading.Thread(target=wait, daemon=True).start()
        return done.wait(timeout)

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(target=self._run, name="interlock-notify", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while True:
            subject, reason = self._queue.get()
            try:
                self.post(subject, reason)
            except Exception:  # a notifier bug must never take the daemon down
                log.exception("desktop notification failed")
                self._fail("notify_error")
            finally:
                self._queue.task_done()

    def post(self, subject: str, reason: str) -> bool:
        """Post one notification synchronously. Records `control.notify_failed` and returns False on failure."""
        cmd = command(self.platform, TITLE, message(subject, reason))
        if cmd is None:
            self._fail("unsupported_platform", once=True)
            return False
        tool, argv, extra = cmd
        exe = shutil.which(tool)
        if exe is None:
            self._fail(f"{tool.replace('-', '_')}_missing", once=True)
            return False
        env = {**os.environ, **extra} if extra else None
        try:
            proc = subprocess.run([exe, *argv[1:]], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=self.timeout_s, check=False)
        except subprocess.TimeoutExpired:
            self._fail("timeout")
            return False
        except OSError:
            self._fail(f"{tool.replace('-', '_')}_failed")
            return False
        if proc.returncode != 0:
            self._fail(f"{tool.replace('-', '_')}_failed")
            return False
        return True

    def _fail(self, reason: str, *, once: bool = False) -> None:
        with self._lock:
            if once and reason in self._reported_once:
                return
            self._reported_once.add(reason)
        try:
            self._record(records.notify_failed(reason, **self._meta()))
        except Exception:
            log.exception("cannot record control.notify_failed")
