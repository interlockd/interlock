"""Daemon lifecycle: the Stop_Marker, the clean-exit mark and the startup audit (Requirement 3).

An operator command that stops or restarts the daemon writes `<Home>/stop-marker.json` before signalling it, so a
shim that finds the daemon unreachable can tell "the operator stopped it" (or "it is restarting") from an
unexpected loss. The daemon removes the marker when it starts, writes a clean-exit mark into `daemon.json` when it
exits on a signal it can handle, and on the next start compares the two: a previous `daemon.json` without the mark
and no marker means the previous daemon died unexpectedly. Calls the shims could not have judged meanwhile are
counted from `<Home>/hook.log` into one `control.calls_unjudged` summary.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__, records, statefile

STOP_MARKER = "stop-marker.json"
DAEMON_JSON = "daemon.json"
HOOK_LOG = "hook.log"
GRACE_S = 120
RESTARTING = frozenset({"restart", "shadow", "enforce", "token_rotate", "init"})   # the marker gets an expiry
STOPPING = frozenset({"stop", "uninstall"})                                        # no expiry
TAMPER_CAUSES = ("token_rejected", "daemon_identity", "daemon_lost")               # hook.log `tamper <cause>`
HOOK_LOG_TAIL_BYTES = 8 * 1024 * 1024        # the startup audit reads at most this much of the end of hook.log

ErrorCallback = Callable[[str, str], None]
log = logging.getLogger("interlockd.lifecycle")


def iso(t: datetime) -> str:
    """Whole-second UTC ISO time with a `Z` suffix (the shims' `date -u +%Y-%m-%dT%H:%M:%SZ` format)."""
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now(now: datetime | None) -> datetime:
    t = now if now is not None else datetime.now(UTC)
    return (t if t.tzinfo else t.replace(tzinfo=UTC)).astimezone(UTC).replace(microsecond=0)


def parse_iso(s: Any) -> datetime | None:
    """`2026-10-17T10:00:00Z`, with or without fractional seconds or an offset; naive times are UTC."""
    if not isinstance(s, str) or not s:
        return None
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


# ---- Stop_Marker --------------------------------------------------------------------------------------------------

def stop_marker_doc(action: str, *, now: datetime | None = None, pid: int | None = None) -> dict[str, Any]:
    """The marker document for `action`: expiry keys (`expires_at`, `expires_epoch`) only for restarting actions."""
    if action not in RESTARTING | STOPPING:
        raise ValueError(f"{action!r} is not an action that stops or restarts the daemon")
    t = _now(now)
    doc: dict[str, Any] = {"action": action, "written_at": iso(t), "pid": os.getpid() if pid is None else pid,
                           "version": __version__}
    if action in RESTARTING:
        exp = t + timedelta(seconds=GRACE_S)
        doc["expires_at"] = iso(exp)
        doc["expires_epoch"] = int(exp.timestamp())
    return doc


def write_stop_marker(home: Path, action: str, *, now: datetime | None = None) -> dict[str, Any]:
    """Write `<Home>/stop-marker.json` for `action` and return the document. Raises OSError when the write fails;
    callers print `cannot write <Home>/stop-marker.json for <action>` and do not stop the daemon (3.15)."""
    doc = stop_marker_doc(action, now=now)
    why: list[str] = []
    if not statefile.write_state(Path(home) / STOP_MARKER, doc, on_error=lambda _f, r: why.append(r)):
        raise OSError(f"cannot write {Path(home) / STOP_MARKER}: {why[0] if why else 'state_write_failed'}")
    return doc


def read_stop_marker(home: Path, *, on_error: ErrorCallback | None = None) -> dict[str, Any] | None:
    return statefile.read_state(Path(home) / STOP_MARKER, {"action": str, "written_at": str}, on_error=on_error)


def remove_stop_marker(home: Path, *, on_error: ErrorCallback | None = None) -> dict[str, Any] | None:
    """Remove the marker (also an unreadable one) and return what it said, or None when absent or unreadable."""
    path = Path(home) / STOP_MARKER
    doc = read_stop_marker(home, on_error=on_error)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass         # a directory in its place: the shims cannot read it as a marker either
    return doc


# ---- daemon.json and the clean-exit mark --------------------------------------------------------------------------

def read_daemon_json(home: Path) -> dict[str, Any] | None:
    """The previous daemon's `daemon.json`: None when absent, {} when present but unreadable (still "a previous
    daemon ran and left no clean-exit mark"). Read leniently: files written before 0.2.0 are mode 0644."""
    path = Path(home) / DAEMON_JSON
    try:
        with open(path, "rb") as f:
            raw = f.read(statefile.MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError:
        return {}
    try:
        doc = json.loads(raw.decode("utf-8")) if len(raw) <= statefile.MAX_BYTES else None
    except (UnicodeDecodeError, ValueError):
        doc = None
    return doc if isinstance(doc, dict) else {}


def _daemon_json_text(doc: dict[str, Any]) -> str:
    try:
        line = statefile.single_line(doc)
    except ValueError:     # e.g. a socket path with non-ASCII characters: still one line of valid JSON
        line = json.dumps(doc, sort_keys=True, separators=(", ", ": "), ensure_ascii=True)
    return line + "\n"


def write_daemon_json(home: Path, doc: dict[str, Any], *, on_error: ErrorCallback | None = None) -> bool:
    """Atomically write `daemon.json` as one line (`"listen": "` stays matchable by the sh shims), mode 0600."""
    path = Path(home) / DAEMON_JSON
    tmp = path.with_name(path.name + ".tmp")
    try:
        data = _daemon_json_text(doc).encode("ascii")
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        return True
    except (OSError, TypeError, ValueError) as e:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        if on_error is not None:
            on_error(str(path), f"state_write_failed:{type(e).__name__.lower()}")
        return False


def daemon_json_doc(listen: str, *, socket: str | None = None, now: datetime | None = None,
                    pid: int | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {"listen": listen, "pid": os.getpid() if pid is None else pid, "version": __version__,
                           "started_at": iso(_now(now))}
    if socket:
        doc["socket"] = socket
    return doc


def mark_clean_exit(home: Path, reason: str, *, now: datetime | None = None,
                    on_error: ErrorCallback | None = None) -> bool:
    """Add `exited_at` and `exit_reason` ("sigterm" | "sigint" | "stop") to this process's `daemon.json`. A file
    that names another pid belongs to another daemon and is left alone. Never raises."""
    doc = read_daemon_json(home)
    if not doc or doc.get("pid") != os.getpid():
        return False
    doc["exited_at"] = iso(_now(now))
    doc["exit_reason"] = reason
    return write_daemon_json(home, doc, on_error=on_error)


# ---- startup audit ------------------------------------------------------------------------------------------------

def summarize_hook_log(lines: Iterable[str], since_iso: str) -> dict[str, Any] | None:
    """Count `hook.log` lines later than `since_iso` by classification: `unjudged ...` and `tamper <cause> ...`.
    Returns the counts plus `span_from`/`span_to` (the first and last counted line's time), or None when nothing
    counts or `since_iso` is not a time."""
    since = parse_iso(since_iso)
    if since is None:
        return None
    counts = {"unjudged": 0, **{f"tamper_{c}": 0 for c in TAMPER_CAUSES}}
    first: datetime | None = None
    last: datetime | None = None
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        t = parse_iso(parts[0])
        if t is None or t <= since:
            continue
        if parts[1] == "unjudged":
            key = "unjudged"
        elif parts[1] == "tamper" and len(parts) > 2 and parts[2] in TAMPER_CAUSES:
            key = f"tamper_{parts[2]}"
        else:
            continue
        counts[key] += 1
        first = t if first is None or t < first else first
        last = t if last is None or t > last else last
    if first is None or last is None:
        return None
    return {**counts, "span_from": iso(first), "span_to": iso(last)}


def _hook_log_lines(home: Path) -> list[str]:
    try:
        with open(Path(home) / HOOK_LOG, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            f.seek(max(0, size - HOOK_LOG_TAIL_BYTES))
            raw = f.read()
    except OSError:
        return []
    lines = raw.decode("utf-8", "replace").splitlines()
    return lines[1:] if size > HOOK_LOG_TAIL_BYTES and lines else lines   # first line may be cut


def startup_audit(home: Path, spool: Any, previous: dict[str, Any] | None, marker: dict[str, Any] | None,
                  now: datetime, **m: Any) -> list[dict[str, Any]]:
    """The control records to append when the daemon starts; appends nothing itself (`spool` is unused and kept for
    the design's signature). `previous` is the previous `daemon.json` (None on first start), `marker` the
    Stop_Marker that was present (None when absent). `m` is record metadata (`mode`, `policy_sha256`)."""
    at = {**m, "at": iso(_now(now))}
    out = [records.daemon_started(marker is not None, str((marker or {}).get("action", "")), **at)]
    if previous is not None and "exited_at" not in previous and marker is None:
        pid = previous.get("pid")
        out.append(records.daemon_unexpected_exit(pid if isinstance(pid, int) else 0,
                                                  str(previous.get("version", "")), **at))
    cutoff = (previous or {}).get("exited_at") or (previous or {}).get("started_at")
    if isinstance(cutoff, str) and cutoff:
        summary = summarize_hook_log(_hook_log_lines(home), cutoff)
        if summary is not None:
            out.append(records.calls_unjudged(**summary, **at))
    return out


def state_error_recorder(spool: Any, meta: Callable[[], dict[str, Any]]) -> ErrorCallback:
    """An `on_error` callback for `statefile` reads and writes that appends the matching control record."""
    def on_error(file: str, reason: str) -> None:
        m = meta()
        if reason.startswith("state_permissions:"):
            rec = records.state_permissions(file, reason, **m)
        elif reason.startswith("state_write_failed:"):
            rec = records.state_write_failed(file, reason, **m)
        else:
            rec = records.state_unreadable(file, reason, **m)
        try:
            spool.append(rec)
        except Exception:  # recording a state-file problem never stops the daemon
            log.exception("could not record %s for %s", reason, file)
    return on_error
