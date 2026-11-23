"""The kill switch: `interlock pause` / `interlock resume`.

While paused, every pre-action call (all agents, or the named ones) is refused, through hooks, SDK integrations,
the MCP gateway, and the egress proxy alike. Pausing is an explicit user action, so it is enforced even in shadow
mode. State is a small file the daemon re-reads when it changes, so pausing takes effect on the next call.

`pause.json` is written through `statefile` (atomic, mode 0600, flat, escape-free). The public view returned by
`pause()` and `PauseState.current()` is unchanged: `{"since": str, "agents": list[str], "until": str | None,
"reason": str}`. On disk:

- `agents` is one string: the agent names, each percent-encoded so it holds no comma, quote, backslash or
  non-ASCII character, joined with ","; "" means every agent.
- `reason` is percent-encoded the same way (a comma is kept), so free text never needs a JSON escape.
- `until` is absent when the pause has no expiry.

A `pause.json` written by an earlier release (`agents` a list, `until` null, mode 0644 from the umask) is still
honoured when it is a regular file owned by this user with no group or other *write* bit. Anything else that is
present but cannot be read fails closed: every agent is paused with reason "pause file unreadable", as before.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, unquote

from . import statefile
from .det import rule

R_PAUSED = rule("control.paused", "control.kill_switch", "critical", "block")
FILE = "pause.json"

# Printable ASCII that JSON serializes verbatim, minus "%" (the escape character itself). quote() always keeps
# letters, digits and "_.-~"; everything else outside this set becomes %XX of its UTF-8 bytes.
_REASON_SAFE = "".join(chr(c) for c in range(0x20, 0x7F) if chr(c) not in '"\\%')
_AGENT_SAFE = _REASON_SAFE.replace(",", "")
_UNREADABLE = {"agents": [], "until": None, "reason": "pause file unreadable"}  # fail closed: pause every agent


def _encode(state: dict) -> dict:
    doc = {"since": state["since"], "agents": ",".join(quote(a, safe=_AGENT_SAFE) for a in state["agents"]),
           "reason": quote(state["reason"], safe=_REASON_SAFE)}
    if state["until"]:
        doc["until"] = state["until"]
    return doc


def _decode(doc: object) -> tuple[dict, datetime | None] | None:
    """(public view, expiry) from a current or legacy document, or None when it is malformed."""
    if not isinstance(doc, dict):
        return None
    since, agents, reason = doc.get("since", ""), doc.get("agents", ""), doc.get("reason", "")
    until = doc.get("until")
    if not isinstance(since, str) or not isinstance(reason, str):
        return None
    if isinstance(agents, str):                                       # current encoding
        agents, reason = [unquote(a) for a in agents.split(",") if a], unquote(reason)
    elif not (isinstance(agents, list) and all(isinstance(a, str) for a in agents)):
        return None                                                   # legacy shape is a list of names
    expiry = None
    if until in (None, ""):
        until = None
    elif isinstance(until, str):
        try:
            expiry = datetime.fromisoformat(until)
        except ValueError:
            return None
        if expiry.tzinfo is None:
            return None
    else:
        return None
    return {"since": since, "agents": agents, "until": until, "reason": reason}, expiry


def _read_legacy(path: Path) -> object | None:
    """Plain JSON read for a file `statefile.read_state` refused, only when nobody but this user could have written
    it (regular file, owned by the effective user, no group/other write bit). None otherwise."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > statefile.MAX_BYTES:
            return None
        if hasattr(os, "geteuid") and (st.st_uid != os.geteuid() or st.st_mode & 0o022):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            if (os.fstat(fd).st_ino, os.fstat(fd).st_dev) != (st.st_ino, st.st_dev):
                return None
            raw = os.read(fd, statefile.MAX_BYTES + 1)
        finally:
            os.close(fd)
        return json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


def pause(home: Path, *, agents: list[str] | None = None, minutes: float | None = None, reason: str = "") -> dict:
    now = datetime.now(UTC)
    state = {"since": now.isoformat(timespec="seconds"), "agents": sorted(set(agents or [])),
             "until": (now + timedelta(minutes=minutes)).isoformat(timespec="seconds") if minutes else None,
             "reason": reason}
    errors: list[str] = []
    if not statefile.write_state(home / FILE, _encode(state), on_error=lambda _f, why: errors.append(why)):
        raise OSError(f"cannot write {home / FILE}: {errors[0] if errors else 'state_write_failed'}")
    return state


def resume(home: Path) -> bool:
    try:
        (home / FILE).unlink()
        return True
    except FileNotFoundError:
        return False


class PauseState:
    """Cached view of pause.json, re-read when its (mtime, size, inode) changes."""

    def __init__(self, home: Path, *, on_error: statefile.ErrorCallback | None = None):
        self.path = home / FILE
        self.on_error = on_error
        self._sig: tuple[int, int, int] | None = None
        self._state: dict | None = None
        self._expiry: datetime | None = None

    def _load(self) -> None:
        errors: list[tuple[str, str]] = []
        doc = statefile.read_state(self.path, {}, on_error=lambda f, why: errors.append((f, why)))
        if doc is None and not errors:                                 # vanished between stat and read
            self._state, self._expiry = None, None
            return
        decoded = _decode(doc if doc is not None else _read_legacy(self.path))
        if decoded is None:
            self._state, self._expiry = dict(_UNREADABLE), None
            if self.on_error is not None:
                for f, why in errors or [(str(self.path), "state_unreadable:wrong_type")]:
                    self.on_error(f, why)
        else:
            self._state, self._expiry = decoded

    def current(self) -> dict | None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._sig, self._state, self._expiry = None, None, None
            return None
        except OSError:
            self._sig, self._state, self._expiry = None, dict(_UNREADABLE), None
            return self._state
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        if sig != self._sig:
            self._load()
            self._sig = sig
        if self._expiry is not None and self._expiry <= datetime.now(UTC):
            return None
        return self._state

    def applies(self, agent: str) -> dict | None:
        st = self.current()
        if st is None:
            return None
        return st if not st.get("agents") or agent in st["agents"] else None
