"""The kill switch: `interlock pause` / `interlock resume`.

While paused, every pre-action call (all agents, or the named ones) is refused, through hooks, SDK integrations,
the MCP gateway, and the egress proxy alike. Pausing is an explicit user action, so it is enforced even in shadow
mode. State is a small file the daemon re-reads when it changes, so pausing takes effect on the next call.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .det import rule

R_PAUSED = rule("control.paused", "control.kill_switch", "critical", "block")
FILE = "pause.json"


def pause(home: Path, *, agents: list[str] | None = None, minutes: float | None = None, reason: str = "") -> dict:
    state = {"since": datetime.now(UTC).isoformat(timespec="seconds"), "agents": sorted(set(agents or [])),
             "until": (datetime.now(UTC) + timedelta(minutes=minutes)).isoformat(timespec="seconds") if minutes else None,
             "reason": reason}
    home.mkdir(parents=True, exist_ok=True)
    tmp = home / (FILE + ".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    os.replace(tmp, home / FILE)
    return state


def resume(home: Path) -> bool:
    try:
        (home / FILE).unlink()
        return True
    except FileNotFoundError:
        return False


class PauseState:
    """Cached view of pause.json, re-read when its mtime changes."""

    def __init__(self, home: Path):
        self.path = home / FILE
        self._mtime: float | None = None
        self._state: dict | None = None

    def current(self) -> dict | None:
        try:
            m = self.path.stat().st_mtime
        except FileNotFoundError:
            self._mtime, self._state = None, None
            return None
        if m != self._mtime:
            try:
                self._state = json.loads(self.path.read_text())
            except (OSError, ValueError):
                self._state = {"agents": [], "until": None, "reason": "pause file unreadable"}   # fail closed
            self._mtime = m
        st = self._state
        if st and st.get("until") and datetime.fromisoformat(st["until"]) <= datetime.now(UTC):
            return None
        return st

    def applies(self, agent: str) -> dict | None:
        st = self.current()
        if st is None:
            return None
        return st if not st.get("agents") or agent in st["agents"] else None
