"""A small client for the local Interlock daemon, shared by framework integrations.

    from interlockd.integrations.client import InterlockClient
    v = InterlockClient().decide("pre_action", "shell", {"command": "git push --force origin main"})
    if InterlockClient.stops(v): ...

Reads the token, the daemon address, and the fail mode from ~/.interlock (or INTERLOCK_HOME / INTERLOCK_URL), like
the hook shims. Returns the daemon's verdict dict, or None when the daemon can't be reached (apply `fails_closed()`).
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from .. import __version__


class InterlockClient:
    def __init__(self, *, home: str | Path | None = None, url: str | None = None, token: str | None = None,
                 agent_type: str = "sdk", session: str | None = None, timeout: float = 1.5):
        self.home = Path(home or os.environ.get("INTERLOCK_HOME") or "~/.interlock").expanduser()
        self._url, self._token = url or os.environ.get("INTERLOCK_URL"), token
        self.agent_type, self.session, self.timeout = agent_type, session, timeout

    @property
    def url(self) -> str:
        if self._url:
            return self._url.rstrip("/")
        try:
            listen = json.loads((self.home / "daemon.json").read_text()).get("listen") or "127.0.0.1:7391"
        except (OSError, ValueError):
            listen = "127.0.0.1:7391"
        return f"http://{listen}"

    @property
    def token(self) -> str:
        if self._token is None:
            try:
                self._token = (self.home / "token").read_text().strip()
            except OSError:
                self._token = ""
        return self._token

    def fails_closed(self) -> bool:
        env = os.environ.get("INTERLOCK_FAIL_MODE")
        if env in ("open", "closed"):
            return env == "closed"
        try:
            return json.loads((self.home / "fail-mode.json").read_text()).get("default") == "closed"
        except (OSError, ValueError):
            return False

    def decide(self, kind: str, tool: str, arguments: dict | None = None, *, content: str | None = None,
               session: str | None = None, cwd: str | None = None, withhold: bool = True) -> dict[str, Any] | None:
        if not self.token:
            return None
        event: dict[str, Any] = {
            "kind": kind, "adapter": {"name": self.agent_type, "version": __version__},
            "session_hint": session or self.session, "identity": {"agent_type": self.agent_type},
            "tool_call": {"name": str(tool), "arguments": arguments if isinstance(arguments, dict) else {"value": arguments}},
            "context": {"cwd": cwd or os.getcwd()}, "capabilities": {"ask": False, "rewrite": False, "withhold": withhold}}
        if content is not None:
            event["result"] = {"content": content[:200_000]}
        req = urllib.request.Request(f"{self.url}/interlock/v1/decide", data=json.dumps(event).encode(), method="POST")
        req.add_header("authorization", f"Bearer {self.token}")
        req.add_header("content-type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout if kind == "pre_action" else self.timeout + 1) as r:
                return json.loads(r.read())
        except Exception:  # noqa: BLE001  unreachable daemon: the caller applies fails_closed()
            return None

    @staticmethod
    def stops(v: dict | None) -> bool:
        return bool(v) and v.get("mode") == "enforce" and v.get("disposition") in ("block", "ask")

    @staticmethod
    def withholds(v: dict | None) -> bool:
        return bool(v) and v.get("mode") == "enforce" and v.get("disposition") == "withhold"

    UNREACHABLE = "[interlock] This action was NOT executed: the Interlock daemon is unreachable and this machine fails closed."
