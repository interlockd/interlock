"""Hook watch: the daemon re-checks the hooks `interlock init` installed and records every change.

Shims an upgrade left behind (they differ only in their version line) are refreshed in place. A removed hook, a
deleted or edited shim, and a later repair each become a `control` record in the hash-chained
audit log (and the OpenTelemetry export, when configured), so lost enforcement is on the record even if nobody runs
`interlock doctor`. Interlock cannot block an agent whose hook is gone; it can make sure that is noticed.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from . import __version__
from .ids import ulid

INTERVAL_S = 60.0
log = logging.getLogger("interlockd.watch")


class HookWatch:
    def __init__(self, daemon: Any, home: Path, *, interval: float = INTERVAL_S):
        self.daemon, self.home, self.interval = daemon, Path(home), interval
        self.state: dict[str, str] | None = None     # harness -> problem ("" when intact); None before the first check
        self._stop = threading.Event()

    def check(self) -> list[dict[str, Any]]:
        """Compare with the last check and record what changed. The first check records only problems."""
        from .insights import hook_integrity, refresh_outdated_shims
        from .pipeline import _now_iso

        for shim in refresh_outdated_shims(self.home):      # left by an upgrade: not tampering, so just refresh them
            log.info("refreshed %s for interlock %s", shim, __version__)
        rows = {h["harness"]: h for h in hook_integrity(self.home)}
        prev = self.state or {}
        out = []
        for name, h in rows.items():
            before = prev.get(name, "")
            if h["problem"] != before and (h["problem"] or self.state is not None):
                out.append(self._record(h, before, _now_iso()))
        self.state = {n: h["problem"] for n, h in rows.items()}
        for rec in out:
            self.daemon.spool.append(rec)
            if self.daemon.otel is not None:
                self.daemon.otel.submit(rec)
        return out

    def _record(self, h: dict[str, str], before: str, at: str) -> dict[str, Any]:
        problem = h["problem"]
        reason = h["detail"] if problem else f"Interlock hook for {h['harness']} restored ({before.replace('_', ' ')} before)"
        findings = [{"category": "control.hook_tamper", "severity": "high", "rule": f"control.{problem}",
                     "detector": "interlock.watch", "path": "hook", "subject": h["file"], "score": 1.0}] if problem else []
        return {"event_id": ulid(), "received_at": at, "kind": "control", "adapter": "interlock", "adapter_version": __version__,
                "agent_type": h["harness"], "session_id": "interlock-watch", "tool_name": "interlock.hooks",
                "arguments": {"harness": h["harness"], "path": h["file"], "problem": problem or "restored"},
                "tier": 0, "normalized": {"action_class": "control"}, "disposition": "flag" if problem else "allow",
                "mode": self.daemon.mode, "reason": reason, "findings": findings, "timing_ms": {},
                "policy_sha256": self.daemon.policy_sha256, "daemon_version": __version__}

    def _safe_check(self) -> None:
        try:
            self.check()
        except Exception:
            log.exception("hook watch check failed")

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self._safe_check()

    def start(self) -> HookWatch:
        self._safe_check()
        threading.Thread(target=self._loop, name="interlock-hook-watch", daemon=True).start()
        return self

    def stop(self) -> None:
        self._stop.set()
