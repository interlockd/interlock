"""`interlock selftest` against a real daemon in every harness format; repeated runs never trip the denial budget."""

from __future__ import annotations

import pytest

from interlockd.api import ApiServer
from interlockd.selftest import CASES, is_selftest, run

HARNESSES = ["claude-code", "codex", "cursor", "gemini-cli", "kiro"]


@pytest.fixture
def daemon_api(settings, tmp_path):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = [str(tmp_path)]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    api = ApiServer(d, "tok", "127.0.0.1", 0); api.start_background()
    yield "{}:{}".format(*api.address), d
    api.shutdown()


def test_selftest_all_harnesses_twice(daemon_api, tmp_path):
    listen, d = daemon_api
    for _ in range(2):                                              # the second run must not inherit denials
        rows, mode = run(listen, "tok", HARNESSES, cwd=str(tmp_path))
        assert mode == "enforce" and len(rows) == len(HARNESSES) * len(CASES)
        assert all(r.ok for r in rows), [(r.harness, r.label, r.decision) for r in rows if not r.ok]
    recs = list(d.spool.iter_records())
    assert recs and all(is_selftest(r) for r in recs)               # every event is tagged, so views can skip it


def test_shadow_reports_what_enforce_would_do(daemon_api, tmp_path):
    listen, d = daemon_api
    d.mode = "shadow"
    rows, mode = run(listen, "tok", ["claude-code"], cwd=str(tmp_path))
    assert mode == "shadow" and all(r.ok for r in rows) and rows[0].decision == "block"


def test_unreachable_daemon():
    rows, msg = run("127.0.0.1:9", "tok", ["claude-code"])
    assert rows == [] and "not reachable" in msg
