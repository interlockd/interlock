"""`interlock bench` smoke test: every path reports percentiles, the verified and unverified http rows are both
measured against an intact enforcement point, `--budget-ms` gates on the Δp95, and nothing is left behind."""

from __future__ import annotations

import os
import tempfile

import pytest

from interlockd import bench, integrity
from interlockd.bench import HTTP, HTTP_NO_VERIFY, format_results, over_budget, run, verify_delta


@pytest.fixture
def made_homes(monkeypatch):
    """The temp homes this run created (not a glob over /tmp, which a concurrent run can populate)."""
    made: list[str] = []
    real = tempfile.mkdtemp

    def mkdtemp(*a, **kw):
        path = real(*a, **kw)
        made.append(path)
        return path

    monkeypatch.setattr(bench.tempfile, "mkdtemp", mkdtemp)
    return made


def test_bench_reports_every_path(made_homes, monkeypatch):
    seen: list[integrity.Verification] = []
    real_verify = integrity.Verifier.verify

    def spy(self, harness, reported=None):
        v = real_verify(self, harness, reported)
        seen.append(v)
        return v

    monkeypatch.setattr(integrity.Verifier, "verify", spy)
    r = run(rounds=1, http_calls=5, shim_calls=2)
    assert {"decide", "probe 4 KB", HTTP, HTTP_NO_VERIFY} <= set(r)
    for v in r.values():
        assert v["n"] > 0 and 0 <= v["p50"] <= v["p99"]
    assert r[HTTP]["n"] == r[HTTP_NO_VERIFY]["n"] == 5
    # the verified row ran the real check against an intact, baselined enforcement point (not `no_baseline`)
    assert len(seen) >= 5 and all(v.problem == "" for v in seen)
    out = format_results(r)
    assert "p50 ms" in out and "verify Δp95 ms" in out
    assert made_homes and not any(os.path.exists(p) for p in made_homes)


def _rows(p95_verify: float, p95_plain: float) -> dict[str, dict]:
    row = lambda p95: {"n": 300, "p50": 1.0, "p95": p95, "p99": p95 + 1}
    return {HTTP: row(p95_verify), HTTP_NO_VERIFY: row(p95_plain)}


def test_verify_delta_and_budget():
    r = _rows(2.75, 2.25)
    assert verify_delta(r) == 0.5
    assert not over_budget(r, None)
    assert not over_budget(r, 0.5) and not over_budget(r, 1.0)
    assert over_budget(r, 0.4)
    assert verify_delta({HTTP: r[HTTP]}) is None and over_budget({HTTP: r[HTTP]}, 1.0)   # unmeasured → fail
    assert bench.MIN_HTTP_CALLS >= 300


def test_cli_budget_exit_code(monkeypatch, capsys):
    from interlockd import cli

    calls = []

    def fake_run(**kw):
        calls.append(kw)
        return _rows(3.0, 1.0)

    monkeypatch.setattr(bench, "run", fake_run)
    assert cli.main(["bench", "--rounds", "1", "--budget-ms", "1"]) == 1
    assert "budget exceeded" in capsys.readouterr().err
    assert cli.main(["bench", "--rounds", "1", "--budget-ms", "2.5"]) == 0
    assert cli.main(["bench", "--rounds", "1"]) == 0
    assert "http_calls" not in calls[0]          # the command keeps run()'s ≥300-call default
