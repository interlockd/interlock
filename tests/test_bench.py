"""`interlock bench` smoke test: every path reports percentiles, and nothing is left behind."""

from __future__ import annotations

import glob

from interlockd.bench import format_results, run


def test_bench_reports_every_path():
    before = set(glob.glob("/tmp/ilb*"))
    r = run(rounds=1, http_calls=5, shim_calls=2)
    assert {"decide", "probe 4 KB", "http"} <= set(r)
    for v in r.values():
        assert v["n"] > 0 and 0 <= v["p50"] <= v["p99"]
    assert "p50 ms" in format_results(r)
    assert set(glob.glob("/tmp/ilb*")) <= before
