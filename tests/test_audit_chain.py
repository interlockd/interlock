"""Hash-chained spool: intact chains verify; edits, deletions, reordering, and insertions are caught."""

from __future__ import annotations

import json

import pytest

from interlockd.cli import main
from interlockd.store.spool import GENESIS, Spool


@pytest.fixture
def sp(tmp_path):
    s = Spool(tmp_path / "spool", fsync=False)
    for i in range(5):
        s.append({"event_id": f"e{i}", "received_at": "2026-10-17T00:00:00Z", "disposition": "allow", "n": i, "f": 0.1 * i})
    return s


def _lines(sp):
    (seg,) = sp.segments()
    return seg, seg.read_text().splitlines()


def test_intact(sp):
    r = sp.verify()
    assert r["ok"] and r["records"] == 5 and r["head"] == sp.head() != GENESIS
    _, lines = _lines(sp)
    assert json.loads(lines[0])["prev_hash"] == GENESIS and json.loads(lines[1])["prev_hash"] == json.loads(lines[0])["hash"]


@pytest.mark.parametrize("tamper,reason", [
    (lambda ls: ls[:2] + [ls[2].replace('"disposition":"allow"', '"disposition":"block"')] + ls[3:], "edited"),
    (lambda ls: ls[:2] + ls[3:], "removed or reordered"),
    (lambda ls: [ls[1], ls[0]] + ls[2:], "start the chain"),
    (lambda ls: ls[:3] + ['{"event_id":"fake","disposition":"allow"}'] + ls[3:], "inserted"),
    (lambda ls: ls[1:], "start the chain"),
])
def test_tamper_is_detected(sp, tamper, reason):
    seg, lines = _lines(sp)
    seg.write_text("\n".join(tamper(lines)) + "\n")
    r = sp.verify()
    assert not r["ok"] and reason in r["break"]["reason"]


def test_legacy_prefix_then_chain(tmp_path):
    d = tmp_path / "spool"; d.mkdir()
    (d / "2026-10-01.jsonl").write_text('{"event_id":"old1"}\n{"event_id":"old2"}\n')
    s = Spool(d, fsync=False)
    s.append({"event_id": "new"})
    r = s.verify()
    assert r["ok"] and r["legacy"] == 2 and r["records"] == 1


def test_cli_verify_and_anchor(sp, tmp_path, capsys, monkeypatch):
    home = sp.dir.parent
    monkeypatch.setenv("INTERLOCK_HOME", str(home))
    assert main(["audit", "verify"]) == 0 and "intact: 5 chained records" in capsys.readouterr().out
    assert main(["audit", "head"]) == 0
    head = capsys.readouterr().out.strip()
    seg, lines = _lines(sp)
    seg.write_text("\n".join(lines[:-1]) + "\n")                       # truncate the newest record
    assert main(["audit", "verify"]) == 0                             # a truncated chain is still a valid chain...
    capsys.readouterr()
    assert main(["audit", "verify", "--expect-head", head]) == 1      # ...but not against the anchored head
    assert "removed or rewritten" in capsys.readouterr().out
