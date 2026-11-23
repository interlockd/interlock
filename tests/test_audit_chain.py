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
    return seg, seg.read_text(encoding="utf-8").splitlines()


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
    seg.write_text("\n".join(tamper(lines)) + "\n", encoding="utf-8")
    r = sp.verify()
    assert not r["ok"] and reason in r["break"]["reason"]


def test_legacy_prefix_then_chain(tmp_path):
    d = tmp_path / "spool"; d.mkdir()
    (d / "2026-10-01.jsonl").write_text('{"event_id":"old1"}\n{"event_id":"old2"}\n', encoding="utf-8")
    s = Spool(d, fsync=False)
    s.append({"event_id": "new"})
    r = s.verify()
    assert r["ok"] and r["legacy"] == 2 and r["records"] == 1


@pytest.mark.parametrize("ch", ["\x85", "\u2028", "\u2029"])
def test_records_with_non_newline_line_breaks_round_trip(tmp_path, ch):
    """`append` writes ensure_ascii=False, so these characters land raw in the line (JSON escapes only C0 controls);
    str.splitlines() treats them as breaks, so readers must split on "\\n" only."""
    s = Spool(tmp_path / "spool", fsync=False)
    s.append({"event_id": "a", "arguments": {"command": "echo 1"}})
    s.append({"event_id": "b", "arguments": {"command": f"x{ch}y"}})
    s.append({"event_id": "c"})
    (seg,) = s.segments()
    assert ch in seg.read_text(encoding="utf-8")
    r = s.verify()
    assert r["ok"] and r["records"] == 3, r["break"]
    assert [x["event_id"] for x in s.iter_records()] == ["c", "b", "a"]
    assert [x["event_id"] for x in s.iter_records(reverse=False)] == ["a", "b", "c"]
    assert [x["arguments"]["command"] for x in s.iter_records(limit=2) if "arguments" in x] == [f"x{ch}y"]
    assert s.head() == r["head"]
    assert [rec["event_id"] for _, _, rec in s.undrained()] == ["a", "b", "c"]


def test_break_line_numbers_count_newlines_only(tmp_path):
    s = Spool(tmp_path / "spool", fsync=False)
    for i in range(3):
        s.append({"event_id": f"e{i}", "arguments": {"command": "a\u2028b"}})
    (seg,) = s.segments()
    lines = seg.read_text(encoding="utf-8").split("\n")[:-1]
    lines[2] = lines[2].replace('"e2"', '"zz"')
    seg.write_text("".join(x + "\n" for x in lines), encoding="utf-8")
    r = s.verify()
    assert not r["ok"] and r["break"]["line"] == 3 and "edited" in r["break"]["reason"]


def test_dropping_the_hash_of_the_first_chained_record_is_detected(sp):
    """Without `hash` the first record looks legacy; the next record must still be held to the genesis check."""
    seg, lines = _lines(sp)
    first = json.loads(lines[0])
    del first["hash"]
    lines[0] = json.dumps(first, separators=(",", ":"))
    seg.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = sp.verify()
    assert not r["ok"] and r["break"]["line"] == 2 and "start the chain" in r["break"]["reason"]


def test_legacy_only_spool_head_is_genesis_and_chain_continues(tmp_path):
    d = tmp_path / "spool"; d.mkdir()
    (d / "2026-10-01.jsonl").write_text('{"event_id":"old1"}\n', encoding="utf-8")
    s = Spool(d, fsync=False)
    assert s.head() == GENESIS
    s.append({"event_id": "new1"})
    s.append({"event_id": "new2"})
    r = s.verify()
    assert r["ok"] and r["legacy"] == 1 and r["records"] == 2


def test_cli_verify_and_anchor(sp, tmp_path, capsys, monkeypatch):
    home = sp.dir.parent
    monkeypatch.setenv("INTERLOCK_HOME", str(home))
    assert main(["audit", "verify"]) == 0 and "intact: 5 chained records" in capsys.readouterr().out
    assert main(["audit", "head"]) == 0
    head = capsys.readouterr().out.strip()
    seg, lines = _lines(sp)
    seg.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")                       # truncate the newest record
    assert main(["audit", "verify"]) == 0                             # a truncated chain is still a valid chain...
    capsys.readouterr()
    assert main(["audit", "verify", "--expect-head", head]) == 1      # ...but not against the anchored head
    assert "removed or rewritten" in capsys.readouterr().out
