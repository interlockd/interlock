from interlockd.store.spool import Spool


def _rec(i, day="2026-10-08"):
    return {"event_id": f"E{i:03d}", "received_at": f"{day}T01:02:03.000Z", "agent_workspace": "proj"}


def test_append_iter_and_drain(tmp_path):
    sp = Spool(tmp_path / "spool")
    for i in range(5):
        sp.append(_rec(i))
    sp.append(_rec(9, day="2026-10-09"))
    assert [r["event_id"] for r in sp.iter_records(limit=3)] == ["E009", "E004", "E003"]
    assert [r["event_id"] for r in sp.iter_records(reverse=False)][:2] == ["E000", "E001"]

    pending = list(sp.undrained())
    assert len(pending) == 6
    seg, off, _ = pending[2]
    sp.mark_drained(seg, off)
    rest = [r["event_id"] for _, _, r in sp.undrained()]
    assert rest == ["E003", "E004", "E009"]
    assert sp.drained_offset(seg) == off


def test_append_is_one_line_and_durable(tmp_path):
    sp = Spool(tmp_path / "spool")
    sp.append({"event_id": "X", "received_at": "2026-10-08T00:00:00Z", "text": "multi\nline"})
    (seg,) = sp.segments()                       # one segment per write day, whatever the record's received_at
    lines = seg.read_text().splitlines()
    assert len(lines) == 1 and '"text":"multi\\nline"' in lines[0]
