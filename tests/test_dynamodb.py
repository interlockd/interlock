import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from datetime import UTC

from interlockd.store.drainer import Drainer
from interlockd.store.dynamodb import DynamoRepository
from interlockd.store.spool import Spool


def _rec(i, disp="allow", ws="proj", hour="01"):
    return {"event_id": f"01J9TEST{i:018d}", "received_at": f"2026-10-08T{hour}:02:03.000Z", "agent_workspace": ws,
            "session_id": "s1", "disposition": disp, "tool_name": "execute_bash", "timing_ms": {"total": 1.5}}


@pytest.fixture
def repo(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with moto.mock_aws():
        yield DynamoRepository.ensure_table("interlock-audit-test", region="us-east-1")


def test_put_get_session_and_review_index(repo):
    repo.put_event(_rec(1))
    repo.put_event(_rec(2, disp="block"))
    got = repo.get_event(_rec(2)["event_id"])
    assert got["disposition"] == "block" and got["GSI3PK"] == "DISP#block#2026-10-08" and got["timing_ms"]["total"] == 1.5
    assert "GSI3PK" not in repo.get_event(_rec(1)["event_id"])  # sparse review index
    repo.put_session({"session_id": "s1", "calls": 2})
    assert repo.get_session("s1")["calls"] == 2
    ttl = repo.ddb.meta.client.describe_time_to_live(TableName="interlock-audit-test")["TimeToLiveDescription"]
    assert ttl["AttributeName"] == "expires_at"


def test_drainer_moves_spool_to_table(repo, tmp_path):
    sp = Spool(tmp_path / "spool", fsync=False)
    from datetime import datetime

    hour = datetime.now(UTC).strftime("%Y-%m-%dT%H")
    for i in range(30):
        r = _rec(i)
        r["received_at"] = f"{hour}:00:00.000Z"
        sp.append(r)
    d = Drainer(sp, repo, batch=25)
    assert d.drain_once() == 30
    assert d.drain_once() == 0
    rows = repo.tail("proj", limit=10)
    assert len(rows) == 10 and rows[0]["event_id"] > rows[-1]["event_id"]
