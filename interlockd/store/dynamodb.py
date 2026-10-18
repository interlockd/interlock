"""DynamoDB single-table repository (design §7). boto3 is imported lazily so the daemon runs without it.

Items:
  Event            PK=EVT#<event_id>  SK=EVT
  Explanation      PK=EVT#<event_id>  SK=EXPL
  Feedback         PK=EVT#<event_id>  SK=FDBK#<ulid>
  Session summary  PK=SES#<session_id> SK=META
Indexes:
  GSI1-session         session_id / event_id
  GSI2-workspace-time  GSI2PK (WS#<workspace>#<yyyy-mm-dd-hh>) / event_id
  GSI3-review          GSI3PK (DISP#<disposition>#<yyyy-mm-dd>) / event_id   (sparse)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from . import hour_bucket

REVIEW_DISPOSITIONS = {"ask", "block", "withhold", "warn"}


def _to_ddb(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_ddb(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_ddb(v) for v in value]
    return value


def _from_ddb(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _from_ddb(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_ddb(v) for v in value]
    return value


TABLE_DEFINITION: dict[str, Any] = {
    "AttributeDefinitions": [
        {"AttributeName": "PK", "AttributeType": "S"},
        {"AttributeName": "SK", "AttributeType": "S"},
        {"AttributeName": "session_id", "AttributeType": "S"},
        {"AttributeName": "event_id", "AttributeType": "S"},
        {"AttributeName": "GSI2PK", "AttributeType": "S"},
        {"AttributeName": "GSI3PK", "AttributeType": "S"},
    ],
    "KeySchema": [{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
    "BillingMode": "PAY_PER_REQUEST",
    "GlobalSecondaryIndexes": [
        {"IndexName": "GSI1-session", "Projection": {"ProjectionType": "ALL"},
         "KeySchema": [{"AttributeName": "session_id", "KeyType": "HASH"}, {"AttributeName": "event_id", "KeyType": "RANGE"}]},
        {"IndexName": "GSI2-workspace-time", "Projection": {"ProjectionType": "ALL"},
         "KeySchema": [{"AttributeName": "GSI2PK", "KeyType": "HASH"}, {"AttributeName": "event_id", "KeyType": "RANGE"}]},
        {"IndexName": "GSI3-review", "Projection": {"ProjectionType": "ALL"},
         "KeySchema": [{"AttributeName": "GSI3PK", "KeyType": "HASH"}, {"AttributeName": "event_id", "KeyType": "RANGE"}]},
    ],
}


class DynamoRepository:
    def __init__(self, table_name: str, *, region: str | None = None, profile: str | None = None, retention_days: int = 90, resource=None):
        import boto3  # lazy

        self.ddb = resource or boto3.Session(profile_name=profile, region_name=region).resource("dynamodb")
        self.table = self.ddb.Table(table_name)
        self.table_name = table_name
        self.retention_days = retention_days

    @classmethod
    def ensure_table(cls, table_name: str, *, region: str | None = None, resource=None) -> DynamoRepository:
        import boto3  # lazy

        ddb = resource or boto3.resource("dynamodb", region_name=region)
        existing = [t.name for t in ddb.tables.all()]
        if table_name not in existing:
            t = ddb.create_table(TableName=table_name, **TABLE_DEFINITION)
            t.wait_until_exists()
            ddb.meta.client.update_time_to_live(
                TableName=table_name, TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires_at"}
            )
        return cls(table_name, region=region, resource=ddb)

    def _event_item(self, record: dict[str, Any]) -> dict[str, Any]:
        item = _to_ddb(dict(record))
        item["PK"] = f"EVT#{record['event_id']}"
        item["SK"] = "EVT"
        ws = record.get("agent_workspace") or ""
        item["GSI2PK"] = f"WS#{ws}#{hour_bucket(record['received_at'])}"
        if record.get("disposition") in REVIEW_DISPOSITIONS:
            item["GSI3PK"] = f"DISP#{record['disposition']}#{record['received_at'][:10]}"
        if "expires_at" not in item:
            exp = datetime.now(UTC) + timedelta(days=self.retention_days)
            item["expires_at"] = int(exp.timestamp())
        return item

    def put_event(self, record: dict[str, Any]) -> None:
        self.table.put_item(Item=self._event_item(record))

    def put_events(self, records: list[dict[str, Any]]) -> None:
        with self.table.batch_writer() as bw:
            for r in records:
                bw.put_item(Item=self._event_item(r))

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        r = self.table.get_item(Key={"PK": f"EVT#{event_id}", "SK": "EVT"})
        item = r.get("Item")
        return _from_ddb(item) if item else None

    def tail(self, workspace: str | None = None, limit: int = 50, *, hours_back: int = 48) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key  # lazy

        out: list[dict[str, Any]] = []
        now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
        ws = workspace or ""
        for h in range(hours_back):
            bucket = (now - timedelta(hours=h)).strftime("%Y-%m-%d-%H")
            resp = self.table.query(
                IndexName="GSI2-workspace-time",
                KeyConditionExpression=Key("GSI2PK").eq(f"WS#{ws}#{bucket}"),
                ScanIndexForward=False,
                Limit=limit - len(out),
            )
            out.extend(_from_ddb(i) for i in resp.get("Items", []))
            if len(out) >= limit:
                break
        return out[:limit]

    def put_session(self, summary: dict[str, Any]) -> None:
        item = _to_ddb(dict(summary))
        item["PK"] = f"SES#{summary['session_id']}"
        item["SK"] = "META"
        self.table.put_item(Item=item)

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        r = self.table.get_item(Key={"PK": f"SES#{session_id}", "SK": "META"})
        item = r.get("Item")
        return _from_ddb(item) if item else None
