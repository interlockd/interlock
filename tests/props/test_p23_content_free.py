"""Property 23: record builders and export surfaces are content-free (Requirements 8.7, 10.1, 10.7, 13.2-13.7).

Every `records.*` builder is called with a marker string planted in each free-form input (paths, digests, reason and
code fields, harness names, adapter names, addresses, timestamps, policy key names, optional fields). The marker
stands for content Interlock must not copy: a command, file text or a Home path. It always contains a space or a
slash, as such content does, so it is never a valid code.

- A record has only the existing schema fields and only the `arguments` keys allowlisted for its kind. Outside
  the fields meant to name an Interlock-owned file or a self-reported sender (`path`, `file`, `adapter`, `addr`),
  it carries no marker, and every digest field is "" or 64 lowercase hex.
- The `plugin_api.Decision` read back from the spool exposes `tamper_kind` and `protection_state` from their fixed
  sets and no marker. This also holds when every argument value of a control record is replaced by a marker.
- `otel.span_from_record` uses only the existing decision attributes plus `interlock.tamper_kind` and
  `interlock.protection_state`, and the span carries no marker.
- The Console add-on heartbeat (`interlockd_console.link`, a separate repository) built from a marker-laden
  ProtectionStatus and spool contains no marker and only fixed reason codes. That test is skipped when the add-on
  cannot be imported.
"""

from __future__ import annotations

import dataclasses
import json
import re
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from interlockd import otel, plugin_api, records
from interlockd.store.spool import Spool

from .strategies import (
    HARNESS_REASONS,
    HOME_REASONS,
    PROPS,
    STATES,
    harnesses,
    home_paths,
    iso_timestamps,
    posix_modes,
    sha256_hex,
)

# --- markers ------------------------------------------------------------------------------------------------------

_HEX = "0123456789abcdef"
cores = st.text(alphabet=_HEX, min_size=12, max_size=12).map(lambda h: f"MK{h}")
"""The detectable part of a marker; one per example."""

_TEMPLATES = (
    "{m} text", "/Users/{m}/.interlock/adapters/x.sh", "rm -rf ~ # {m}", "{m}\n", 'é"{m}\'', "\x00{m}\x1b",
    "{m}/{m}", "policy: {m} value", " {m}",
)


def free(core: str) -> st.SearchStrategy[str]:
    """Free-form text carrying the marker, as a file, a command or a Home path would."""
    return st.sampled_from(_TEMPLATES).map(lambda t: t.format(m=core))


# Fields meant to name an Interlock-owned or hook-config file, or the sender a rejected request named itself.
# A marker inside one of these values is the caller's own path or name and is allowed (Requirement 13.2, 2.4).
TEXT_FIELDS = frozenset({"path", "file", "adapter", "addr"})
SCHEMA_FIELDS = frozenset({
    "event_id", "received_at", "kind", "adapter", "adapter_version", "agent_type", "session_id", "tool_name",
    "arguments", "tier", "normalized", "disposition", "mode", "reason", "findings", "timing_ms", "policy_sha256",
    "daemon_version",
})
FINDING_FIELDS = frozenset({"category", "severity", "rule", "detector", "path", "subject", "score"})
DECISION_ATTRS = frozenset({
    "gen_ai.operation.name", "gen_ai.tool.name", "gen_ai.tool.call.id", "gen_ai.agent.name",
    "gen_ai.conversation.id", "interlock.event_id", "interlock.kind", "interlock.disposition", "interlock.mode",
    "interlock.tier", "interlock.action_class", "interlock.rules", "interlock.workspace",
    "interlock.policy_sha256", "interlock.unjudged",
})
CONTROL_ATTRS = frozenset({"interlock.tamper_kind", "interlock.protection_state"})
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TS = re.compile(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z?$")
TIME_FIELDS = frozenset({"first_at", "last_at", "span_from", "span_to"})
REASON_CODES = HARNESS_REASONS | HOME_REASONS


# --- one call per builder -----------------------------------------------------------------------------------------

def _calls(data: st.DataObject, core: str) -> dict[str, dict]:
    """{record name: the record its builder returns} with marker-laden inputs drawn for every free-form parameter."""
    f = free(core)

    def d(strategy, label):
        return data.draw(strategy, label=label)

    def code(*valid):
        return d(st.one_of(st.sampled_from(valid or ("ok",)), f), "code")

    def harness():
        return d(st.one_of(harnesses(), f), "harness")

    def digest():
        return d(st.one_of(sha256_hex(), st.just(""), f), "digest")

    def path():
        return d(st.one_of(home_paths().map(lambda h: f"{h}/{core}/x"), f), "path")

    def ts():
        return d(st.one_of(iso_timestamps(), f), "ts")

    def num():
        return d(st.one_of(st.integers(0, 10**6), f), "num")

    def flag():
        return d(st.one_of(st.booleans(), f), "flag")

    def codes(*valid):
        return d(st.lists(st.one_of(st.sampled_from(valid), f), max_size=4), "codes")

    def state():
        return d(st.one_of(st.sampled_from(STATES), f), "state")

    def optional(make):
        return make() if d(st.booleans(), "optional") else None

    kinds = sorted(records.TAMPER_KINDS)
    def pkind():
        return d(st.sampled_from(("policy", "managed")), "policy_kind")

    out = {
        "tamper_event": records.tamper_event(
            d(st.sampled_from(kinds), "tamper_kind"), harness(), path(), digest(), digest(), code(*kinds),
            detector=code("watch", "verifier"), observed_mode=optional(lambda: d(st.one_of(posix_modes(), f), "m")),
            restored_mode=optional(lambda: d(st.one_of(posix_modes(), f), "m")),
            restore_error=optional(lambda: code("EACCES", ""))),
        "hook_restored": records.hook_restored(harness(), path(), code("hook_removed", "shim_missing")),
        "shim_repaired": records.shim_repaired(harness(), path(), digest()),
        "shim_repair_failed": records.shim_repair_failed(harness(), path(), code("EACCES", "EROFS")),
        "no_baseline": records.no_baseline(harness()),
        "baseline_created": records.baseline_created(path()),
        "identity_restored": records.identity_restored(path()),
        "operator_action": records.operator_action(
            code("init", "ack", "shadow"), harness(), state(), via=code("cli", "console"),
            caused_by=code("01JD0000000000000000000000"), confirmed=flag(), grace_s=num(), failed=flag()),
        "operator_ack": records.operator_ack(codes("claude-code:shim_modified", "home:policy_modified")),
        "protection_state": records.protection_state(
            d(st.one_of(st.just("home"), harnesses(), f), "subject"), state(), state(),
            codes(*sorted(REASON_CODES)), caused_by=code("01JD0000000000000000000000")),
        "daemon_started": records.daemon_started(flag(), code("restart", "stop", "")),
        "daemon_unexpected_exit": records.daemon_unexpected_exit(num(), code("0.2.0")),
        "calls_unjudged": records.calls_unjudged(
            unjudged=num(), tamper_token_rejected=num(), tamper_daemon_identity=num(), tamper_daemon_lost=num(),
            span_from=ts(), span_to=ts()),
        "policy_baseline_set": records.policy_baseline_set(
            pkind(), path(), digest(), failed=flag(), previous_sha256=digest(),
            caused_by=code("01JD0000000000000000000000")),
        "policy_modified": records.policy_modified(
            pkind(), path(), digest(), digest(), added=codes("mode", "fail_mode"), removed=codes("trust"),
            changed=codes("packs", "judge"), unparseable=flag()),
        "policy_restored": records.policy_restored(
            pkind(), path(), digest(), rejected_sha256=digest(), caused_by=code("01JD0000000000000000000000", "")),
        "token_rejected": records.token_rejected(d(st.one_of(harnesses(), f), "adapter"), d(f, "addr")),
        "token_rejected_summary": records.token_rejected_summary(
            d(st.one_of(harnesses(), f), "adapter"), num(), ts(), ts()),
        "expected_after_rotate": records.expected_after_rotate(d(st.one_of(harnesses(), f), "adapter"),
                                                               d(f, "addr")),
        "state_unreadable": records.state_unreadable(path(), code("state_unreadable:nesting")),
        "state_permissions": records.state_permissions(path(), code("state_permissions:mode")),
        "state_write_failed": records.state_write_failed(path(), code("ENOSPC")),
        "notify_failed": records.notify_failed(code("osascript_failed")),
    }
    assert set(out) == set(records.BUILDERS), "every builder is exercised"
    return out


def _planted(rec: dict, core: str) -> dict:
    """`rec` with every argument value (the tamper kind and the protection state included) replaced by a marker."""
    args = {k: (v if k == "record" else f"{core} planted /x") for k, v in rec["arguments"].items()}
    args.update(tamper_kind=f"{core} kind", new=f"{core} new", protection_state=f"{core} state")
    return {**rec, "arguments": args}


def _without_text_fields(rec: dict) -> dict:
    return {**rec, "arguments": {k: v for k, v in rec["arguments"].items() if k not in TEXT_FIELDS}}


# --- records.* ----------------------------------------------------------------------------------------------------

# Feature: hook-tamper-detection, Property 23: Record builders and export surfaces are content-free
@PROPS
@given(st.data(), cores)
def test_record_builders_are_content_free(data, core):
    # **Validates: Requirements 8.7, 13.2, 13.3, 13.6, 13.7**
    for name, rec in _calls(data, core).items():
        assert set(rec) == SCHEMA_FIELDS, name                       # no cwd, state, answers, guardrails, result_*
        args = rec["arguments"]
        assert args["record"] == name
        assert set(args) <= records.ARGUMENT_KEYS[name], (name, set(args) - records.ARGUMENT_KEYS[name])
        assert rec["kind"] == "control" and rec["session_id"] == records.SESSION_ID and rec["tier"] == 0
        assert rec["normalized"] == {"action_class": "control"} and rec["timing_ms"] == {}

        tk = args.get("tamper_kind", "")
        assert tk == "" or tk in records.TAMPER_KINDS
        assert rec["disposition"] == ("flag" if tk else "allow")
        if tk:
            [finding] = rec["findings"]
            assert set(finding) == FINDING_FIELDS
            assert finding["category"] == records.FINDING_CATEGORY and finding["rule"] == f"control.{tk}"
            assert finding["path"] == "hook"
        else:
            assert rec["findings"] == []

        for k, v in args.items():
            if k.endswith("sha256"):
                assert v == "" or HEX64.match(v), (name, k)
            if k in TIME_FIELDS:
                assert v == "" or TS.match(v), (name, k)
        leaked = json.dumps(_without_text_fields(rec), ensure_ascii=False)
        assert core not in leaked, (name, leaked)


# Feature: hook-tamper-detection, Property 23: Record builders and export surfaces are content-free
@PROPS
@given(cores, st.sampled_from(("", " ", "shim modified", "token_rejected/x", "Shim_Modified", "rm -rf ~")))
def test_unknown_tamper_kind_is_refused(core, kind):
    # **Validates: Requirements 13.2**
    with pytest.raises(ValueError):
        records.tamper_event(kind or f"{core} kind", "claude-code", "/x", "", "", "")


# --- plugin_api.Decision and the OTel span ------------------------------------------------------------------------

# Feature: hook-tamper-detection, Property 23: Record builders and export surfaces are content-free
@PROPS
@given(st.data(), cores)
def test_decisions_and_spans_are_content_free(data, core):
    # **Validates: Requirements 13.4, 13.5**
    built = list(_calls(data, core).values())
    planted = [_planted(r, core) for r in built]
    with tempfile.TemporaryDirectory() as tmp:
        spool = Spool(Path(tmp) / "spool", fsync=False)
        for rec in built + planted:
            spool.append(rec)
        now = datetime.now(UTC)
        got = list(plugin_api.decisions(spool.dir, now - timedelta(days=1), now + timedelta(days=1)))

    assert len(got) == len(built) + len(planted)
    for i, dec in enumerate(got):
        assert core not in repr(dataclasses.astuple(dec)), dec
        assert dec.kind == "control"
        assert dec.tamper_kind == "" or dec.tamper_kind in records.TAMPER_KINDS
        assert dec.protection_state == "" or dec.protection_state in STATES
        if i < len(built):                                           # metadata survives for the real records
            args = built[i]["arguments"]
            assert dec.tamper_kind == args.get("tamper_kind", "")
            want = {"protection_state": args.get("new"), "operator_action": args.get("protection_state")}.get(
                args["record"], "")
            assert dec.protection_state == (want if want in STATES else "")
        else:                                                        # planted values never pass the fixed sets
            assert dec.tamper_kind == "" and dec.protection_state == ""

    for rec in built + planted:
        span = otel.span_from_record(rec)
        keys = {a["key"] for a in span["attributes"]}
        assert keys <= DECISION_ATTRS | CONTROL_ATTRS, keys - DECISION_ATTRS - CONTROL_ATTRS
        assert not keys & {"interlock.workspace", "gen_ai.tool.call.id", "interlock.unjudged"}
        attrs = {a["key"]: a["value"] for a in span["attributes"]}
        if "interlock.tamper_kind" in attrs:
            assert attrs["interlock.tamper_kind"]["stringValue"] in records.TAMPER_KINDS
        if "interlock.protection_state" in attrs:
            assert attrs["interlock.protection_state"]["stringValue"] in STATES
        assert core not in json.dumps(span, ensure_ascii=False), span


# --- Console add-on heartbeat -------------------------------------------------------------------------------------

_ADDON_SRC = Path(__file__).resolve().parents[3] / "interlock-pro" / "packages" / "interlockd-console" / "src"


def _heartbeat_module():
    """The add-on's `link` module, from an installed add-on or the sibling checkout; skip when neither exists."""
    if _ADDON_SRC.is_dir() and str(_ADDON_SRC) not in sys.path:
        sys.path.append(str(_ADDON_SRC))
    pytest.importorskip("interlockd_console")
    return pytest.importorskip("interlockd_console.link")


def _status(data: st.DataObject, core: str) -> plugin_api.ProtectionStatus:
    f = free(core)

    def d(strategy, label):
        return data.draw(strategy, label=label)

    def reasons(valid):
        return tuple(d(st.lists(st.one_of(st.sampled_from(sorted(valid)), f), max_size=4), "reasons"))

    hs = []
    for _ in range(d(st.integers(0, 4), "n_harnesses")):
        rs = reasons(HARNESS_REASONS)
        hs.append(plugin_api.HarnessProtection(
            d(st.one_of(harnesses(), f), "name"), d(st.one_of(st.sampled_from(STATES), f), "state"), rs,
            tuple(d(st.one_of(iso_timestamps(), f), "at") for _ in rs)))
    return plugin_api.ProtectionStatus(
        aggregate=d(st.one_of(st.sampled_from(STATES), f), "aggregate"), harnesses=tuple(hs),
        home_reasons=reasons(HOME_REASONS),
        last_tamper_at=d(st.one_of(st.none(), iso_timestamps(), f), "last_tamper_at"),
        tamper_count_since=d(st.one_of(st.integers(0, 1000), f), "count"),
        pinned_policy_sha256=d(st.one_of(st.none(), sha256_hex(), f), "pinned"),
        on_disk_policy_sha256=d(st.one_of(st.none(), sha256_hex(), f), "on_disk"),
        operator_action=d(st.one_of(st.none(), st.sampled_from(("shadow", "init", "ack")), f), "action"))


# Feature: hook-tamper-detection, Property 23: Record builders and export surfaces are content-free
@PROPS
@given(st.data(), cores)
def test_console_heartbeat_is_content_free(data, core):
    # **Validates: Requirements 10.1, 10.7**
    cl = _heartbeat_module()
    from interlockd import operator

    status = _status(data, core)
    built = list(_calls(data, core).values())
    now = datetime.now(UTC)
    cfg = cl.ConsoleConfig(url="https://console.invalid", key="k" * 32, key_id="0123456789ab",
                           daemon_id="dmn_" + "a" * 16, name="laptop", connected_at=now.isoformat())
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "home"
        spool = Spool(home / "spool", fsync=False)
        for rec in built + [_planted(r, core) for r in built]:
            spool.append(rec)
        hb = cl.build_heartbeat(cfg, spool_dir=spool.dir, home=home, since=now - timedelta(hours=1),
                                now=now + timedelta(seconds=1), agents=[], protection=status)

    assert core not in json.dumps(hb, ensure_ascii=False), hb
    p = hb["protection"]
    assert p["state"] in STATES
    assert set(p["homeReasons"]) <= HOME_REASONS | {"other"}
    for name, agent in p["agents"].items():
        assert re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", name)
        assert agent["state"] in STATES
        assert set(agent["reasons"]) <= HARNESS_REASONS | {"other"}
    assert p["operatorAction"] is None or p["operatorAction"] in operator.ACTIONS | {"other"}
    assert p["lastTamperAt"] == "none" or TS.match(p["lastTamperAt"].replace("+00:00", "Z"))
    assert isinstance(p["tamperCount"], int) and p["tamperCount"] >= 0
    assert hb["policyPinnedHash"] is None or HEX64.match(hb["policyPinnedHash"])
    if "policyOnDiskHash" in hb:
        assert hb["policyOnDiskHash"] is None or HEX64.match(hb["policyOnDiskHash"])
