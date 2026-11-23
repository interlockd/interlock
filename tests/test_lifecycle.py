"""Stop_Marker, clean-exit mark, startup audit and the daemon's start order (Requirement 3)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from interlockd import lifecycle
from interlockd.config import Settings
from interlockd.service import ServiceManager
from interlockd.store.spool import Spool

NOW = datetime(2026, 10, 17, 10, 0, 0, tzinfo=UTC)
POSIX = os.name == "posix"


def _kinds(recs):
    return [r["arguments"]["record"] for r in recs]


# ------------------------------------------------------------------------------------------------ Stop_Marker


@pytest.mark.parametrize("action", sorted(lifecycle.RESTARTING | lifecycle.STOPPING))
def test_marker_expiry_only_for_restarting_actions(tmp_path, action):
    doc = lifecycle.write_stop_marker(tmp_path, action, now=NOW)
    on_disk = lifecycle.read_stop_marker(tmp_path)
    assert on_disk == doc
    assert doc["action"] == action and doc["written_at"] == "2026-10-17T10:00:00Z" and doc["pid"] == os.getpid()
    if action in lifecycle.RESTARTING:
        assert doc["expires_at"] == "2026-10-17T10:02:00Z"
        assert doc["expires_epoch"] == int(NOW.timestamp()) + lifecycle.GRACE_S
    else:
        assert "expires_at" not in doc and "expires_epoch" not in doc
    if POSIX:
        assert stat.S_IMODE((tmp_path / lifecycle.STOP_MARKER).stat().st_mode) == 0o600


def test_marker_rejects_unknown_action(tmp_path):
    with pytest.raises(ValueError):
        lifecycle.write_stop_marker(tmp_path, "start")
    assert not (tmp_path / lifecycle.STOP_MARKER).exists()


def test_marker_write_failure_raises(tmp_path):
    home = tmp_path / "not-a-dir"
    home.write_text("x", encoding="utf-8")
    with pytest.raises(OSError):
        lifecycle.write_stop_marker(home, "stop")


def test_remove_marker_returns_it_and_removes_unreadable_ones(tmp_path):
    lifecycle.write_stop_marker(tmp_path, "stop", now=NOW)
    assert lifecycle.remove_stop_marker(tmp_path)["action"] == "stop"
    assert not (tmp_path / lifecycle.STOP_MARKER).exists()
    assert lifecycle.remove_stop_marker(tmp_path) is None

    p = tmp_path / lifecycle.STOP_MARKER
    p.write_text("{not json", encoding="utf-8")
    os.chmod(p, 0o600)
    errors = []
    assert lifecycle.remove_stop_marker(tmp_path, on_error=lambda f, r: errors.append(r)) is None
    assert not p.exists() and errors == ["state_unreadable:invalid_json"]


# ------------------------------------------------------------------------------------------------ ServiceManager


def _svc(home, calls):
    svc = ServiceManager(home, backend="process", runner=lambda cmd: pytest.fail(f"ran {cmd}"))
    svc.stop = lambda: calls.append(("stop", (home / lifecycle.STOP_MARKER).exists()))
    svc.restart = lambda: calls.append(("restart", (home / lifecycle.STOP_MARKER).exists()))
    return svc


def test_stop_for_and_restart_for_write_the_marker_first(tmp_path):
    calls = []
    svc = _svc(tmp_path, calls)
    svc.stop_for("stop")
    assert calls == [("stop", True)] and "expires_epoch" not in lifecycle.read_stop_marker(tmp_path)
    svc.restart_for("restart")
    assert calls[-1] == ("restart", True) and "expires_epoch" in lifecycle.read_stop_marker(tmp_path)


def test_stop_for_refuses_when_the_marker_cannot_be_written(tmp_path):
    home = tmp_path / "not-a-dir"
    home.write_text("x", encoding="utf-8")
    calls = []
    svc = _svc(home, calls)
    with pytest.raises(OSError):
        svc.stop_for("stop")
    with pytest.raises(OSError):
        svc.restart_for("restart")
    assert calls == []


# ------------------------------------------------------------------------------------------------ daemon.json


def test_daemon_json_is_one_line_the_sh_shim_can_parse(tmp_path):
    doc = lifecycle.daemon_json_doc("127.0.0.1:7391", socket=str(tmp_path / "interlockd.sock"), now=NOW)
    assert lifecycle.write_daemon_json(tmp_path, doc)
    text = (tmp_path / "daemon.json").read_text(encoding="utf-8")
    assert text.count("\n") == 1 and json.loads(text) == doc and doc["started_at"] == "2026-10-17T10:00:00Z"
    # the exact parsing both sh shims use
    script = ('read -r line < "$1/daemon.json"\n'
              'case "$line" in *\'"listen": "\'*) listen=${line#*\'"listen": "\'}; listen=${listen%%\\"*} ;; esac\n'
              'printf %s "$listen"\n')
    r = subprocess.run(["sh", "-c", script, "sh", str(tmp_path)], capture_output=True, text=True, check=True)
    assert r.stdout == "127.0.0.1:7391"


def test_read_daemon_json_absent_old_format_and_garbage(tmp_path):
    assert lifecycle.read_daemon_json(tmp_path) is None
    (tmp_path / "daemon.json").write_text(json.dumps({"listen": "127.0.0.1:7391", "pid": 7}), encoding="utf-8")
    assert lifecycle.read_daemon_json(tmp_path) == {"listen": "127.0.0.1:7391", "pid": 7}
    (tmp_path / "daemon.json").write_text("garbage", encoding="utf-8")
    assert lifecycle.read_daemon_json(tmp_path) == {}


def test_clean_exit_mark(tmp_path):
    lifecycle.write_daemon_json(tmp_path, lifecycle.daemon_json_doc("127.0.0.1:7391", now=NOW))
    assert lifecycle.mark_clean_exit(tmp_path, "sigterm", now=NOW + timedelta(minutes=5))
    doc = lifecycle.read_daemon_json(tmp_path)
    assert doc["exited_at"] == "2026-10-17T10:05:00Z" and doc["exit_reason"] == "sigterm"
    assert doc["listen"] == "127.0.0.1:7391" and doc["pid"] == os.getpid()


def test_clean_exit_mark_leaves_another_daemons_file_alone(tmp_path):
    lifecycle.write_daemon_json(tmp_path, lifecycle.daemon_json_doc("127.0.0.1:7391", pid=os.getpid() + 1))
    before = (tmp_path / "daemon.json").read_bytes()
    assert not lifecycle.mark_clean_exit(tmp_path, "sigterm")
    assert (tmp_path / "daemon.json").read_bytes() == before
    assert not lifecycle.mark_clean_exit(tmp_path / "absent", "sigterm")


# ------------------------------------------------------------------------------------------------ startup audit

CLEAN = {"listen": "127.0.0.1:7391", "pid": 41, "version": "0.1.8", "started_at": "2026-10-17T09:00:00Z",
         "exited_at": "2026-10-17T09:30:00Z", "exit_reason": "sigterm"}
UNCLEAN = {k: v for k, v in CLEAN.items() if k not in ("exited_at", "exit_reason")}


@pytest.mark.parametrize("previous", [None, CLEAN, UNCLEAN], ids=["first-start", "clean", "unclean"])
@pytest.mark.parametrize("marker", [None, {"action": "restart", "written_at": "2026-10-17T09:59:00Z"}],
                         ids=["no-marker", "marker"])
def test_startup_audit_matrix(tmp_path, previous, marker):
    recs = lifecycle.startup_audit(tmp_path, None, previous, marker, NOW, mode="enforce")
    started = [r for r in recs if r["arguments"]["record"] == "daemon_started"]
    assert len(started) == 1
    assert started[0]["arguments"]["marker_present"] is (marker is not None)
    assert started[0]["arguments"]["marker_action"] == (marker["action"] if marker else "")
    unexpected = [r for r in recs if r["arguments"]["record"] == "daemon_unexpected_exit"]
    if previous is UNCLEAN and marker is None:
        assert len(unexpected) == 1
        assert unexpected[0]["arguments"]["prev_pid"] == 41 and unexpected[0]["arguments"]["prev_version"] == "0.1.8"
        assert unexpected[0]["disposition"] == "flag"
    else:
        assert unexpected == []
    assert "calls_unjudged" not in _kinds(recs)          # no hook.log
    assert all(r["received_at"] == "2026-10-17T10:00:00Z" and r["mode"] == "enforce" for r in recs)


HOOK_LOG = """\
2026-10-17T09:20:00Z unjudged harness=claude-code tool=Bash kind=pre curl_rc=7 fail_mode=open
2026-10-17T09:31:00Z unjudged why=curl_rc_7 harness=claude-code tool=Bash kind=pre addr=x fail_mode=open
2026-10-17T09:32:00.250Z unjudged tool=Bash kind=pre reason=timeout fail_mode=open
2026-10-17T09:33:00Z tamper daemon_lost harness=kiro tool=? kind=pre addr=x status=- fail_mode=closed
2026-10-17T09:34:00Z tamper token_rejected harness=kiro tool=Bash kind=post addr=x status=401 fail_mode=closed
2026-10-17T09:35:00Z tamper daemon_identity harness=kiro tool=Bash kind=pre addr=x status=200 fail_mode=closed
2026-10-17T09:36:00Z inert: no token at /h/token
2026-10-17T09:37:00Z tamper something_else harness=kiro
not a log line
"""


def test_calls_unjudged_counts_lines_after_the_clean_exit(tmp_path):
    (tmp_path / "hook.log").write_text(HOOK_LOG, encoding="utf-8")
    recs = lifecycle.startup_audit(tmp_path, None, CLEAN, None, NOW)
    [summary] = [r["arguments"] for r in recs if r["arguments"]["record"] == "calls_unjudged"]
    assert summary["unjudged"] == 2                       # the 09:20 line is before the clean exit
    assert summary["tamper_daemon_lost"] == summary["tamper_token_rejected"] == 1
    assert summary["tamper_daemon_identity"] == 1
    assert summary["span_from"] == "2026-10-17T09:31:00Z" and summary["span_to"] == "2026-10-17T09:35:00Z"


def test_calls_unjudged_uses_start_time_without_a_clean_exit_and_skips_zero(tmp_path):
    (tmp_path / "hook.log").write_text(HOOK_LOG, encoding="utf-8")
    recs = lifecycle.startup_audit(tmp_path, None, UNCLEAN, None, NOW)
    [summary] = [r["arguments"] for r in recs if r["arguments"]["record"] == "calls_unjudged"]
    assert summary["unjudged"] == 3
    late = {**CLEAN, "exited_at": "2026-10-17T09:59:00Z"}
    assert "calls_unjudged" not in _kinds(lifecycle.startup_audit(tmp_path, None, late, None, NOW))


def test_summarize_hook_log_none_when_nothing_counts():
    assert lifecycle.summarize_hook_log(["2026-10-17T09:00:00Z inert: no token"], "2026-10-17T08:00:00Z") is None
    assert lifecycle.summarize_hook_log(HOOK_LOG.splitlines(), "not a time") is None


# ------------------------------------------------------------------------------------------------ cmd_serve


def test_serve_start_order_and_clean_exit(tmp_path, monkeypatch):
    from interlockd import cli, watch

    home = tmp_path
    (home / "hook.log").write_text(HOOK_LOG, encoding="utf-8")
    (home / "daemon.json").write_text(json.dumps(UNCLEAN), encoding="utf-8")   # pre-0.2.0 style, 0644
    lifecycle.write_stop_marker(home, "restart")
    spool_dir = Settings.load(home).spool_dir
    handlers, seen = {}, {}

    class FakeWatch:
        def __init__(self, daemon, home_, **kwargs):
            pass

        def start(self):
            seen["watch_started_with_marker"] = (home / lifecycle.STOP_MARKER).exists()
            seen["daemon_json_at_watch"] = lifecycle.read_daemon_json(home)
            return self

        def stop(self):
            pass

    class FakeServer:
        def __init__(self, daemon, token, host, port, *, unix_socket=None, identity=None):
            seen["marker_at_bind"] = (home / lifecycle.STOP_MARKER).exists()

        def serve_forever(self):
            seen["marker_at_serve"] = (home / lifecycle.STOP_MARKER).exists()
            seen["daemon_json_at_serve"] = lifecycle.read_daemon_json(home)
            seen["records_at_serve"] = _kinds(Spool(spool_dir).iter_records(reverse=False))
            handlers[cli.signal.SIGTERM](cli.signal.SIGTERM, None)

        def shutdown(self):
            pass

    monkeypatch.setattr(cli, "ApiServer", FakeServer)
    monkeypatch.setattr(watch, "HookWatch", FakeWatch)
    monkeypatch.setattr(cli.signal, "signal", lambda sig, h: handlers.__setitem__(sig, h))
    assert cli.cmd_serve(SimpleNamespace(home=str(home), mode=None, listen="127.0.0.1:0")) == 0

    assert seen["marker_at_bind"] is True                    # removed after the bind, before serving
    assert seen["watch_started_with_marker"] is False and seen["marker_at_serve"] is False
    at_watch = seen["daemon_json_at_watch"]
    assert at_watch["pid"] == os.getpid() and "started_at" in at_watch and "exited_at" not in at_watch
    recs = seen["records_at_serve"]
    assert "daemon_started" in recs and "calls_unjudged" in recs
    assert "daemon_unexpected_exit" not in recs              # a marker was present
    started = next(r for r in Spool(spool_dir).iter_records() if r["arguments"].get("record") == "daemon_started")
    assert started["arguments"]["marker_present"] is True and started["arguments"]["marker_action"] == "restart"

    after = lifecycle.read_daemon_json(home)
    assert after["exit_reason"] == "sigterm" and after["exited_at"] and after["pid"] == os.getpid()


def test_serve_records_unexpected_exit_without_marker(tmp_path, monkeypatch):
    from interlockd import cli, watch

    (tmp_path / "daemon.json").write_text(json.dumps(UNCLEAN), encoding="utf-8")
    spool_dir = Settings.load(tmp_path).spool_dir

    class FakeServer:
        def __init__(self, *a, **k):
            pass

        def serve_forever(self):
            raise KeyboardInterrupt

        def shutdown(self):
            pass

    monkeypatch.setattr(cli, "ApiServer", FakeServer)
    monkeypatch.setattr(watch, "HookWatch", lambda d, h, **kw: SimpleNamespace(start=lambda: SimpleNamespace(stop=lambda: None)))
    monkeypatch.setattr(cli.signal, "signal", lambda sig, h: None)
    assert cli.cmd_serve(SimpleNamespace(home=str(tmp_path), mode=None, listen="127.0.0.1:0")) == 0
    recs = list(Spool(spool_dir).iter_records(reverse=False))
    [ux] = [r for r in recs if r["arguments"].get("record") == "daemon_unexpected_exit"]
    assert ux["arguments"]["prev_pid"] == 41
    assert lifecycle.read_daemon_json(tmp_path)["exit_reason"] == "sigint"
    assert Spool(spool_dir).verify()["ok"]
