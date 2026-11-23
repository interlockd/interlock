"""The optional `interlockd[watch]` notifier (Requirement 5.6): a `watchfiles` subscription wakes the hook watch early,
while the 10 s pass keeps running whatever the subscription does.

Most tests use a fake `watchfiles` module, so they run without the extra; the last one uses the real library and is
skipped when it is not installed.
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
import types

import pytest

from interlockd import watch
from interlockd.onboard import Manifest
from interlockd.watch import HookWatch, PollingNotifier, WatchfilesNotifier, make_notifier, watched_paths


@pytest.fixture
def fake_watchfiles(monkeypatch):
    """A stand-in for `watchfiles.watch`: yields the batches put on `mod.events` (filtered as the real one filters),
    raises an exception put there, and returns when the stop event is set."""
    mod = types.ModuleType("watchfiles")
    mod.events = queue.Queue()
    mod.calls = []

    def fake_watch(*paths, watch_filter=None, stop_event=None, **kw):
        mod.calls.append((paths, kw))
        while not stop_event.is_set():
            try:
                item = mod.events.get(timeout=0.01)
            except queue.Empty:
                continue
            if isinstance(item, BaseException):
                raise item
            yield {(c, p) for c, p in item if watch_filter is None or watch_filter(c, p)}

    mod.watch = fake_watch
    monkeypatch.setitem(sys.modules, "watchfiles", mod)
    return mod


def _wait(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return pred()


def test_make_notifier_is_opt_in_and_falls_back_without_the_extra(monkeypatch, tmp_path):
    monkeypatch.delenv(watch.WATCH_ENV, raising=False)
    assert isinstance(make_notifier(tmp_path), PollingNotifier)              # default: polling only
    monkeypatch.setitem(sys.modules, "watchfiles", None)                     # extra absent: import fails
    monkeypatch.setenv(watch.WATCH_ENV, "watchfiles")
    assert isinstance(make_notifier(tmp_path), PollingNotifier)
    with pytest.raises(ImportError):
        WatchfilesNotifier(list)


def test_make_notifier_uses_watchfiles_when_enabled(fake_watchfiles, monkeypatch, tmp_path):
    monkeypatch.setenv(watch.WATCH_ENV, "watchfiles")
    assert isinstance(make_notifier(tmp_path), WatchfilesNotifier)
    assert isinstance(make_notifier(tmp_path, enabled=False), PollingNotifier)
    monkeypatch.setenv(watch.WATCH_ENV, "polling")
    assert isinstance(make_notifier(tmp_path), PollingNotifier)


def test_watched_paths_cover_home_files_and_the_manifest_entries(settings, tmp_path):
    shim, hooks = tmp_path / "a" / "shim.sh", tmp_path / "b" / "settings.json"
    Manifest(created_at="2026-10-18T00:00:00Z", hooks=[{"harness": "claude-code", "file": str(hooks),
                                                         "marker": str(shim), "created": False}]).save(settings.home)
    names = {p.name for p in watched_paths(settings.home) if p.parent == settings.home}
    assert names == {"install-manifest.json", "token", "policy.yaml", "managed-policy.yaml", "identity"}
    assert {shim, hooks} <= set(watched_paths(settings.home))


def test_a_watched_change_wakes_the_loop_and_others_do_not(fake_watchfiles, daemon, settings, tmp_path):
    target, other = tmp_path / "token", tmp_path / "hook.log"
    n = WatchfilesNotifier(lambda: [target, tmp_path / "missing-dir" / "x"], debounce_ms=10)
    w = HookWatch(daemon, settings.home, interval=60.0, notifier=n)
    passes = []
    w.check = lambda: passes.append(1) or []
    w.start()
    try:
        assert len(passes) == 1                                              # the synchronous first pass
        assert _wait(lambda: fake_watchfiles.calls)
        [(dirs, kw)] = fake_watchfiles.calls
        assert dirs == (os.path.realpath(tmp_path),)                         # existing parent directories only
        assert kw["recursive"] is False and kw["debounce"] == 10
        fake_watchfiles.events.put({("modified", str(other))})
        time.sleep(0.2)
        assert len(passes) == 1 and not n.changed()                          # hook.log is not a watched file
        fake_watchfiles.events.put({("modified", str(target))})
        assert _wait(lambda: len(passes) == 2)                               # well before the 60 s interval
    finally:
        w.stop()
    assert n._thread is None


def test_the_subscription_follows_a_changed_set_of_paths(fake_watchfiles, tmp_path):
    (tmp_path / "new").mkdir()
    paths = [tmp_path / "token"]
    n = WatchfilesNotifier(lambda: list(paths), debounce_ms=10)
    woke = threading.Event()
    n.start(woke.set)
    try:
        assert _wait(lambda: len(fake_watchfiles.calls) == 1)
        paths.append(tmp_path / "new" / "shim.sh")                         # e.g. `interlock init` added a harness
        fake_watchfiles.events.put({("modified", str(tmp_path / "token"))})
        assert woke.wait(5) and n.changed()
        assert _wait(lambda: len(fake_watchfiles.calls) == 2)
        assert fake_watchfiles.calls[1][0] == tuple(sorted({os.path.realpath(tmp_path),
                                                            os.path.realpath(tmp_path / "new")}))
    finally:
        n.stop()


def test_a_watcher_error_ends_the_subscription_and_polling_continues(fake_watchfiles, daemon, settings, tmp_path,
                                                                     caplog):
    n = WatchfilesNotifier(lambda: [tmp_path / "token"], debounce_ms=10)
    w = HookWatch(daemon, settings.home, interval=0.02, notifier=n)
    passes = []
    w.check = lambda: passes.append(1) or []
    with caplog.at_level(logging.ERROR, logger="interlockd.watch"):
        w.start()
        try:
            assert _wait(lambda: fake_watchfiles.calls)
            fake_watchfiles.events.put(OSError("inotify watch limit reached"))
            assert _wait(lambda: n.failed)
            assert _wait(lambda: not n._thread.is_alive())
            seen = len(passes)
            assert _wait(lambda: len(passes) >= seen + 3)                    # the interval pass keeps running
        finally:
            w.stop()
    assert "file watcher failed" in caplog.text


def test_real_watchfiles_wakes_on_a_watched_file(tmp_path):
    pytest.importorskip("watchfiles")
    target, other = tmp_path / "token", tmp_path / "hook.log"
    target.write_text("a", encoding="utf-8")
    n = WatchfilesNotifier(lambda: [target], debounce_ms=50, refresh_ms=500)
    woke = threading.Event()
    n.start(woke.set)
    try:
        time.sleep(0.5)                                                      # let the subscription settle
        woke.clear()                                    # FSEvents may still report the file's creation: drain it
        n.changed()
        other.write_text("x", encoding="utf-8")
        assert not woke.wait(1.0)                                            # an unwatched entry: no wake
        for i in range(20):                                                  # retry: the first event may be early
            target.write_text(str(i), encoding="utf-8")
            if woke.wait(0.5):
                break
        assert woke.is_set() and n.changed() and not n.changed()
    finally:
        n.stop()
    assert not n.failed
