"""Plugins: optional packages registered under the interlockd.plugins entry-point group."""

from __future__ import annotations

import sys
import types

import pytest

from interlockd import plugins
from interlockd.cli import main


class _Dist:
    def __init__(self, version):
        self.version = version


class _EP:
    def __init__(self, name, module=None, error=None, version="1.2.3"):
        self.name, self.value, self.dist = name, f"fake_{name}.plugin", _Dist(version)
        self._module, self._error = module, error

    def load(self):
        if self._error:
            raise self._error
        return self._module


@pytest.fixture
def fake(monkeypatch):
    eps: list[_EP] = []
    monkeypatch.setattr(plugins, "_entry_points", lambda: list(eps))
    plugins.reset()
    yield eps
    plugins.reset()


def _module(**hooks):
    m = types.ModuleType("fake_plugin")
    for k, v in hooks.items():
        setattr(m, k, v)
    return m


def test_no_plugins_changes_nothing(fake, capsys):
    assert plugins.load() == [] and plugins.start(object(), None) == [] and plugins.versions() == {}
    assert main(["plugins"]) == 0
    assert "no plugins installed" in capsys.readouterr().out


def test_plugin_adds_a_command_and_background_work(fake, capsys, tmp_path):
    events = []

    def register_cli(sub):
        p = sub.add_parser("hello", help="say hello")
        p.add_argument("--who", default="world")
        p.set_defaults(fn=lambda a: print(f"hello {a.who} from {plugins.settings_from_args(a).home.name}") or 0)

    def on_serve(daemon, home):
        events.append(("start", daemon, home))
        return lambda: events.append(("stop",))

    fake.append(_EP("greeter", _module(register_cli=register_cli, on_serve=on_serve), version="0.9"))
    assert main(["--home", str(tmp_path / "ihome"), "hello", "--who", "you"]) == 0
    assert capsys.readouterr().out.strip() == "hello you from ihome"
    stops = plugins.start("D", tmp_path)
    assert events == [("start", "D", tmp_path)]
    plugins.stop(stops)
    assert events[-1] == ("stop",)
    assert plugins.versions() == {"greeter": "0.9"}
    assert main(["plugins"]) == 0 and "greeter" in capsys.readouterr().out


def test_broken_plugins_are_isolated(fake, capsys, caplog):
    def boom(*_):
        raise RuntimeError("nope")

    fake.append(_EP("badimport", error=ImportError("missing dep")))
    fake.append(_EP("badhooks", _module(register_cli=boom, on_serve=boom)))
    fake.append(_EP("good", _module(on_serve=lambda d, h: None)))
    assert main(["plugins"]) == 1                          # listed with the failure
    out = capsys.readouterr().out
    assert "badimport" in out and "FAILED" in out and "good" in out
    assert plugins.start(object(), None) == []           # a raising on_serve is skipped, good returns no stop
    plugins.stop([boom])                                 # a raising stop doesn't propagate
    assert any("failed" in r.message for r in caplog.records)


def test_conflicting_command_is_skipped(fake, capsys):
    fake.append(_EP("clash", _module(register_cli=lambda sub: sub.add_parser("plugins"))))
    assert main(["plugins"]) == 1                         # the built-in still works; the plugin is marked failed
    assert "FAILED" in capsys.readouterr().out


def test_plugins_can_be_turned_off(fake, monkeypatch, capsys):
    fake.append(_EP("greeter", _module(on_serve=lambda d, h: pytest.fail("must not run"))))
    monkeypatch.setenv("INTERLOCK_PLUGINS", "0")
    plugins.reset()
    assert plugins.load() == [] and plugins.start(object(), None) == []
    assert main(["plugins"]) == 0 and "plugins are off" in capsys.readouterr().out


def test_real_entry_point_lookup_works():
    plugins.reset()
    assert isinstance(plugins.load(), list)               # whatever is installed, discovery never raises
    plugins.reset()
    assert "interlockd.plugins" == plugins.GROUP and sys.version_info >= (3, 12)
