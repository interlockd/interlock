"""Plugins: optional packages that extend the `interlock` CLI and the daemon.

A plugin is any installed distribution that registers a module under the `interlockd.plugins` entry-point group:

    [project.entry-points."interlockd.plugins"]
    myplugin = "my_package.plugin"

The module may define either or both hooks:

    def register_cli(subparsers): ...          # add `interlock <command>` subcommands (argparse subparsers)
    def on_serve(daemon, home): ...            # `interlock serve` started; begin background work, never block.
                                               # Return a callable to stop it on shutdown, or None.

Plugins can't change a decision: they run beside the gate, never inside it. A plugin that fails to import or raises
in a hook logs one warning and is skipped; it never stops the CLI or the daemon. `INTERLOCK_PLUGINS=0` turns all
plugins off. `interlock plugins` lists what's installed.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from types import ModuleType
from typing import Any

GROUP = "interlockd.plugins"
log = logging.getLogger("interlockd.plugins")


@dataclass
class Plugin:
    name: str
    target: str                       # "package.module" from the entry point
    version: str                      # the distribution's version, or "?"
    module: ModuleType | None = field(default=None, repr=False)
    error: str = ""                   # why it didn't load


def enabled() -> bool:
    return os.environ.get("INTERLOCK_PLUGINS", "1") != "0"


def _entry_points():                  # indirection so tests can install fake entry points
    return entry_points(group=GROUP)


_loaded: list[Plugin] | None = None


def load() -> list[Plugin]:
    """Every registered plugin, imported once per process. Failed ones carry `error` and no module."""
    global _loaded
    if _loaded is not None:
        return _loaded
    _loaded = []
    if not enabled():
        return _loaded
    for ep in sorted(_entry_points(), key=lambda e: e.name):
        dist = getattr(ep, "dist", None)
        p = Plugin(name=ep.name, target=ep.value, version=getattr(dist, "version", None) or "?")
        try:
            p.module = ep.load()
        except Exception as e:  # noqa: BLE001 - a broken plugin is skipped, never fatal
            p.error = f"{type(e).__name__}: {e}"
            log.warning("plugin %s (%s) failed to load and is skipped: %s", p.name, p.target, p.error)
        _loaded.append(p)
    return _loaded


def reset() -> None:
    """Forget loaded plugins (tests)."""
    global _loaded
    _loaded = None


def active() -> list[Plugin]:
    return [p for p in load() if p.module is not None]


def versions() -> dict[str, str]:
    """{plugin name: version} for the plugins that loaded, e.g. for status output."""
    return {p.name: p.version for p in active()}


def _call(p: Plugin, hook: str, *args: Any) -> Any:
    fn = getattr(p.module, hook, None)
    if not callable(fn):
        return None
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001 - isolate the plugin
        p.error = f"{hook}: {type(e).__name__}: {e}"
        log.warning("plugin %s failed in %s and is skipped: %s", p.name, hook, e)
        return None


def register_cli(subparsers: Any) -> None:
    for p in active():
        _call(p, "register_cli", subparsers)


def start(daemon: Any, home: Path) -> list[Callable[[], Any]]:
    """Run every plugin's on_serve; returns the stop callables they handed back."""
    stops = []
    for p in active():
        stop = _call(p, "on_serve", daemon, home)
        if callable(stop):
            stops.append(stop)
    return stops


def stop(stops: list[Callable[[], Any]]) -> None:
    for fn in stops:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - shutdown continues regardless
            log.warning("a plugin failed to stop cleanly: %s", e)


def settings_from_args(args: Any):
    """The daemon Settings for a parsed `interlock` command line (honours --home / $INTERLOCK_HOME), for plugin
    commands."""
    from .cli import _settings

    return _settings(args)
