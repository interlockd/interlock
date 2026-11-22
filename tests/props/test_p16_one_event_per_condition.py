"""Property 16: One event per distinct observed condition (Requirements 5.9, 8.10).

Each example builds a fresh Home and daemon wired as `interlock serve` wires them (`cli.attach_integrity`, a token, an
identity file, one claude-code shim with its hook config and install manifest), runs one intact `HookWatch.check()`
pass, then applies a random sequence of steps, each one condition change followed by 1-3 passes:

- the hook config edited so it no longer runs the shim (two removal variants), or restored to its original bytes;
- the token content set to one of a few values (with repeats, including the original);
- the token mode set (POSIX only): a widened mode, which the pass restores to 0600, or an owner-only mode;
- the identity file deleted or altered, which the pass rewrites from memory;
- the shim edited, which the pass rewrites from the installed package (5.8);
- no change.

A model computes, per monitored item `(subject, reason)`, the fingerprint the item has on each pass, from what is on
disk rather than from what the watch happens to look at. A Tamper_Event (a record with `arguments.tamper_kind`) is
expected exactly where the fingerprint differs from the previous pass's and is a problem:

- `(claude-code, hook_removed)`: "removed" while the config lacks the shim, else intact.
- `(home, token_modified)`: the token digest while it differs from the pinned one, else intact. A widened mode does
  not change the digest, so it changes nothing for this item.
- `(home, token_permissions)`, `(home, identity_missing)`, `(claude-code, shim_modified)`: the pass that finds the
  condition also restores it, so the item is a problem on that one pass and intact on the next; each step that widens,
  deletes, alters or edits is one new condition and one event. This is how the shim auto-repair path is modelled.

Also checked: the hook config's bytes are never modified by a pass (5.9), and every Tamper_Event in the spool is one
the passes returned.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from interlockd import identity
from interlockd.auth import load_or_create_token
from interlockd.cli import CLAUDE_SHIM_SRC, attach_integrity
from interlockd.config import Settings
from interlockd.onboard import Manifest
from interlockd.pipeline import Daemon
from interlockd.store.memory import MemoryRepository
from interlockd.store.spool import Spool
from interlockd.watch import HookWatch

from .strategies import PROPS, identities

HARNESS = "claude-code"
HOME = "home"
POSIX = sys.platform != "win32"
IDENTITY = identity.derive("t", b"\x00" * 16)

TOKEN_VALUES = ("original", "tok-A\n", "tok-B\n", "tok-C")        # "original" = the token the Home was created with
HOOK_REMOVED = ('{}', '{"hooks": {}}  \n')
SHIM_EDITS = ("\nexit 0\n", "\n# local edit\n", "\necho hi >&2\n")


@dataclass(frozen=True)
class Step:
    op: str            # hook_remove | hook_restore | token_set | token_mode | identity_delete | identity_alter
    #                    | shim_edit | noop
    arg: object
    passes: int


def _steps() -> st.SearchStrategy[Step]:
    ops = [
        st.tuples(st.just("hook_remove"), st.sampled_from(HOOK_REMOVED)),
        st.tuples(st.just("hook_restore"), st.none()),
        st.tuples(st.just("token_set"), st.sampled_from(TOKEN_VALUES)),
        st.tuples(st.just("identity_delete"), st.none()),
        st.tuples(st.just("identity_alter"),
                  st.one_of(identities(), st.sampled_from(("", "garbage\n", "0" * 31))).filter(
                      lambda v: v.strip() != IDENTITY)),
        st.tuples(st.just("shim_edit"), st.sampled_from(SHIM_EDITS)),
        st.tuples(st.just("noop"), st.none()),
    ]
    if POSIX:
        widened = st.integers(0, 0o777).filter(lambda m: m & 0o077)
        ops.append(st.tuples(st.just("token_mode"), st.one_of(widened, st.sampled_from((0o600, 0o700)))))
    return st.builds(lambda t, n: Step(t[0], t[1], n), st.one_of(ops), st.integers(1, 3))


# ---- one Home ------------------------------------------------------------------------------------------------------

def _home(root: Path):
    home = root / "interlock"
    home.mkdir()
    settings = Settings(home=home)
    settings.workspace_roots = []
    daemon = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository())
    shim = home / "adapters" / HARNESS / "interlock-hook.sh"
    shim.parent.mkdir(parents=True)
    shim.write_text(CLAUDE_SHIM_SRC.read_text(encoding="utf-8").replace("__HARNESS__", HARNESS), encoding="utf-8")
    hooks = root / "agent" / "settings.json"
    hooks.parent.mkdir()
    hooks.write_text(f'{{"hooks": {{"PreToolUse": [{{"hooks": [{{"command": "sh {shim}"}}]}}]}}}}', encoding="utf-8")
    Manifest(created_at="2026-10-18T00:00:00Z",
             hooks=[{"harness": HARNESS, "file": str(hooks), "marker": str(shim), "created": False}]).save(home)
    load_or_create_token(settings.token_path)
    attach_integrity(daemon, home, None)
    daemon.identity = IDENTITY
    identity.write(home, IDENTITY)
    return settings, daemon, hooks, shim


def _events(recs: list[dict]) -> Counter:
    """Tamper_Events by (subject, reason): records carrying a tamper kind."""
    out: Counter = Counter()
    for r in recs:
        kind = r.get("arguments", {}).get("tamper_kind")
        if kind:
            out[(r["findings"][0]["subject"], kind)] += 1
    return out


# Feature: hook-tamper-detection, Property 16: One event per distinct observed condition
@PROPS
@given(steps=st.lists(_steps(), min_size=1, max_size=12))
def test_one_event_per_distinct_observed_condition(steps: list[Step]) -> None:
    """**Validates: Requirements 5.9, 8.10**"""
    with tempfile.TemporaryDirectory() as d:
        settings, daemon, hooks, shim = _home(Path(d))
        token_path = settings.token_path
        original_token = token_path.read_bytes()
        original_hooks = hooks.read_bytes()
        w = HookWatch(daemon, settings.home)
        assert w.check() == []                                         # intact at start

        # model state: what is on disk, and the conditions a pass restores itself
        hook_text = original_hooks
        token_bytes = original_token
        pending: set[tuple[str, str]] = set()                          # one-pass conditions awaiting the next pass
        prev: dict[tuple[str, str], str] = {}                          # last pass's fingerprint ("" = intact)
        returned: Counter = Counter()

        for i, step in enumerate(steps):
            if step.op == "hook_remove":
                hook_text = str(step.arg).encode("utf-8")
                hooks.write_bytes(hook_text)
            elif step.op == "hook_restore":
                hook_text = original_hooks
                hooks.write_bytes(hook_text)
            elif step.op == "token_set":
                token_bytes = original_token if step.arg == "original" else str(step.arg).encode("utf-8")
                token_path.write_bytes(token_bytes)                    # keeps the file's mode
            elif step.op == "token_mode":
                mode = int(step.arg)                                   # type: ignore[call-overload]
                os.chmod(token_path, mode)
                if mode & 0o077:
                    pending.add((HOME, "token_permissions"))
            elif step.op == "identity_delete":
                (settings.home / identity.FILE).unlink()
                pending.add((HOME, "identity_missing"))
            elif step.op == "identity_alter":
                (settings.home / identity.FILE).write_text(str(step.arg), encoding="utf-8")
                pending.add((HOME, "identity_missing"))
            elif step.op == "shim_edit":
                shim.write_text(shim.read_text(encoding="utf-8") + str(step.arg), encoding="utf-8")
                pending.add((HARNESS, "shim_modified"))

            for n in range(step.passes):
                fp = {
                    (HARNESS, "hook_removed"): "" if hook_text == original_hooks else "removed",
                    (HOME, "token_modified"): ("" if token_bytes == original_token
                                               else hashlib.sha256(token_bytes).hexdigest()),
                }
                for k in pending:
                    fp[k] = f"step{i}"
                pending = set()
                expected = Counter({k: 1 for k, v in fp.items() if v and v != prev.get(k, "")})
                prev = fp

                got = w.check()
                ctx = (i, n, step, steps)
                assert _events(got) == expected, ctx
                returned += _events(got)
                assert hooks.read_bytes() == hook_text, ctx                # never edited by the watch (5.9)

        assert _events(list(daemon.spool.iter_records())) == returned   # nothing recorded outside the passes
        assert daemon.spool.verify()["ok"]
