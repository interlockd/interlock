"""Argument rewrites: a safer form of a risky call, offered instead of a refusal. Opt-in by policy (`rewrites:`).

    git.force_with_lease   `git push --force` / `-f`  ->  `git push --force-with-lease`: the push still replaces the
                           remote branch, but only if nobody else pushed to it since you last fetched

A rewrite is proposed only for a single, simple command (no chaining, pipes, substitutions or heredocs), never for a
call the policy blocks (a force push to a protected branch stays refused), and only where the harness can apply
changed arguments (see render.REWRITE_HARNESSES). The user confirms the rewritten call: the verdict is an `ask`
carrying `updated_arguments` (only the changed keys).
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from typing import Any

from ..models import InterlockEvent

COMMAND_KEYS = ("command", "cmd")
_SIMPLE = re.compile(r"""^[^;&|<>`$()\n\\]*$""")        # nothing that chains, pipes, redirects or substitutes


def _command(event: InterlockEvent) -> tuple[str, str] | None:
    args = event.tool_call.arguments
    for k in COMMAND_KEYS:
        if isinstance(args.get(k), str) and args[k].strip():
            return k, args[k]
    return None


def _force_with_lease(event: InterlockEvent) -> tuple[dict[str, Any], str] | None:
    found = _command(event)
    if found is None:
        return None
    key, cmd = found
    if not _SIMPLE.match(cmd):
        return None
    try:
        words = shlex.split(cmd)
    except ValueError:
        return None
    if words[:2] != ["git", "push"] or any(w.startswith(("--force-with-lease", "--force-if-includes")) for w in words):
        return None
    if any(w.startswith("+") for w in words[2:]):
        return None                                       # a +refspec forces too; leave it to the rule
    force = [i for i, w in enumerate(words) if i >= 2 and w in ("--force", "-f")]
    if not force:
        return None
    new = [("--force-with-lease" if i in force else w) for i, w in enumerate(words)]
    rewritten = shlex.join(new)
    return {key: rewritten}, f"--force rewritten to --force-with-lease: {rewritten}"


REWRITES: dict[str, Callable[[InterlockEvent], tuple[dict[str, Any], str] | None]] = {
    "git.force_with_lease": _force_with_lease,
}


def propose(event: InterlockEvent, enabled: list[str]) -> tuple[dict[str, Any], str] | None:
    """(changed arguments, description) from the first enabled rewrite that applies, else None."""
    for rid in enabled:
        fn = REWRITES.get(rid)
        out = fn(event) if fn else None
        if out:
            return out
    return None
