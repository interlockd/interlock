"""Property 14: Policy key diff and once-per-digest recording (Requirements 7.4, 7.9).

- For any two YAML mappings A (pinned) and B (on disk), `pin.top_level_diff(A, B)` returns
  added = keys(B) - keys(A), removed = keys(A) - keys(B), changed = {k in both : A[k] != B[k]} and no value text.
  An absent on-disk file compares as an empty mapping; an on-disk file that is not a YAML mapping is `unparseable`
  with empty key lists. The same key lists reach the `control.policy_modified` record written by
  `PolicyGuard.check`.
- For any sequence of on-disk documents (with repeats, the pinned document and an absent file among them) and
  1-3 `check()` calls after each write, while no Operator_Action explains a change: exactly one
  `control.policy_modified` record is written per run of consecutive identical on-disk digests that differ from
  the pin, none while the file equals the pin, and the pin never moves.
- A marker string placed in values and nested keys never appears in a diff or in any spool record.

`changed` uses Python equality on the parsed values, so `true` vs `1` (True == 1) is not a changed key; the model
uses the same comparison. Each example runs in a fresh temporary Home.
"""

from __future__ import annotations

import hashlib
import json
import string
import tempfile
from pathlib import Path

import yaml
from hypothesis import given
from hypothesis import strategies as st

from interlockd.integrity import Baseline
from interlockd.operator import OperatorActions
from interlockd.policy import pin as pp
from interlockd.protection import HOME, ProtectionState
from interlockd.store.spool import Spool

from .strategies import PROPS, yaml_scalars

# Upper case and digits: never produced by the top-level key alphabet, the Home path or a digest.
MARKER = "MARKER5F1C"

_KEYS = st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=12)
_SCALARS = st.one_of(yaml_scalars(), st.just(MARKER),
                     st.builds(lambda a, b: f"{a}{MARKER}{b}", st.text(alphabet=string.ascii_lowercase, max_size=4),
                               st.text(alphabet=string.ascii_lowercase, max_size=4)))


def _extend(children: st.SearchStrategy) -> st.SearchStrategy:
    return st.one_of(st.lists(children, max_size=3),
                     st.dictionaries(st.one_of(_KEYS, st.just(MARKER)), children, max_size=3))


_VALUES = st.recursive(_SCALARS, _extend, max_leaves=12)
_MAPPINGS = st.dictionaries(_KEYS, _VALUES, max_size=6)


def _dump(doc: dict) -> bytes:
    return yaml.safe_dump(doc, sort_keys=False).encode("utf-8")


def _sha(data: bytes | None) -> str:
    return hashlib.sha256(data).hexdigest() if data is not None else ""


@st.composite
def _pairs(draw) -> tuple[dict, tuple[str, object]]:
    """(A, (variant, on-disk)): B keeps a subset of A's keys (each value kept or redrawn) plus new keys; or the
    on-disk file is absent, a YAML sequence, or broken YAML."""
    a = draw(_MAPPINGS)
    keep = draw(st.sets(st.sampled_from(sorted(a)))) if a else set()
    b = {k: draw(st.one_of(st.just(a[k]), _VALUES)) for k in sorted(keep)}
    b.update(draw(st.dictionaries(_KEYS.filter(lambda k: k not in a), _VALUES, max_size=3)))
    variant = draw(st.sampled_from(("mapping", "mapping", "mapping", "absent", "sequence", "broken")))
    if variant == "mapping":
        return a, ("mapping", b)
    if variant == "sequence":
        return a, ("sequence", draw(st.lists(_VALUES, max_size=3)))
    return a, (variant, None)


def _on_disk_bytes(variant: str, value: object) -> bytes | None:
    if variant == "mapping":
        return _dump(value)                                   # type: ignore[arg-type]
    if variant == "sequence":
        return yaml.safe_dump(value).encode("utf-8")
    if variant == "broken":
        return f"mode: [unclosed {MARKER}\n".encode()
    return None


def _model(a: dict, variant: str, b: object) -> dict:
    if variant in ("sequence", "broken"):
        return {"added": [], "removed": [], "changed": [], "unparseable": True}
    b = b if variant == "mapping" else {}
    assert isinstance(b, dict)
    return {"added": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)),
            "changed": sorted(k for k in set(a) & set(b) if a[k] != b[k]), "unparseable": False}


class _Home:
    """A fresh Home with `pinned` as the pinned policy, plus spool, protection state, operator actions and guard."""

    def __init__(self, root: Path, pinned: bytes):
        self.home = root
        (root / "policy.yaml").write_bytes(pinned)
        self.spool = Spool(root / "spool", fsync=False)
        self.baseline = Baseline(created_at="2026-10-17T09:00:00Z", version="0")
        self.baseline.save(root)
        self.protection = ProtectionState(root, self.spool, None, lambda: "enforce", harnesses=list)
        self.guard = pp.PolicyGuard(root, lambda: self.baseline, self.protection, OperatorActions(self.spool),
                                    spool=self.spool)
        self.pinned_sha = pp.pin(root, "policy", baseline=self.baseline)

    def write(self, data: bytes | None) -> None:
        path = self.home / "policy.yaml"
        if data is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(data)

    def records(self) -> list[dict]:
        return list(self.spool.iter_records(reverse=False))

    def modified(self) -> list[dict]:
        return [r for r in self.records()
                if r.get("kind") == "control" and r["arguments"]["record"] == "policy_modified"]

    def reasons(self) -> set[str]:
        return {r.reason for r in self.protection.reasons() if r.subject == HOME}


# Feature: hook-tamper-detection, Property 14: Policy key diff and once-per-digest recording
@PROPS
@given(_pairs())
def test_top_level_diff_matches_the_key_model_and_carries_no_values(pair) -> None:
    a, (variant, b) = pair
    pinned = _dump(a)
    on_disk = _on_disk_bytes(variant, b)
    assert yaml.safe_load(pinned) == a                         # generator sanity: YAML round trip
    if variant == "mapping":
        assert yaml.safe_load(on_disk) == b                    # type: ignore[arg-type]

    expected = _model(a, variant, b)
    diff = pp.top_level_diff(pinned, on_disk)
    assert diff == expected
    assert MARKER not in json.dumps(diff)

    with tempfile.TemporaryDirectory() as tmp:
        env = _Home(Path(tmp), pinned)
        env.write(on_disk)
        env.guard.check()
        mods = env.modified()
        if _sha(on_disk) == env.pinned_sha:
            assert mods == []
        else:
            assert len(mods) == 1
            args = mods[0]["arguments"]
            assert (args["pinned_sha256"], args["on_disk_sha256"]) == (env.pinned_sha, _sha(on_disk))
            assert {k: args[k] for k in expected} == expected
            assert env.reasons() == {"policy_modified"}
        for rec in env.records():
            assert MARKER not in json.dumps(rec)


@st.composite
def _sequences(draw) -> tuple[dict, list[dict | None], list[tuple[int, int]]]:
    """(pinned, pool, steps): step (i, n) writes document i (0 = the pinned document, None in the pool = delete the
    file) and then runs n checks."""
    pinned = draw(_MAPPINGS)
    pool = draw(st.lists(st.one_of(_MAPPINGS, st.none()), min_size=1, max_size=4))
    steps = draw(st.lists(st.tuples(st.integers(0, len(pool)), st.integers(1, 3)), min_size=1, max_size=10))
    return pinned, pool, steps


# Feature: hook-tamper-detection, Property 14: Policy key diff and once-per-digest recording
@PROPS
@given(_sequences())
def test_policy_modified_is_recorded_once_per_consecutive_unpinned_digest(seq) -> None:
    pinned_doc, pool, steps = seq
    docs: list[bytes | None] = [_dump(pinned_doc)] + [None if d is None else _dump(d) for d in pool]

    with tempfile.TemporaryDirectory() as tmp:
        env = _Home(Path(tmp), docs[0])                        # type: ignore[arg-type]
        previous = env.pinned_sha
        expected: list[str] = []
        for index, checks in steps:
            data = docs[index]
            digest = _sha(data)
            if digest != env.pinned_sha and digest != previous:
                expected.append(digest)
            previous = digest
            env.write(data)
            for _ in range(checks):
                env.guard.check()
            assert [r["arguments"]["on_disk_sha256"] for r in env.modified()] == expected
            assert env.reasons() == ({"policy_modified"} if digest != env.pinned_sha else set())
            assert env.baseline.policy_file_sha256 == env.pinned_sha          # an unexplained change never pins
        assert all(r["arguments"]["pinned_sha256"] == env.pinned_sha for r in env.modified())
        for rec in env.records():
            assert MARKER not in json.dumps(rec)
