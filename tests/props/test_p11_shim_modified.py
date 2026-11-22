"""Property 11: Shim modification detection and single event (Requirements 5.1, 5.3).

Each example installs a fresh Home (a sh-family shim from `cli.CLAUDE_SHIM_SRC`, its hook config, the install
manifest and an Integrity_Baseline pinned from disk), applies one random edit to the shim and then sends N hook
requests through a real `integrity.Verifier`.

- An edit off the `VERSION="..."` line (insert, delete or replace 1-8 bytes anywhere outside the line's content) is
  reported as `shim_modified` on every request, with the pinned and observed digests and the shim path.
- An edit confined to the version line (a new version value) is reported intact on every request.

The request loop models the hot path as the daemon will run it once task 6.1 wires the Verifier result into the
pipeline (`pipeline.decide` accepts `integrity=` but does not act on it yet): verify, and on a problem build the
`records.tamper_event` and call `ProtectionState.add_reason`; the Tamper_Event is appended to the spool only when
`add_reason` reports a new reason. Over N requests exactly one Tamper_Event is recorded, the harness is
`compromised` with `shim_modified`, and exactly one `control.protection_state` record exists.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from interlockd import records
from interlockd.cli import CLAUDE_SHIM_SRC
from interlockd.integrity import Baseline, Verifier
from interlockd.onboard import Manifest
from interlockd.protection import ProtectionState
from interlockd.store.spool import Spool

from .strategies import PROPS

AT = "2026-10-17T10:00:00Z"
SH_HARNESSES = ("claude-code", "codex", "cursor", "gemini-cli", "copilot-cli", "windsurf", "antigravity")
_VERSION_VALUE = re.compile(rb'^VERSION="([^"\r\n]*)"$', re.MULTILINE)


def _shim_bytes(harness: str) -> bytes:
    return CLAUDE_SHIM_SRC.read_text(encoding="utf-8").replace("__HARNESS__", harness).encode("utf-8")


def _version_span(data: bytes) -> tuple[int, int, int, int]:
    """(line_start, line_end, value_start, value_end) of the single version line; line_end excludes the newline."""
    found = list(_VERSION_VALUE.finditer(data))
    assert len(found) == 1, "the packaged shim has exactly one version line"
    m = found[0]
    return m.start(), m.end(), m.start(1), m.end(1)


# --- edits --------------------------------------------------------------------------------------------------------

# Inserted / replacement bytes never contain CR: the Verifier compares with universal newlines (a CRLF shim is
# intact by design), so a CR edit is not a content change.
_EDIT_BYTES = st.binary(min_size=1, max_size=8).filter(lambda b: b"\r" not in b)


@dataclass(frozen=True)
class OffLineEdit:
    op: str          # "insert" | "delete" | "replace"
    where: float     # relative position in the bytes outside the version line's content
    length: int      # bytes deleted / replaced
    data: bytes      # bytes inserted / written

    def apply(self, original: bytes) -> bytes:
        line_start, line_end, _, _ = _version_span(original)
        if self.op == "insert":
            # an index i inserts before byte i; indexes line_start..line_end would land inside the version line
            slots = [*range(line_start), *range(line_end + 1, len(original) + 1)]
            i = slots[min(int(self.where * len(slots)), len(slots) - 1)]
            return original[:i] + self.data + original[i:]
        # delete / replace a run that does not overlap the version line's content (its newline may go)
        starts = [*range(line_start - self.length + 1), *range(line_end, len(original) - self.length + 1)]
        i = starts[min(int(self.where * len(starts)), len(starts) - 1)]
        if self.op == "delete":
            return original[:i] + original[i + self.length:]
        old = original[i:i + self.length]
        new = bytes(_differing(b, o) for b, o in zip((self.data * self.length)[:self.length], old, strict=True))
        return original[:i] + new + original[i + self.length:]


def _differing(b: int, o: int) -> int:
    """`b`, or another non-CR byte when `b` equals the original byte `o` (so every replaced byte changes)."""
    if b != o:
        return b
    return next(c for c in (o ^ 0x01, o ^ 0x02) if c != 0x0D)


def off_line_edits() -> st.SearchStrategy[OffLineEdit]:
    return st.builds(OffLineEdit, st.sampled_from(("insert", "delete", "replace")),
                     st.floats(0, 1, exclude_max=True), st.integers(1, 8), _EDIT_BYTES)


def version_values() -> st.SearchStrategy[bytes]:
    """New version values: anything a version line can hold (no quote, no line break)."""
    return st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters='"\r\n'),
                   max_size=24).map(lambda s: s.encode("utf-8"))


def on_line_edit(original: bytes, value: bytes) -> bytes:
    _, _, v0, v1 = _version_span(original)
    return original[:v0] + value + original[v1:]


# --- one install and the modelled request loop --------------------------------------------------------------------

class Otel:
    def __init__(self) -> None:
        self.recs: list[dict] = []

    def submit(self, rec: dict) -> None:
        self.recs.append(rec)


def _install(home: Path, harness: str) -> tuple[Path, Verifier]:
    shim = home / "adapters" / harness / "interlock-hook.sh"
    shim.parent.mkdir(parents=True)
    shim.write_bytes(_shim_bytes(harness))
    cfg = home / "agent-settings.json"
    cfg.write_text(f'{{"hooks": {{"PreToolUse": [{{"hooks": [{{"command": "sh {shim}"}}]}}]}}}}', encoding="utf-8")
    man = Manifest(hooks=[{"harness": harness, "file": str(cfg), "marker": str(shim), "created": False}])
    man.save(home)
    (home / "token").write_text("t0ken-value\n", encoding="utf-8")
    os.chmod(home / "token", 0o600)
    base = Baseline.from_disk(home, man)
    assert base.save(home)
    return shim, Verifier(home, lambda: man, lambda: base)


def _requests(home: Path, harness: str, verifier: Verifier, n: int, report_shim: str | None):
    """N hook requests: verify, then (task 6.1's wiring, modelled here) record a Tamper_Event when the reason is new."""
    spool = Spool(home / "spool", fsync=False)
    otel = Otel()
    ps = ProtectionState(home, spool, otel, lambda: "enforce", harnesses=lambda: [harness])
    results = []
    for _ in range(n):
        v = verifier.verify(harness, report_shim)
        results.append(v)
        if v.problem and v.problem != "no_baseline":
            ev = records.tamper_event(v.problem, harness, v.path, v.expected_sha256, v.observed_sha256,
                                      detector="verifier", mode="enforce", at=AT)
            if ps.add_reason(harness, v.problem, ev["event_id"], AT):
                spool.append(ev)
    recs = list(spool.iter_records(reverse=False))
    tamper = [r for r in recs if r.get("arguments", {}).get("record") == "tamper_event"]
    changes = [r for r in recs if r.get("arguments", {}).get("record") == "protection_state"]
    return results, ps, tamper, changes, spool


# Feature: hook-tamper-detection, Property 11: Shim modification detection and single event
@PROPS
@given(harness=st.sampled_from(SH_HARNESSES), edit=off_line_edits(), n=st.integers(1, 20),
       report=st.booleans())
def test_off_version_line_edit_is_shim_modified_once(harness: str, edit: OffLineEdit, n: int, report: bool) -> None:
    """**Validates: Requirements 5.1, 5.3**"""
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        shim, verifier = _install(home, harness)
        original = shim.read_bytes()
        pinned = hashlib.sha256(original).hexdigest()
        assert verifier.verify(harness).problem == ""                     # intact before the edit
        edited = edit.apply(original)
        assert edited != original
        shim.write_bytes(edited)
        observed = hashlib.sha256(edited).hexdigest()

        results, ps, tamper, changes, spool = _requests(home, harness, verifier, n, str(shim) if report else None)

        for v in results:                                                  # every request, not only the first
            assert v.problem == "shim_modified", (edit, v)
            assert (v.expected_sha256, v.observed_sha256, v.path) == (pinned, observed, str(shim))
        assert ps.harness_state(harness) == "compromised"
        assert {(r.subject, r.reason) for r in ps.reasons()} == {(harness, "shim_modified")}
        assert len(tamper) == 1
        args = tamper[0]["arguments"]
        assert (args["tamper_kind"], args["harness"], args["path"]) == ("shim_modified", harness, str(shim))
        assert (args["expected_sha256"], args["observed_sha256"]) == (pinned, observed)
        assert tamper[0]["disposition"] == "flag"
        assert tamper[0]["findings"][0]["category"] == "control.hook_tamper"
        assert len(changes) == 1
        assert spool.verify()["ok"]


# Feature: hook-tamper-detection, Property 11: Shim modification detection and single event
@PROPS
@given(harness=st.sampled_from(SH_HARNESSES), value=version_values(), n=st.integers(1, 20), report=st.booleans())
def test_version_line_only_edit_is_intact(harness: str, value: bytes, n: int, report: bool) -> None:
    """**Validates: Requirements 5.1, 5.3**"""
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        shim, verifier = _install(home, harness)
        shim.write_bytes(on_line_edit(shim.read_bytes(), value))

        results, ps, tamper, changes, _ = _requests(home, harness, verifier, n, str(shim) if report else None)

        assert [v.problem for v in results] == [""] * n, value
        assert ps.harness_state(harness) == "protected"
        assert tamper == [] and changes == []
