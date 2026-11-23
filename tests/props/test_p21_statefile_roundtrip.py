"""Property 21: state-file serializer invariants and round trip (statefile.dumps / write_state / read_state).

Documents are generated from the four state-file schemas in design.md (Data Models): Stop_Marker,
Integrity_Baseline, Protection_State and the clean-exit mark in daemon.json.
"""

from __future__ import annotations

import json
import os
import stat

from hypothesis import given
from hypothesis import strategies as st

from interlockd import statefile
from interlockd.onboard import HARNESSES

from .strategies import (
    HARNESS_REASONS,
    HOME_REASONS,
    PROPS,
    STATES,
    epochs,
    home_paths,
    iso,
    iso_timestamps,
    path_components,
    sha256_hex,
    stop_marker_docs,
)

_ULID = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _key(harness: str) -> str:
    return harness.replace("-", "_")


def _versions() -> st.SearchStrategy[str]:
    return st.builds(lambda a, b, c: f"{a}.{b}.{c}", *(st.integers(0, 20) for _ in range(3)))


def _ulids() -> st.SearchStrategy[str]:
    return st.text(alphabet=_ULID, min_size=26, max_size=26)


def _hook_configs() -> st.SearchStrategy[str]:
    return st.builds(lambda home, name: f"{home}/{name}.json", home_paths(), path_components())


@st.composite
def baseline_docs(draw) -> dict:
    """Integrity_Baseline: flat; shim_<h> digests and hook_<h> paths for a subset of harnesses."""
    installed = draw(st.lists(st.sampled_from(HARNESSES), unique=True, max_size=len(HARNESSES)))
    digest_or_absent = st.one_of(st.just(""), sha256_hex())
    doc: dict = {
        "created_at": draw(iso_timestamps()),
        "version": draw(_versions()),
        "policy_file_sha256": draw(digest_or_absent),
        "managed_policy_file_sha256": draw(digest_or_absent),
        "token_sha256": draw(sha256_hex()),
        "token_sha256_previous": draw(digest_or_absent),
        "token_mode": draw(st.one_of(st.just(-1), st.integers(0, 0o777))),
    }
    for h in installed:
        doc[f"shim_{_key(h)}"] = draw(sha256_hex())
        doc[f"hook_{_key(h)}"] = draw(_hook_configs())
    return doc


@st.composite
def protection_docs(draw) -> dict:
    """Protection_State: events/reasons keyed `<subject>__<reason>`, plus state_<h> per harness."""
    harness_keys = st.tuples(st.sampled_from(HARNESSES).map(_key), st.sampled_from(sorted(HARNESS_REASONS)))
    home_keys = st.tuples(st.just("home"), st.sampled_from(sorted(HOME_REASONS)))
    keys = draw(st.lists(st.one_of(harness_keys, home_keys).map("__".join), unique=True, max_size=12))
    doc: dict = {
        "aggregate": draw(st.sampled_from(STATES)),
        "events": {k: draw(_ulids()) for k in keys},
        "observing": draw(st.booleans()),
        "reasons": {k: draw(iso_timestamps()) for k in keys},
        "updated_at": draw(iso_timestamps()),
        "version": draw(_versions()),
    }
    for h in draw(st.lists(st.sampled_from(HARNESSES), unique=True)):
        doc[f"state_{_key(h)}"] = draw(st.sampled_from(STATES))
    return doc


@st.composite
def clean_exit_docs(draw) -> dict:
    """daemon.json with the clean-exit mark; `socket` optional."""
    started = draw(epochs())
    doc: dict = {
        "listen": f"127.0.0.1:{draw(st.integers(1, 65535))}",
        "pid": draw(st.integers(1, 2**22)),
        "version": draw(_versions()),
        "started_at": iso(started),
        "exited_at": iso(started + draw(st.integers(0, 10**6))),
        "exit_reason": draw(st.sampled_from(("sigterm", "sigint", "stop"))),
    }
    if draw(st.booleans()):
        doc["socket"] = draw(home_paths()) + "/interlockd.sock"
    return doc


def state_docs() -> st.SearchStrategy[dict]:
    return st.one_of(stop_marker_docs(), baseline_docs(), protection_docs(), clean_exit_docs())


def _parse_recording_keys(text: str) -> tuple[dict, list[list[str]]]:
    """json.loads, also returning every object's keys in document order (to check order and uniqueness)."""
    seen: list[list[str]] = []

    def hook(pairs):
        seen.append([k for k, _ in pairs])
        return dict(pairs)

    return json.loads(text, object_pairs_hook=hook), seen


# Feature: hook-tamper-detection, Property 21: State-file serializer invariants and round trip
@PROPS
@given(state_docs())
def test_serializer_invariants_and_round_trip(tmp_path, doc):
    """**Validates: Requirements 9.11, 12.1, 12.2**"""
    text = statefile.dumps(doc)
    raw = text.encode("ascii")  # ASCII only (raises otherwise)

    assert len(raw) <= statefile.MAX_BYTES
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert text.count("\n") == 1
    assert "\\" not in text  # no JSON escape sequences

    parsed, key_lists = _parse_recording_keys(text)
    for keys in key_lists:
        assert keys == sorted(keys)
        assert len(keys) == len(set(keys))
        assert all(statefile.KEY_RE.match(k) and 1 <= len(k) <= 32 for k in keys)
    for v in parsed.values():
        if isinstance(v, dict):
            assert all(isinstance(x, (str, int)) for x in v.values())  # one level of nesting only
        else:
            assert isinstance(v, (str, int))

    assert parsed == doc
    assert statefile.dumps(parsed) == text
    assert statefile.single_line(doc) == text[:-1]

    path = tmp_path / "state.json"
    errors: list[tuple[str, str]] = []
    assert statefile.write_state(path, doc, on_error=lambda f, r: errors.append((f, r)))
    assert errors == []
    assert path.read_bytes() == raw
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert not path.with_name(path.name + ".tmp").exists()

    assert statefile.read_state(path, {}, on_error=lambda f, r: errors.append((f, r))) == doc
    assert errors == []
