"""Property 12: Relocation is a canonical-path comparison (integrity.Verifier.verify, reported shim path).

The Shim reports its own path; the Verifier compares it, with symlinks resolved, against the Manifest's path for the
harness. Any spelling of the Manifest path (a symlink to the file, a path through a symlinked parent directory, `./`
and `sib/../` segments, duplicate slashes) is intact; a path whose canonical form differs is `shim_relocated`; an
omitted path (a pre-0.2 shim) never yields `shim_relocated`.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from hypothesis import assume, given
from hypothesis import strategies as st

from interlockd.integrity import Baseline, Verifier, key
from interlockd.onboard import Manifest

from .strategies import PROPS, harnesses, path_components

SYMLINKS = os.name == "posix"          # creating symlinks needs privileges on Windows
SHIM_NAME = "interlock-hook.sh"
JOINTS = ("", "./", "/", "sib/../")    # what may be inserted after a separator: nothing, `./`, `//`, a detour
RESERVED = frozenset({"sib", "links", "elsewhere", "nowhere", "copy", "else", "dlink", "hook-config.json"})


def _install(root: Path, harness: str, dirs: list[str]) -> tuple[Path, Verifier]:
    """A Home under `root` with one enforcement point for `harness` at `root/<dirs...>/interlock-hook.sh`, a hook
    config that runs it, and a baseline pinning its digest. Every directory on the way gets a `sib` sibling so that
    `sib/../` detours resolve through real directories."""
    shim_dir = root.joinpath(*dirs)
    shim_dir.mkdir(parents=True)
    for i in range(len(dirs) + 1):
        (root.joinpath(*dirs[:i]) / "sib").mkdir(exist_ok=True)
    shim = shim_dir / SHIM_NAME
    shim.write_text(f"#!/bin/sh\n# interlock shim for {harness}\n", encoding="utf-8")
    cfg = root / "hook-config.json"
    cfg.write_text(f'{{"hooks": [{{"command": "sh {shim}"}}]}}', encoding="utf-8")
    man = Manifest(hooks=[{"harness": harness, "file": str(cfg), "marker": str(shim), "created": False}])
    base = Baseline(shims={key(harness): hashlib.sha256(shim.read_bytes()).hexdigest()})
    return shim, Verifier(root, lambda: man, lambda: base)


def _spell(start: str, parts: list[str], joints: list[str]) -> str:
    """`start` followed by `parts`, with `joints[i]` inserted right after the separator before `parts[i]`."""
    out = start
    for part, joint in zip(parts, joints, strict=True):
        out += "/" + joint + part
    return out


@st.composite
def layouts(draw) -> tuple[str, list[str]]:
    dirs = draw(st.lists(path_components().filter(lambda c: c not in RESERVED), min_size=1, max_size=4,
                         unique=True))
    return draw(harnesses()), dirs


@st.composite
def equivalent_spellings(draw, n_parts: int) -> dict:
    """A plan for spelling the Manifest path differently. `n_parts` = directories + the file name."""
    kinds = ["plain"] + (["file_link", "dir_link"] if SYMLINKS else [])
    plan = {"kind": draw(st.sampled_from(kinds)),
            "joints": draw(st.lists(st.sampled_from(JOINTS), min_size=n_parts, max_size=n_parts)),
            "chain": draw(st.integers(1, 3)),                      # file_link: links to links to the shim
            "level": draw(st.integers(1, n_parts - 1))}            # dir_link: link replaces the first `level` dirs
    return plan


def _realize_equivalent(root: Path, dirs: list[str], plan: dict) -> str:
    parts = [*dirs, SHIM_NAME]
    joints = plan["joints"]
    if plan["kind"] == "plain":
        return _spell(str(root), parts, joints)
    links = root / "links"
    (links / "sib").mkdir(parents=True)
    if plan["kind"] == "file_link":
        target = root.joinpath(*parts)
        for i in range(plan["chain"]):
            link = links / f"l{i}.sh"
            link.symlink_to(target)
            target = link
        return _spell(str(links), [target.name], joints[:1])
    level = plan["level"]
    link = links / "d"
    link.symlink_to(root.joinpath(*dirs[:level]), target_is_directory=True)
    # Joints after the link stay valid: every real directory below it has a `sib` sibling.
    return _spell(str(link), parts[level:], joints[level:])


DIFFERENT = ("other_dir_copy", "missing_elsewhere", "sibling_name", "shim_dir", "detour_elsewhere", "nul",
             "overlong") + (("link_to_copy", "dir_link_elsewhere") if SYMLINKS else ())


def _realize_different(root: Path, shim: Path, dirs: list[str], kind: str, name: str) -> str:
    if kind == "other_dir_copy":                  # same bytes, different place
        other = root / "elsewhere" / name / SHIM_NAME
        other.parent.mkdir(parents=True)
        other.write_bytes(shim.read_bytes())
        return str(other)
    if kind == "missing_elsewhere":
        return str(root / "nowhere" / name / SHIM_NAME)
    if kind == "sibling_name":
        return str(shim.with_name(name + ".sh"))
    if kind == "shim_dir":
        return str(shim.parent)
    if kind == "detour_elsewhere":                # `..` that lands in a different directory
        return _spell(str(root), [*dirs[:-1], "sib", "..", "..", "sib", SHIM_NAME], [""] * (len(dirs) + 4))
    if kind == "nul":
        return str(shim) + "\x00" + name
    if kind == "overlong":
        return str(root) + "/" + "/".join([name] * (4097 // (len(name) + 1) + 1)) + "/" + SHIM_NAME
    if kind == "link_to_copy":                    # a symlink, but to a different file
        other = root / "copy" / SHIM_NAME
        other.parent.mkdir()
        other.write_bytes(shim.read_bytes())
        link = root / f"{name}.sh"
        link.symlink_to(other)
        return str(link)
    # dir_link_elsewhere: a symlinked directory that does not lead to the shim's directory
    elsewhere = root / "else" / name
    elsewhere.mkdir(parents=True)
    link = root / "dlink"
    link.symlink_to(elsewhere, target_is_directory=True)
    return str(link / SHIM_NAME)


# Feature: hook-tamper-detection, Property 12: Relocation is a canonical-path comparison
@PROPS
@given(layouts(), st.data())
def test_equivalent_spellings_are_intact(layout, data):
    """**Validates: Requirements 5.11, 5.13**"""
    harness, dirs = layout
    plan = data.draw(equivalent_spellings(len(dirs) + 1))
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shim, v = _install(root, harness, dirs)
        reported = _realize_equivalent(root, dirs, plan)
        assert os.path.samefile(reported, shim)                      # the spelling really names the shim
        assert v.verify(harness, None).problem == ""                 # 5.13: omitted path, intact point
        assert v.verify(harness, "").problem == ""
        res = v.verify(harness, reported)
        assert res.problem == "" and res.problems == ()
        assert v.verify(harness, reported).problem == ""             # cached realpath gives the same answer


# Feature: hook-tamper-detection, Property 12: Relocation is a canonical-path comparison
@PROPS
@given(layouts(), st.sampled_from(DIFFERENT), path_components())
def test_different_paths_are_relocated(layout, kind, name):
    """**Validates: Requirements 5.11, 5.13**"""
    harness, dirs = layout
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shim, v = _install(root, harness, dirs)
        reported = _realize_different(root, shim, dirs, kind, name)
        if "\x00" not in reported and len(reported) <= 4096:
            assume(os.path.realpath(reported) != os.path.realpath(shim))
        res = v.verify(harness, reported)
        assert res.problem == "shim_relocated" and res.problems == ("shim_relocated",)
        assert res.path == str(shim)                                 # the Manifest's path, never the request's
        assert v.verify(harness, reported).problem == "shim_relocated"
        assert v.verify(harness, None).problem == ""                 # 5.13: omitting the path is not relocation
        assert v.verify(harness, str(shim)).problem == ""            # the cache keeps the two answers apart
