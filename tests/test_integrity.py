"""Integrity baseline, hot-path enforcement-point verification and the token check (Requirements 5 and 8)."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

from interlockd import integrity
from interlockd.cli import CLAUDE_SHIM_SRC
from interlockd.integrity import Baseline, Verifier, cached_loader, token_check
from interlockd.onboard import Manifest

POSIX = os.name == "posix"


def _shim_text(version: str | None = None) -> str:
    text = CLAUDE_SHIM_SRC.read_text(encoding="utf-8").replace("__HARNESS__", "claude-code")
    return text if version is None else text.replace('VERSION="0.1.8"', f'VERSION="{version}"')


@pytest.fixture
def install(tmp_path):
    """A Home with one claude-code enforcement point, its manifest, token, policy and a saved baseline."""
    home = tmp_path / "home"
    shim = home / "adapters" / "claude-code" / "interlock-hook.sh"
    shim.parent.mkdir(parents=True)
    shim.write_text(_shim_text(), encoding="utf-8", newline="\n")
    cfg = tmp_path / "settings.json"
    cfg.write_text(f'{{"hooks": {{"PreToolUse": [{{"hooks": [{{"command": "sh {shim}"}}]}}]}}}}', encoding="utf-8", newline="\n")
    man = Manifest(hooks=[{"harness": "claude-code", "file": str(cfg), "marker": str(shim), "created": False}])
    man.save(home)
    (home / "token").write_text("t0ken-value\n", encoding="utf-8", newline="\n")
    assert integrity.restore_token_mode(home / "token") is None       # owner-only, as auth makes a real token
    (home / "policy.yaml").write_text("version: 1\nmode: shadow\n", encoding="utf-8", newline="\n")
    base = Baseline.from_disk(home, man)
    assert base.save(home)
    holder = {"man": man, "base": base}
    v = Verifier(home, lambda: holder["man"], lambda: holder["base"])
    return home, shim, cfg, v, holder


# ------------------------------------------------------------------------------------------------ baseline


def test_baseline_round_trip_flat_owner_only(install):
    home, shim, _, _, holder = install
    p = home / integrity.BASELINE
    if POSIX:
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    text = p.read_text(encoding="ascii")
    assert '"shim_claude_code": "' + hashlib.sha256(shim.read_bytes()).hexdigest() + '"' in text
    assert '"hook_claude_code": "' in text and "{" not in text[1:]          # flat: no nested object
    loaded = Baseline.load(home)
    assert loaded == holder["base"]
    assert loaded.token_sha256 == hashlib.sha256(b"t0ken-value\n").hexdigest()
    assert loaded.policy_file_sha256 == hashlib.sha256((home / "policy.yaml").read_bytes()).hexdigest()
    assert loaded.managed_policy_file_sha256 == ""                         # absent file
    if POSIX:
        assert loaded.token_mode == 0o600


def test_baseline_skips_hook_paths_that_need_json_escapes(tmp_path):
    b = Baseline(created_at="2026-10-17T09:00:00Z", version="0.2.0", token_mode=384,
                 shims={"claude_code": "a" * 64}, hooks={"claude_code": '/tmp/we"ird', "codex": "/tmp/caf\u00e9"})
    assert b.save(tmp_path)
    text = (tmp_path / integrity.BASELINE).read_text(encoding="ascii")
    assert "hook_" not in text and '"shim_claude_code"' in text
    assert Baseline.load(tmp_path).hooks == {}


def test_baseline_bad_digest_is_unreadable(tmp_path):
    errors = []
    Baseline(shims={"claude_code": "a" * 64}).save(tmp_path)
    p = tmp_path / integrity.BASELINE
    p.write_text(p.read_text(encoding="ascii").replace("a" * 64, "nothex"), encoding="ascii", newline="\n")
    os.chmod(p, 0o600)
    assert Baseline.load(tmp_path, lambda f, r: errors.append(r)) is None
    assert errors == ["state_unreadable:bad_digest"]


def test_from_disk_keeps_previous_token_digest_and_load_or_create(install):
    home, _, _, _, holder = install
    (home / "token").write_text("rotated\n", encoding="utf-8", newline="\n")
    b = Baseline.from_disk(home, holder["man"], previous=holder["base"])
    assert b.token_sha256_previous == holder["base"].token_sha256
    assert b.token_sha256 == hashlib.sha256(b"rotated\n").hexdigest()
    (home / integrity.BASELINE).unlink()
    created, was_created = Baseline.load_or_create(home, holder["man"])
    assert was_created and (home / integrity.BASELINE).exists()
    again, was_created = Baseline.load_or_create(home, holder["man"])
    assert not was_created and again == created


# ------------------------------------------------------------------------------------------------ verifier


def test_intact_and_version_line_only_difference(install):
    _, shim, _, v, _ = install
    assert v.verify("claude-code").problem == ""
    shim.write_text(_shim_text("0.0.9"), encoding="utf-8", newline="\n")                # an upgrade leaves only this difference
    assert v.verify("claude-code").problem == ""


def test_crlf_shim_is_intact(install):
    _, shim, _, v, holder = install
    holder["base"] = Baseline(shims={})                                  # no pin: packaged-shim semantics only
    shim.write_bytes(_shim_text().replace("\n", "\r\n").encode("utf-8"))
    assert v.verify("claude-code").problem == ""


def test_shim_modified(install):
    _, shim, _, v, holder = install
    shim.write_text(_shim_text() + "\nexit 0\n", encoding="utf-8", newline="\n")
    res = v.verify("claude-code")
    assert res.problem == "shim_modified" and res.path == str(shim)
    assert res.expected_sha256 == holder["base"].shims["claude_code"]
    assert res.observed_sha256 == hashlib.sha256(shim.read_bytes()).hexdigest()
    assert v.verify("claude-code").problem == "shim_modified"            # reported on every request


def test_shim_missing(install):
    _, shim, _, v, _ = install
    shim.unlink()
    res = v.verify("claude-code")
    assert res.problem == "shim_missing" and res.path == str(shim)


def test_shim_replaced_by_directory_is_modified(install):
    _, shim, _, v, _ = install
    shim.unlink()
    shim.mkdir()
    assert v.verify("claude-code").problem == "shim_modified"


@pytest.mark.parametrize("variant", ["edited", "deleted", "directory", "unreadable"])
def test_hook_removed_variants(install, variant):
    _, _, cfg, v, _ = install
    if variant == "edited":
        cfg.write_text('{"hooks": {}}', encoding="utf-8", newline="\n")
    elif variant == "deleted":
        cfg.unlink()
    elif variant == "directory":
        cfg.unlink()
        cfg.mkdir()
    else:
        if not POSIX or os.geteuid() == 0:
            pytest.skip("needs POSIX permissions and a non-root user")
        os.chmod(cfg, 0)
    try:
        res = v.verify("claude-code")
    finally:
        if variant == "unreadable":
            os.chmod(cfg, 0o600)
    assert res.problem == "hook_removed" and res.path == str(cfg)
    assert res.expected_sha256 == "" and res.observed_sha256 == ""


def test_hook_removed_comes_first_and_all_problems_listed(install):
    _, shim, cfg, v, _ = install
    cfg.write_text("{}", encoding="utf-8", newline="\n")
    shim.write_text("echo pwned\n", encoding="utf-8", newline="\n")
    res = v.verify("claude-code", "/elsewhere/hook.sh")
    assert res.problem == "hook_removed"
    assert res.problems == ("hook_removed", "shim_modified", "shim_relocated")


def test_opencode_plugin_file_is_its_own_hook_config(tmp_path):
    plugin = tmp_path / "interlock.js"
    plugin.write_text("// plugin without its own path\n", encoding="utf-8", newline="\n")
    man = Manifest(hooks=[{"harness": "opencode", "file": str(plugin), "marker": str(plugin), "created": True}])
    base = Baseline(shims={"opencode": hashlib.sha256(plugin.read_bytes()).hexdigest()})
    assert Verifier(tmp_path, lambda: man, lambda: base).verify("opencode").problem == ""


def test_no_baseline_for_unmanifested_harness(install):
    _, _, _, v, holder = install
    assert v.verify("codex").problem == "no_baseline"
    holder["man"] = None
    assert v.verify("claude-code").problem == "no_baseline"


@pytest.mark.skipif(not POSIX, reason="symlinks need privileges on Windows")
def test_reported_shim_path_is_compared_canonically(install, tmp_path):
    _, shim, _, v, _ = install
    link = tmp_path / "link.sh"
    link.symlink_to(shim)
    linked_dir = tmp_path / "adapters-link"
    linked_dir.symlink_to(shim.parent, target_is_directory=True)
    assert v.verify("claude-code", str(shim)).problem == ""
    assert v.verify("claude-code", str(link)).problem == ""
    assert v.verify("claude-code", str(linked_dir / shim.name)).problem == ""
    assert v.verify("claude-code", None).problem == ""                 # pre-0.2 shim: no path, no relocation
    other = tmp_path / "other.sh"
    other.write_text(_shim_text(), encoding="utf-8", newline="\n")
    res = v.verify("claude-code", str(other))
    assert res.problem == "shim_relocated" and res.path == str(shim)  # never the request's string
    assert v.verify("claude-code", "bad\x00path").problem == "shim_relocated"


def test_stat_cache_rereads_only_on_change(install, monkeypatch):
    _, shim, cfg, v, _ = install
    reads = []
    real = integrity._read_bytes
    monkeypatch.setattr(integrity, "_read_bytes", lambda p: reads.append(p) or real(p))
    assert v.verify("claude-code").problem == ""
    assert sorted(reads) == sorted([str(shim), str(cfg)])
    reads.clear()
    for _ in range(5):
        assert v.verify("claude-code").problem == ""
    assert reads == []                                                  # unchanged: stat only

    st = shim.stat()
    os.utime(shim, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))  # mtime
    v.verify("claude-code")
    assert reads == [str(shim)]

    reads.clear()
    cfg.write_text(cfg.read_text(encoding="utf-8") + " ", encoding="utf-8", newline="\n")  # size
    v.verify("claude-code")
    assert reads == [str(cfg)]

    reads.clear()
    st = shim.stat()
    tmp = shim.with_name("new.sh")
    tmp.write_bytes(shim.read_bytes())
    os.utime(tmp, ns=(st.st_atime_ns, st.st_mtime_ns))                  # same size and mtime, new inode
    os.replace(tmp, shim)
    assert shim.stat().st_ino != st.st_ino
    v.verify("claude-code")
    assert reads == [str(shim)]

    reads.clear()
    v.invalidate()
    v.verify("claude-code")
    assert sorted(reads) == sorted([str(shim), str(cfg)])


@pytest.mark.skipif(sys.platform == "win32", reason="st_ctime is the creation time on Windows (see test_watch_rereads_every_pass_on_windows)")
def test_in_place_edit_with_restored_mtime_is_caught(install):
    _, shim, _, v, _ = install
    assert v.verify("claude-code").problem == ""
    st = shim.stat()
    data = bytearray(shim.read_bytes())
    data[-2:-1] = b"#"                                                   # same size, different content
    with open(shim, "r+b") as f:
        f.write(bytes(data))
    os.utime(shim, ns=(st.st_atime_ns, st.st_mtime_ns))                  # `touch -r` back
    assert v.verify("claude-code").problem == "shim_modified"


def test_pin_change_rechecks_cached_shim(install):
    _, shim, _, v, holder = install
    shim.write_text("echo replaced\n", encoding="utf-8", newline="\n")
    assert v.verify("claude-code").problem == "shim_modified"
    holder["base"] = Baseline(shims={"claude_code": hashlib.sha256(shim.read_bytes()).hexdigest()})  # `ack`
    assert v.verify("claude-code").problem == ""


def test_verifier_is_thread_safe(install):
    _, _, _, v, _ = install
    out: list[str] = []
    threads = [threading.Thread(target=lambda: out.extend(v.verify("claude-code").problem for _ in range(50)))
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert out == [""] * 400


def test_cached_loader_keeps_last_good_value(tmp_path):
    p = tmp_path / "install-manifest.json"
    clock = [0.0]
    p.write_text('{"hooks": []}', encoding="utf-8", newline="\n")
    load = cached_loader(p, lambda: Manifest.load(tmp_path), ttl_s=1.0, clock=lambda: clock[0])
    first = load()
    assert isinstance(first, Manifest)
    p.write_text("{not json", encoding="utf-8", newline="\n")
    assert load() is first                                              # within the TTL: no stat
    clock[0] = 5.0
    assert load() is first                                              # unparseable: last good value
    p.unlink()
    clock[0] = 10.0
    assert load() is first                                              # deleted: last good value


# ------------------------------------------------------------------------------------------------ token


def test_token_intact_modified_missing(install):
    home, _, _, _, holder = install
    assert token_check(home, holder["base"]) == ("", {})
    (home / "token").write_text("swapped\n", encoding="utf-8", newline="\n")
    os.chmod(home / "token", 0o600)
    kind, detail = token_check(home, holder["base"])
    assert kind == "token_modified" and detail == {"observed_sha256": hashlib.sha256(b"swapped\n").hexdigest()}
    assert "swapped" not in repr(detail)
    (home / "token").unlink()
    assert token_check(home, holder["base"]) == ("token_missing", {})


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits")
def test_token_permissions_restored(install):
    home, _, _, _, holder = install
    os.chmod(home / "token", 0o644)
    kind, detail = token_check(home, holder["base"])
    assert kind == "token_permissions"
    assert detail == {"observed_mode": 0o644, "restored_mode": 0o600, "restore_error": ""}
    assert stat.S_IMODE((home / "token").stat().st_mode) == 0o600
    assert token_check(home, holder["base"]) == ("", {})


class FakeIcacls:
    """A file ACL kept in memory; answers the icacls argv forms restore_token_mode and _acl_extra use."""

    def __init__(self, path: str, entries: list[str]):
        self.path, self.entries, self.calls = path, list(entries), []

    def __call__(self, argv, **kw):
        assert isinstance(argv, list) and kw.get("check") is False and "shell" not in kw
        self.calls.append(argv)
        assert argv[0] == "icacls" and argv[1] == self.path
        if len(argv) == 2:
            lines = [f"{self.path} {self.entries[0]}", *(" " * len(self.path) + " " + e for e in self.entries[1:]),
                     "", "Successfully processed 1 files; Failed processing 0 files"]
            out = "\n".join(lines) + "\n"
        elif argv[2] == "/inheritance:r":
            self.entries = [e for e in self.entries if "(I)" not in e]
            for g in argv[4:]:
                who = g.rsplit(":", 1)[0]
                self.entries = [e for e in self.entries if not e.startswith(who + ":")] + [f"{who}:(F)"]
            out = "processed file\n"
        elif argv[2] == "/remove:g":
            self.entries = [e for e in self.entries if not e.startswith(argv[3] + ":")]
            out = "processed file\n"
        else:
            raise AssertionError(argv)
        return type("R", (), {"returncode": 0, "stdout": out, "stderr": ""})()


def test_windows_acl_check_and_reset(install, monkeypatch):
    home, _, _, _, holder = install
    path = str(home / "token")
    fake = FakeIcacls(path, ["NT AUTHORITY\\SYSTEM:(F)", "BUILTIN\\Administrators:(F)", "PC\\alice:(F)",
                             "BUILTIN\\Users:(I)(RX)", "Everyone:(R)"])
    monkeypatch.setattr(integrity, "_WINDOWS", True)
    monkeypatch.setenv("USERNAME", "alice")
    monkeypatch.setattr(integrity.subprocess, "run", fake)
    kind, detail = token_check(home, holder["base"])
    assert kind == "token_permissions"
    assert detail == {"observed_mode": -1, "restored_mode": -1, "restore_error": "", "extra_principals": 2}
    assert ["icacls", path, "/inheritance:r", "/grant:r", "alice:F", "*S-1-5-18:F", "*S-1-5-32-544:F"] in fake.calls
    assert ["icacls", path, "/remove:g", "Everyone"] in fake.calls
    assert integrity._acl_extra(home / "token") == []
    assert token_check(home, holder["base"]) == ("", {})               # owner-only now: nothing to report


def test_windows_acl_unreadable_is_reported(install, monkeypatch):
    home, _, _, _, holder = install

    def failing(argv, **kw):
        return type("R", (), {"returncode": 5, "stdout": "", "stderr": "Access is denied."})()

    monkeypatch.setattr(integrity, "_WINDOWS", True)
    monkeypatch.setenv("USERNAME", "alice")
    monkeypatch.setattr(integrity.subprocess, "run", failing)
    kind, detail = token_check(home, holder["base"])
    assert kind == "token_permissions" and detail["restore_error"] == "icacls_failed:grant"
    assert detail["extra_principals"] == -1


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX chmod path")
def test_restore_token_mode_reports_errno(tmp_path):
    assert integrity.restore_token_mode(tmp_path / "absent").startswith("chmod_failed:")


def test_new_and_rotated_tokens_are_made_owner_only_on_windows(tmp_path, monkeypatch):
    """Windows ignores the 0o600 passed to os.open, so the token would inherit its folder's ACL; it is reset to the
    owner, SYSTEM and Administrators when created and before a rotated token replaces the old one."""
    from interlockd import auth

    made = []
    monkeypatch.setattr(auth.sys, "platform", "win32")
    monkeypatch.setattr(integrity, "restore_token_mode", lambda p: made.append(Path(p).name))
    path = tmp_path / "token"
    auth.load_or_create_token(path)
    auth.load_or_create_token(path)                                      # existing token: left as it is
    auth.rotate_token(path)
    assert made == ["token", "token.new"] and not (tmp_path / "token.new").exists()
    monkeypatch.setattr(auth.sys, "platform", "linux")
    auth.rotate_token(path)
    assert made == ["token", "token.new"]
