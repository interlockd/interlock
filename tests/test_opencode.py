"""OpenCode plugin (JS) against a real daemon via Node: blocks by throwing, passes benign calls, records results,
fails open or closed when the daemon is down; installer and uninstall."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from interlockd.api import ApiServer
from interlockd.cli import main

PLUGIN = Path(__file__).resolve().parents[1] / "interlockd" / "shims" / "opencode" / "interlock.js"
DRIVER = """
const { Interlock } = await import(process.argv[2]);
const hooks = await Interlock({ directory: "/ws" });
const out = [];
for (const [tool, args] of [["bash", {command: "git push --force origin main"}], ["bash", {command: "ls"}]]) {
  try { await hooks["tool.execute.before"]({tool, sessionID: "oc1"}, {args}); out.push("allowed"); }
  catch (e) { out.push("blocked: " + e.message.slice(0, 40)); }
}
await hooks["tool.execute.after"]({tool: "read", sessionID: "oc1"}, {args: {filePath: "README.md"}, output: "hello"});
console.log(JSON.stringify(out));
"""

def _node_works() -> bool:
    if shutil.which("node") is None:
        return False
    try:
        return subprocess.run(["node", "--version"], capture_output=True, timeout=10, check=False).returncode == 0
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _node_works(), reason="node not available or not runnable")


@pytest.fixture
def server(settings):
    from interlockd.pipeline import Daemon
    from interlockd.policy import Policy
    from interlockd.store.memory import MemoryRepository
    from interlockd.store.spool import Spool

    pol = Policy(); pol.mode = "enforce"; pol.trust.workspace_roots = ["/ws"]
    d = Daemon(settings, spool=Spool(settings.spool_dir), repo=MemoryRepository(), policy=pol)
    s = ApiServer(d, "tok", "127.0.0.1", 0); s.start_background()
    yield s
    s.shutdown()


def _run(tmp_path, url, **env):
    home = tmp_path / "ih"; home.mkdir(exist_ok=True); (home / "token").write_text("tok\n")
    plugin = tmp_path / "interlock.mjs"; plugin.write_text(PLUGIN.read_text().replace("__VERSION__", "t"))
    driver = tmp_path / "driver.mjs"; driver.write_text(DRIVER)
    e = {**os.environ, "INTERLOCK_HOME": str(home), "INTERLOCK_URL": url, **env}
    r = subprocess.run(["node", str(driver), plugin.as_uri()], text=True, capture_output=True, env=e, timeout=30, check=False)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_plugin_against_daemon(server, tmp_path):
    host, port = server.address
    out = _run(tmp_path, f"http://{host}:{port}")
    assert out[0].startswith("blocked: [interlock]") and out[1] == "allowed"
    recs = list(server.daemon.spool.iter_records())
    assert {r["kind"] for r in recs} == {"pre_action", "post_action"} and {r["agent_type"] for r in recs} == {"opencode"}


def test_plugin_daemon_down(tmp_path):
    assert _run(tmp_path, "http://127.0.0.1:1") == ["allowed", "allowed"]                       # fail open by default
    out = _run(tmp_path, "http://127.0.0.1:1", INTERLOCK_FAIL_MODE="closed")
    assert out[0].startswith("blocked: [interlock] This action was NOT") and out[1].startswith("blocked")


def test_install_uninstall(tmp_path, monkeypatch):
    home = tmp_path / "home"; (home / ".config" / "opencode").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("INTERLOCK_HOME", str(home / ".interlock"))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False); monkeypatch.setenv("PATH", "/usr/bin:/bin"); monkeypatch.chdir(tmp_path)
    assert main(["init", "--yes", "--no-service", "--harness", "opencode"]) == 0
    plugin = home / ".config" / "opencode" / "plugins" / "interlock.js"
    assert plugin.exists() and "__VERSION__" not in plugin.read_text()
    assert main(["uninstall", "--yes"]) == 0 and not plugin.exists()
