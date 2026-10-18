"""CycloneDX AI bill of materials: components, package URLs and pinning, remote services, models, no secrets."""

from __future__ import annotations

import json

from test_scan import GH_TOKEN, sandbox  # noqa: F401  reuse the scan sandbox (configs for 8 agents)

from interlockd.aibom import _purl, build
from interlockd.scan import Server


def S(cmd, args):
    return Server(name="s", agent="a", source="x", transport="stdio", command=cmd, args=args)


def test_purls():
    assert _purl(S("npx", ["-y", "@modelcontextprotocol/server-github@1.2.0"])) == ("pkg:npm/%40modelcontextprotocol/server-github@1.2.0", "1.2.0", True)
    assert _purl(S("npx", ["-y", "pkg"])) == ("pkg:npm/pkg", None, False)
    assert _purl(S("uvx", ["mcp-server-fetch==2025.1.1"])) == ("pkg:pypi/mcp-server-fetch@2025.1.1", "2025.1.1", True)
    assert _purl(S("uvx", ["--from", "My_Pkg==1.0", "tool"])) == ("pkg:pypi/my_pkg@1.0", "1.0", True)
    p, v, pinned = _purl(S("docker", ["run", "-i", "--rm", "ghcr.io/acme/mcp:latest"]))
    assert p == "pkg:oci/mcp?repository_url=ghcr.io/acme/mcp&tag=latest" and v == "latest" and pinned is False
    p, v, pinned = _purl(S("docker", ["run", "localhost:5000/team/img@sha256:abc"]))
    assert p.startswith("pkg:oci/img@sha256%3Aabc?repository_url=localhost:5000/team/img") and pinned is True
    assert _purl(S("node", ["server.js"])) == (None, None, None)


def test_bom(sandbox):  # noqa: F811
    home, proj = sandbox
    (home / ".codex" / "config.toml").write_text((home / ".codex" / "config.toml").read_text().replace(
        'sandbox_mode', 'model = "gpt-x"\nsandbox_mode', 1))
    bom = build(home, home / ".interlock", proj)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6" and bom["serialNumber"].startswith("urn:uuid:")
    comps = {c["bom-ref"]: c for c in bom["components"]}
    gh = comps["mcp:claude-code:gh"]
    assert gh["purl"] == "pkg:npm/%40modelcontextprotocol/server-github" and {"name": "interlock:pinned", "value": "false"} in gh["properties"]
    assert {"name": "interlock:env", "value": "GITHUB_TOKEN"} in gh["properties"]
    assert any(c["type"] == "machine-learning-model" and c["name"] == "gpt-x" for c in bom["components"])
    assert {s["name"] for s in bom["services"]} == {"remote", "safe"}
    refs = set(comps) | {s["bom-ref"] for s in bom["services"]}
    assert all(d["ref"] in refs and set(d["dependsOn"]) <= refs for d in bom["dependencies"])
    assert GH_TOKEN not in json.dumps(bom)                                  # values never included
