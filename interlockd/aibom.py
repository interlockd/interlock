"""`interlock aibom`: a CycloneDX 1.6 AI bill of materials for the agent stack on this machine (or a repo).

Components: the agents found (application), each stdio MCP server (application, with a package URL when it is
launched from npm / PyPI / a container image, and whether that version is pinned), models named in agent configs
(machine-learning-model), and Interlock itself. Remote MCP servers are `services` with their endpoint. Tool
definitions pinned by the MCP gateway are recorded as component properties (name + sha256). Env values, headers, and
arguments that look like secrets are never included: only env and header *names*.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .scan import LAUNCHERS, Server, _load, _npm_pinned, _package_arg, _pypi_pinned, discover


def _purl(s: Server) -> tuple[str | None, str | None, bool | None]:
    """(purl, version, pinned) for a launcher-fetched package or a container image."""
    cmd = Path(s.command).name if s.command else ""
    args = s.args
    if cmd in ("pnpm", "yarn", "bun") and args[:1] in (["dlx"], ["x"]):
        cmd, args = "npx", args[1:]
    if cmd in LAUNCHERS:
        spec = _package_arg(cmd, args)
        if not spec:
            return None, None, None
        if LAUNCHERS[cmd] == "npm":
            body = spec.removeprefix("@")
            name, ver = (spec, None) if "@" not in body else (spec[: len(spec) - len(body.rsplit("@", 1)[1]) - 1], body.rsplit("@", 1)[1])
            purl_name = name.replace("@", "%40", 1) if name.startswith("@") else name
            return f"pkg:npm/{purl_name}" + (f"@{ver}" if ver else ""), ver, _npm_pinned(spec)
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+?)(?:==|@)\s*([0-9][^,;\s]*)$", spec)
        name, ver = (m.group(1), m.group(2)) if m else (re.split(r"[<>=@\[]", spec)[0], None)
        return f"pkg:pypi/{name.lower()}" + (f"@{ver}" if ver else ""), ver, _pypi_pinned(spec)
    if cmd in ("docker", "podman") and "run" in args:
        image = next((a for a in args[args.index("run") + 1:] if not a.startswith("-") and "=" not in a), None)
        if image:
            repo, _, digest = image.partition("@")
            repo, _, tag = repo.partition(":") if "/" not in repo.rsplit(":", 1)[-1] else (repo, "", "")
            name = repo.rsplit("/", 1)[-1]
            version = f"@{digest.replace(':', '%3A')}" if digest else ""
            quals = [f"repository_url={repo}"] + ([f"tag={tag}"] if tag else [])
            return f"pkg:oci/{name}{version}?{'&'.join(quals)}", digest or tag or None, bool(digest)
    return None, None, None


def _models(home: Path, project: Path) -> list[tuple[str, str]]:
    """(agent, model) pairs named in agent configs."""
    out = []
    for agent, path, keys in (("codex", home / ".codex" / "config.toml", ("model",)),
                              ("claude-code", home / ".claude" / "settings.json", ("model",)),
                              ("claude-code", project / ".claude" / "settings.json", ("model",)),
                              ("gemini-cli", home / ".gemini" / "settings.json", ("model",))):
        d = _load(path) if path.is_file() else None
        if isinstance(d, dict):
            for k in keys:
                v = d.get(k)
                if isinstance(v, dict):
                    v = v.get("name")
                if isinstance(v, str) and v:
                    out.append((agent, v))
    return sorted(set(out))


def build(home: Path, interlock_home: Path, project: Path) -> dict:
    from .mcp_proxy import Pins
    from .onboard import detect

    servers, sources = discover(home, project)
    pins = Pins(interlock_home / "mcp-pins.json").load()
    components, services, deps = [], [], []
    il_ref = "interlock"
    components.append({"type": "application", "bom-ref": il_ref, "name": "interlock", "version": __version__,
                       "purl": f"pkg:pypi/interlock@{__version__}", "description": "Pre/post-action gate for AI agents"})
    for d in detect(project):
        if d.present:
            components.append({"type": "application", "bom-ref": f"agent:{d.name}", "name": d.name,
                               "properties": [{"name": "interlock:detected_by", "value": d.why or ""}]})
    for agent, model in _models(home, project):
        components.append({"type": "machine-learning-model", "bom-ref": f"model:{agent}:{model}", "name": model,
                           "properties": [{"name": "interlock:configured_in", "value": agent}]})
    for s in servers:
        ref = f"mcp:{s.agent}:{s.name}"
        props = [{"name": "interlock:agent", "value": s.agent}, {"name": "interlock:config", "value": s.source},
                 {"name": "interlock:disabled", "value": str(s.disabled).lower()}]
        props += [{"name": "interlock:env", "value": k} for k in sorted(s.env)]
        for tool, meta in sorted((pins.get(s.name) or {}).items()):
            props.append({"name": f"interlock:pinned_tool:{tool}", "value": meta.get("sha256", "")})
        if s.url:
            services.append({"bom-ref": ref, "name": s.name, "endpoints": [s.url],
                             "properties": props + [{"name": "interlock:headers", "value": ",".join(sorted(s.headers))}]})
        else:
            purl, ver, pinned = _purl(s)
            comp = {"type": "application", "bom-ref": ref, "name": s.name,
                    "properties": props + [{"name": "interlock:command", "value": Path(s.command).name}]}
            if purl:
                comp["purl"] = purl
                comp["properties"].append({"name": "interlock:pinned", "value": str(bool(pinned)).lower()})
            if ver:
                comp["version"] = ver
            components.append(comp)
        deps.append({"ref": f"agent:{s.agent}", "dependsOn": [ref]})
    merged: dict[str, set] = {}
    for d in deps:
        merged.setdefault(d["ref"], set()).update(d["dependsOn"])
    known = {c["bom-ref"] for c in components} | {s["bom-ref"] for s in services}
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
                     "tools": {"components": [{"type": "application", "name": "interlock", "version": __version__}]},
                     "properties": [{"name": "interlock:sources", "value": ",".join(sources)}]},
        "components": components,
        **({"services": services} if services else {}),
        "dependencies": [{"ref": r, "dependsOn": sorted(v)} for r, v in sorted(merged.items()) if r in known],
    }


def summary(bom: dict) -> str:
    comps = bom["components"]
    servers = [c for c in comps if c["bom-ref"].startswith("mcp:")]
    unpinned = [c["name"] for c in servers if any(p["name"] == "interlock:pinned" and p["value"] == "false" for p in c.get("properties", []))]
    lines = [f"AI bill of materials (CycloneDX {bom['specVersion']}):",
             f"  agents   {sum(c['bom-ref'].startswith('agent:') for c in comps)}",
             f"  models   {sum(c['type'] == 'machine-learning-model' for c in comps)}",
             f"  mcp      {len(servers)} local server(s), {len(bom.get('services', []))} remote",
             f"  unpinned {', '.join(unpinned) or 'none'}"]
    return "\n".join(lines)


def to_json(bom: dict) -> str:
    return json.dumps(bom, indent=2)
