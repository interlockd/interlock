"""OAuth checks for remote MCP servers behind the HTTP gateway (`mcp.oauth` in policy).

The gateway sees the client's bearer token on every request and the server's challenge (401/403 with
`WWW-Authenticate`) on the way back. It turns what it sees into one `mcp.oauth` call that these rules decide:

  mcp.oauth_audience_mismatch      the token was issued for another resource (its `aud` names a different host).
                                   MCP forbids passing tokens through to servers they weren't issued for.
  mcp.oauth_denied_scope           a scope the token carries, or the server asks for, matches `mcp.oauth.deny_scopes`.
  mcp.oauth_broad_scope            a scope looks administrative or unlimited (recorded; tune with an override).
  mcp.oauth_metadata_foreign_host  the server points its protected-resource metadata at another host.
  mcp.oauth_resource_mismatch      the metadata's `resource` is not this server.
  mcp.oauth_auth_server_changed    the server's authorization servers differ from the ones pinned on first use.

Tokens are read, never verified (the gateway is not the resource server) and never recorded: only the claims
named above reach the audit log.
"""

from __future__ import annotations

import base64
import json
import re
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit

from ..policy import Policy
from . import DetResult, rule

TOOL = "mcp.oauth"

R_AUD = rule("mcp.oauth_audience_mismatch", "security.unauthorized_tool", "high", "block")
R_DENIED = rule("mcp.oauth_denied_scope", "security.privilege_escalation", "high", "block")
R_BROAD = rule("mcp.oauth_broad_scope", "security.privilege_escalation", "medium", "flag")
R_META_HOST = rule("mcp.oauth_metadata_foreign_host", "security.unauthorized_tool", "medium", "flag")
R_RESOURCE = rule("mcp.oauth_resource_mismatch", "security.unauthorized_tool", "high", "block")
R_AS_CHANGED = rule("mcp.oauth_auth_server_changed", "security.unauthorized_tool", "high", "block")

BROAD_EXACT = {"*", "all", "admin", "root", "sudo", "full_access", "delete_repo", "admin:org", "admin:enterprise",
               "https://www.googleapis.com/auth/cloud-platform"}
BROAD_GLOBS = ("admin:*", "*:admin", "*.admin", "*.all", "*:all", "write:*", "*.readwrite.all")


def jwt_claims(token: str) -> dict[str, Any] | None:
    """The payload of a JWT, unverified; None for opaque tokens."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except (ValueError, json.JSONDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def token_facts(authorization: str | None) -> dict[str, Any]:
    """What the audit log may keep about a bearer token: audience and scopes, never the token."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return {}
    claims = jwt_claims(authorization[7:].strip())
    if claims is None:
        return {"token": "opaque"}
    aud = claims.get("aud")
    scopes = claims.get("scope") or claims.get("scp") or []
    if isinstance(scopes, str):
        scopes = scopes.split()
    return {"token": "jwt", "aud": aud if isinstance(aud, list) else ([aud] if aud else []),
            "token_scopes": [str(s) for s in scopes][:100], "iss": str(claims.get("iss") or "")}


def challenge_facts(www_authenticate: str | None) -> dict[str, Any]:
    """`scope` and `resource_metadata` from a Bearer challenge (RFC 6750, RFC 9728)."""
    if not www_authenticate:
        return {}
    params = dict(re.findall(r'(\w+)="([^"]*)"', www_authenticate))
    out: dict[str, Any] = {}
    if params.get("scope"):
        out["requested_scopes"] = params["scope"].split()[:100]
    if params.get("resource_metadata"):
        out["resource_metadata"] = params["resource_metadata"]
    if params.get("error"):
        out["error"] = params["error"]
    return out


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _same_site(a: str, b: str) -> bool:
    """Same host, or one a subdomain of the other's registrable part (mcp.example.com vs auth.example.com is not
    enough: only the exact host or a parent/child relation counts)."""
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def check(args: dict[str, Any], res: DetResult, policy: Policy) -> None:
    upstream = str(args.get("upstream") or "")
    up_host = _host(upstream)
    server = str(args.get("server") or "")
    for aud in args.get("aud") or []:
        aud = str(aud)
        aud_host = _host(aud) if "://" in aud else ""
        if aud_host and not _same_site(aud_host, up_host):
            res.add(policy, R_AUD, path="token.aud", subject=f"{server}: token issued for {aud_host}, not {up_host}")
            break
    scopes = [*(args.get("token_scopes") or []), *(args.get("requested_scopes") or [])]
    denied = [s for s in scopes if any(fnmatchcase(s, p) for p in policy.mcp.oauth.deny_scopes)]
    if denied:
        res.add(policy, R_DENIED, path="token.scope", subject=f"{server}: {', '.join(sorted(set(denied)))[:120]}")
    broad = [s for s in scopes if s not in denied and (s.lower() in BROAD_EXACT or any(fnmatchcase(s.lower(), p) for p in BROAD_GLOBS))]
    if broad:
        res.add(policy, R_BROAD, path="token.scope", subject=f"{server}: {', '.join(sorted(set(broad)))[:120]}")
    meta = str(args.get("resource_metadata") or "")
    if meta and not _same_site(_host(meta), up_host):
        res.add(policy, R_META_HOST, path="challenge.resource_metadata", subject=f"{server}: metadata at {_host(meta)}")
    resource = str(args.get("resource") or "")
    if resource and not _same_site(_host(resource), up_host):
        res.add(policy, R_RESOURCE, path="metadata.resource", subject=f"{server}: resource is {resource}")
    if args.get("auth_servers_changed"):
        res.add(policy, R_AS_CHANGED, path="metadata.authorization_servers",
                subject=f"{server}: now {', '.join(args.get('authorization_servers') or [])[:120]} "
                        f"(pinned {', '.join(args.get('pinned_authorization_servers') or [])[:120]})")
