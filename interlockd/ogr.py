"""OGR conformance (design §5.2): the `POST /v1/evaluate` seat.

An OGR `GuardEvent` carries one half of a model call (`step/request` or `step/response`) in a
provider-native or canonical `payload`. We map it onto one or more `InterlockEvent`s — one per
proposed tool call for a `step/response`, one per arriving tool result for a `step/request` — run
each through the SAME `Daemon.decide()` pipeline the native `/interlock/v1/decide` path uses (the
judge is consulted whenever a backend is configured, exactly as for pre/post-action), and compose
the per-event dispositions into a single OGR `Verdict`.

Disposition → OGR decision (the wire enum is only `allow`/`block`; `require_approval` was removed in
OGR v1.x, so the "ask" band is Interlock-native and maps to `block` by default — fail stricter —
configurable to `allow` with the finding retained):

    allow, pass, warn  -> allow      (warn keeps its finding + notice; it is advisory)
    ask                -> block | allow   (ogr.ask_maps_to, default block)
    block, withhold    -> block

The verdict validates against `schema/verdict.schema.json`. GuardEvent and Verdict shapes follow
`interlock/phase1-research.md` §4 (verified against the OGR specification) and the mapping in
`interlock/phase1-design.md` §5.2.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ids import ulid
from .models import (
    AdapterInfo,
    Capabilities,
    Context,
    Finding,
    Identity,
    InterlockEvent,
    ToolCall,
    ToolResult,
    UserMessage,
    Verdict,
)

SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "verdict.schema.json"
OGR_PROVIDER = "interlock"
PROTOCOLS = ("canonical", "openai.chat", "openai.responses", "anthropic.messages")
# OGR peers can drop a single call, withhold a result, or take a redaction span, so the daemon may
# emit its richest dispositions and the OGR verdict layer renders them as decision + continuation.
OGR_CAPABILITIES = Capabilities(ask=True, rewrite=True, withhold=True)

MAX_USER_MESSAGES = 6
_USER_MSG_CAP = 4000


# ----------------------------------------------------------------------------- payload -> trajectory


@dataclass
class Trajectory:
    """The parts of a GuardEvent payload the pipeline needs, protocol-independent."""

    user_messages: list[str] = field(default_factory=list)
    prior_calls: list[dict[str, Any]] = field(default_factory=list)   # {name, arguments_summary}
    tool_calls: list[dict[str, Any]] = field(default_factory=list)    # proposed now: {id, name, arguments}
    tool_results: list[dict[str, Any]] = field(default_factory=list)  # arriving now: {id, name, content}


def _text_of(content: Any) -> str:
    """Flatten a message `content` (string, provider content-block list, or dict) to plain text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for b in content:
            if isinstance(b, str):
                parts.append(b)
            elif isinstance(b, dict):
                if isinstance(b.get("text"), str):
                    parts.append(b["text"])
                elif isinstance(b.get("content"), str):
                    parts.append(b["content"])
        return "\n".join(p for p in parts if p)
    if isinstance(content, dict):
        if isinstance(content.get("text"), str):
            return content["text"]
        if isinstance(content.get("content"), str):
            return content["content"]
    return str(content)


def _coerce_args(arguments: Any) -> dict[str, Any]:
    """Tool arguments must be an object; OpenAI ships them as a JSON string."""
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        s = arguments.strip()
        if not s:
            return {}
        try:
            parsed = json.loads(s)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except json.JSONDecodeError:
            return {"value": arguments}
    if arguments is None:
        return {}
    return {"value": arguments}


def _args_summary(name: str, arguments: dict[str, Any]) -> str:
    for k in ("command", "cmd", "script", "path", "file_path", "url", "query"):
        v = arguments.get(k)
        if isinstance(v, str) and v:
            return f"{name} {v}"[:200]
    return f"{name} {json.dumps(arguments, ensure_ascii=False, sort_keys=True)}"[:200]


def _norm_call(cid: Any, name: Any, arguments: Any) -> dict[str, Any]:
    return {"id": cid if isinstance(cid, str) else None, "name": str(name or ""), "arguments": _coerce_args(arguments)}


def _openai_calls(obj: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tc in (obj.get("tool_calls") or []):
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
        out.append(_norm_call(tc.get("id"), fn.get("name") or tc.get("name"), fn.get("arguments", tc.get("arguments"))))
    return out


def _anthropic_calls(content: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for b in (content or []):
        if isinstance(b, dict) and b.get("type") == "tool_use":
            out.append(_norm_call(b.get("id"), b.get("name"), b.get("input")))
    return out


def _parse_canonical(payload: dict[str, Any], traj: Trajectory) -> list[list[dict[str, Any]]]:
    assistant_call_seq: list[list[dict[str, Any]]] = []
    for m in (payload.get("messages") or []):
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role == "user":
            traj.user_messages.append(_text_of(m.get("content")))
        elif role == "assistant":
            calls = _openai_calls(m) or _anthropic_calls(m.get("content"))
            if calls:
                assistant_call_seq.append(calls)
        elif role in ("tool", "tool_result"):
            traj.tool_results.append({"id": m.get("tool_call_id") or m.get("id"), "name": m.get("name"),
                                      "content": _text_of(m.get("content"))})
    explicit = [_norm_call(tc.get("id"), tc.get("name"), tc.get("arguments"))
                for tc in (payload.get("tool_calls") or []) if isinstance(tc, dict)]
    if explicit:
        traj.tool_calls = explicit
    return assistant_call_seq


def _parse_openai(payload: dict[str, Any], traj: Trajectory) -> list[list[dict[str, Any]]]:
    assistant_call_seq: list[list[dict[str, Any]]] = []
    for m in (payload.get("messages") or []):
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role == "user":
            traj.user_messages.append(_text_of(m.get("content")))
        elif role == "assistant":
            calls = _openai_calls(m)
            if calls:
                assistant_call_seq.append(calls)
        elif role == "tool":
            traj.tool_results.append({"id": m.get("tool_call_id"), "name": m.get("name"),
                                      "content": _text_of(m.get("content"))})
    resp = None
    choices = payload.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        resp = choices[0].get("message")
    elif isinstance(payload.get("message"), dict):
        resp = payload["message"]
    explicit = _openai_calls(resp) if isinstance(resp, dict) else _openai_calls(payload)
    if explicit:
        traj.tool_calls = explicit
    return assistant_call_seq


def _parse_anthropic(payload: dict[str, Any], traj: Trajectory) -> list[list[dict[str, Any]]]:
    assistant_call_seq: list[list[dict[str, Any]]] = []
    for m in (payload.get("messages") or []):
        if not isinstance(m, dict):
            continue
        role, content = m.get("role"), m.get("content")
        if role == "user":
            if isinstance(content, list):
                texts: list[str] = []
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        traj.tool_results.append({"id": b.get("tool_use_id"), "name": None,
                                                  "content": _text_of(b.get("content"))})
                    else:
                        t = _text_of(b)
                        if t:
                            texts.append(t)
                if texts:
                    traj.user_messages.append("\n".join(texts))
            else:
                traj.user_messages.append(_text_of(content))
        elif role == "assistant":
            calls = _anthropic_calls(content)
            if calls:
                assistant_call_seq.append(calls)
    explicit = _anthropic_calls(payload.get("content"))
    if explicit:
        traj.tool_calls = explicit
    return assistant_call_seq


def parse_payload(proto: str, payload: dict[str, Any], kind: str = "step/response") -> Trajectory:
    """Map a provider/canonical payload onto a protocol-independent Trajectory.

    `kind` disambiguates where the trailing assistant tool calls belong: on a `step/response` the
    last assistant message IS the response under judgement, so (absent an explicit response position)
    its calls become the proposed `tool_calls`; on a `step/request` every assistant call already ran
    and is prior context, and what is being judged are the tool results that just arrived.
    """
    traj = Trajectory()
    if proto == "anthropic.messages":
        seq = _parse_anthropic(payload, traj)
    elif proto in ("openai.chat", "openai.responses"):
        seq = _parse_openai(payload, traj)
    else:
        seq = _parse_canonical(payload, traj)
    # When the response position carried no explicit tool calls, the last assistant message in the
    # trajectory IS the response being judged; earlier assistant calls are prior context.
    if kind != "step/request" and not traj.tool_calls and seq:
        traj.tool_calls = seq[-1]
        seq = seq[:-1]
    for calls in seq:
        for c in calls:
            traj.prior_calls.append({"name": c["name"], "arguments_summary": _args_summary(c["name"], c["arguments"])})
    return traj


# ----------------------------------------------------------------------------- GuardEvent -> events


def _user_messages(texts: list[str]) -> list[UserMessage]:
    kept = [t for t in texts if t and t.strip()][-MAX_USER_MESSAGES:]
    k = len(kept)
    return [UserMessage(n=i - k, text=t[:_USER_MSG_CAP]) for i, t in enumerate(kept)]


def guard_event_to_events(ge: dict[str, Any]) -> list[InterlockEvent]:
    """Map one GuardEvent to the InterlockEvents its tool calls / results require."""
    if not isinstance(ge, dict):
        raise TypeError("GuardEvent must be a JSON object")
    proto = ge.get("llm_protocol") or "canonical"
    if proto not in PROTOCOLS:
        proto = "canonical"
    kind = str(ge.get("kind") or "step/response")
    payload = ge.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    traj = parse_payload(proto, payload, kind)

    identity = Identity(
        agent_id=str(ge.get("agent_id") or ""),
        agent_type=str(ge.get("agent_type") or ""),
        agent_workspace=str(ge.get("agent_workspace") or ""),
        agent_user=str(ge.get("agent_user") or ""),
    )
    session = ge.get("session_hint") or ge.get("step_id")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    ums = _user_messages(traj.user_messages)
    adapter = AdapterInfo(name="ogr", version=str(ge.get("integration") or proto))

    def ctx() -> Context:
        return Context(cwd=cwd, user_messages=ums or None, prior_tool_calls=list(traj.prior_calls))

    def pre(call: dict[str, Any]) -> InterlockEvent:
        return InterlockEvent(kind="pre_action", adapter=adapter, identity=identity, session_hint=session,
                              tool_call=ToolCall(id=call.get("id"), name=call.get("name") or "", arguments=call.get("arguments") or {}),
                              context=ctx(), capabilities=OGR_CAPABILITIES)

    def post(res: dict[str, Any]) -> InterlockEvent:
        return InterlockEvent(kind="post_action", adapter=adapter, identity=identity, session_hint=session,
                              tool_call=ToolCall(id=res.get("id"), name=res.get("name") or "tool_result", arguments={}),
                              context=ctx(), result=ToolResult(content=res.get("content") or "", evidence={}),
                              capabilities=OGR_CAPABILITIES)

    want_post = kind == "step/request"
    if want_post and traj.tool_results:
        return [post(r) for r in traj.tool_results]
    if traj.tool_calls:
        return [pre(c) for c in traj.tool_calls]
    if traj.tool_results:  # lenient: judge whatever is present even if kind disagreed
        return [post(r) for r in traj.tool_results]
    return []


# ----------------------------------------------------------------------------- verdict composition


def _map_disposition(disposition: str, ask_maps_to: str) -> str:
    if disposition in ("allow", "pass", "warn"):
        return "allow"
    if disposition == "ask":
        return "allow" if ask_maps_to == "allow" else "block"
    if disposition in ("block", "withhold"):
        return "block"
    return "allow"


def _finding_to_ogr(f: Finding) -> dict[str, Any]:
    return {
        "category": f.category,
        "severity": f.severity,
        "path": f.path,
        "start": f.start,
        "end": f.end,
        "score": f.score,
        "fp": False,
        "whitelisted": bool(f.whitelisted),
        "subject": f.subject,
        "detector": f.detector,
        "rule": f.rule,
    }


def compose_ogr_verdict(event_id: str, pairs: list[tuple[InterlockEvent, Verdict]], *,
                        ask_maps_to: str = "block", latency_ms: float = 0.0,
                        provider: str = OGR_PROVIDER) -> dict[str, Any]:
    """Combine per-InterlockEvent verdicts into one OGR Verdict (deny-wins)."""
    decision = "allow"
    findings: list[dict[str, Any]] = []
    unjudged: list[str] = []
    drop_calls: list[str] = []
    spans: list[dict[str, Any]] = []
    notices: list[str] = []
    withhold = False

    for ev, v in pairs:
        for f in v.findings:
            findings.append(_finding_to_ogr(f))
            if (f.category or "").startswith("security.secret_leak") and f.start is not None and f.end is not None:
                spans.append({"path": f.path, "start": f.start, "end": f.end})
        unjudged.extend(v.unjudged)
        if _map_disposition(v.disposition, ask_maps_to) == "block":
            decision = "block"
            if ev.kind == "pre_action" and ev.tool_call.id:
                drop_calls.append(ev.tool_call.id)
            if v.disposition == "withhold":
                withhold = True
            if v.notice:
                notices.append(v.notice)
        elif v.disposition == "warn" and v.notice:
            notices.append(v.notice)

    notice = " ".join(dict.fromkeys(notices)) or None
    if withhold:
        continuation = {"style": "withhold", "notice": notice}
    elif drop_calls:
        continuation = {"style": "drop_calls", "calls": drop_calls, "notice": notice}
    else:
        continuation = {"style": "answer", "notice": notice}

    return {
        "event_id": event_id,
        "provider": provider,
        "decision": decision,
        "findings": findings,
        "modifications": {"spans": spans},
        "unjudged": sorted(set(unjudged)),
        "latency_ms": round(latency_ms, 2),
        "continuation": continuation,
        "timing": {},
    }


def evaluate_guard_event(daemon, ge: dict[str, Any], *, ask_maps_to: str = "block") -> dict[str, Any]:
    """The body of `POST /v1/evaluate`: GuardEvent -> InterlockEvents -> decide() -> OGR Verdict."""
    t0 = time.perf_counter()
    event_id = ulid()
    events = guard_event_to_events(ge)
    pairs = [(ev, daemon.decide(ev)) for ev in events]
    latency = (time.perf_counter() - t0) * 1000
    return compose_ogr_verdict(event_id, pairs, ask_maps_to=ask_maps_to, latency_ms=latency)


# ----------------------------------------------------------------------------- schema + validation

_SCHEMA_CACHE: dict[str, Any] | None = None


def load_schema() -> dict[str, Any]:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        _SCHEMA_CACHE = json.loads(SCHEMA_PATH.read_text())
    return _SCHEMA_CACHE


def _is_type(value: Any, t: str) -> bool:
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "null":
        return value is None
    return True


def _schema_errors(instance: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """A small, dependency-free Draft-07 subset validator — enough for the OGR verdict schema."""
    errors: list[str] = []
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_is_type(instance, tt) for tt in types):
            errors.append(f"{path}: expected type {t}, got {type(instance).__name__}")
            return errors
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: {instance!r} != const {schema['const']!r}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance} < minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance} > maximum {schema['maximum']}")
    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path}: missing required property '{req}'")
        ap = schema.get("additionalProperties", True)
        for k, v in instance.items():
            if k in props:
                errors += _schema_errors(v, props[k], f"{path}.{k}")
            elif ap is False:
                errors.append(f"{path}: additional property '{k}' not allowed")
            elif isinstance(ap, dict):
                errors += _schema_errors(v, ap, f"{path}.{k}")
    if isinstance(instance, list) and "items" in schema:
        for i, it in enumerate(instance):
            errors += _schema_errors(it, schema["items"], f"{path}[{i}]")
    if "oneOf" in schema:
        matched = sum(1 for s in schema["oneOf"] if not _schema_errors(instance, s, path))
        if matched != 1:
            errors.append(f"{path}: matched {matched} of oneOf, expected exactly 1")
    return errors


def validate_verdict(verdict: Any, schema: dict[str, Any] | None = None) -> list[str]:
    """Return a list of human-readable schema errors ([] means valid)."""
    return _schema_errors(verdict, schema or load_schema())


# ----------------------------------------------------------------------------- seed-v0 reader


def _as_case(raw: Any, default_suite: str, idx: int) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    ge = raw.get("guard_event") or raw.get("guardEvent") or raw.get("event") or raw.get("input")
    if ge is None:
        if any(k in raw for k in ("llm_protocol", "payload", "kind", "agent_id", "step_id")):
            ge, meta = raw, {}
        else:
            return None
    else:
        meta = raw
    if not isinstance(ge, dict):
        return None
    cid = meta.get("id") or meta.get("case_id") or f"{default_suite}-{idx}"
    suite = meta.get("suite") or meta.get("category") or default_suite
    expect = meta.get("expect") if meta.get("expect") is not None else (meta.get("label") or meta.get("expected"))
    return {"id": str(cid), "suite": str(suite), "expect": (str(expect) if expect is not None else None), "guard_event": ge}


def _read_one(path: Path) -> list[dict[str, Any]]:
    suite = path.stem
    text = path.read_text()
    cases: list[dict[str, Any]] = []
    if path.suffix == ".jsonl":
        for i, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            c = _as_case(raw, suite, i)
            if c:
                cases.append(c)
        return cases
    data = json.loads(text) if text.strip() else []
    if isinstance(data, dict):
        data = data.get("cases") or data.get("items") or data.get("data") or data.get("events") or []
    if isinstance(data, list):
        for i, raw in enumerate(data):
            c = _as_case(raw, suite, i)
            if c:
                cases.append(c)
    return cases


def read_seed(path: Path) -> list[dict[str, Any]]:
    """Read an OGR seed suite: a single .json/.jsonl file, or a directory of them."""
    path = Path(path)
    cases: list[dict[str, Any]] = []
    if path.is_dir():
        for p in sorted(path.rglob("*")):
            if p.suffix in (".jsonl", ".json") and p.is_file():
                cases.extend(_read_one(p))
    elif path.is_file():
        cases = _read_one(path)
    return cases


def expected_decision(expect: str | None) -> str | None:
    """Normalize a seed label to the OGR decision it should produce (None if unlabelled)."""
    if not expect:
        return None
    e = expect.strip().lower()
    if e in ("block", "deny", "attack", "unsafe", "malicious", "injection", "positive"):
        return "block"
    if e in ("allow", "pass", "benign", "safe", "negative", "clean"):
        return "allow"
    return None
