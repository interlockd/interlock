"""Corpus v1 engine (design §6, evaluation): build a labelled corpus from real and synthetic sources.

This module is the logic behind `interlock corpus <export|label|import>` (wired in cli.py). It is kept
separate from the CLI so it is unit-testable without argparse. Everything it emits is in the same case
schema the deterministic runner (`interlockd.testkit`) consumes, plus three v1 additions:

    transcript  optional list of {role, text} turns giving the user-intent context a judge case needs
                (role in {"user","assistant"}); never read by the deterministic layer, only the judge step
    judge       {question_id: expected_noul} expected judge answers (already defined by testkit)
    split       "dev" | "heldout" — stable 70/30 assignment from sha256(id), stamped into the file

Sources:
    export   real pre_action events from the local spool and the DynamoDB audit table, secrets redacted
             with the deterministic engine's own SECRET_PATTERNS, deduped by normalized command, written
             UNLABELLED (expect/label/category absent) to corpus/shadow/*.jsonl for a human to label
    label    interactive pass that sets expect/label/category on unlabelled cases
    import   re-shapers for AgentDojo / InjecAgent / AgentDrift into our schema

Redaction note: the review asked to "redact with the existing projector", but redaction proper lives in
the secret patterns, not the projector (which only bounds/structures state). We reuse det.packs.SECRET_PATTERNS
so the corpus is redacted by exactly the same matcher the gate uses — one source of truth.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .det.packs import SECRET_PATTERNS

SPLIT_DEV_FRACTION = 0.70  # 70% dev / 30% heldout


# ---- split -------------------------------------------------------------------------------------------

def split_for(case_id: str, dev_fraction: float = SPLIT_DEV_FRACTION) -> str:
    """Stable dev/heldout assignment from a hash of the id. Deterministic across runs and machines:
    the first 8 hex digits of sha256(id) scaled to [0,1); below dev_fraction → dev, else heldout."""
    h = int(hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:8], 16)
    return "dev" if (h / 0xFFFFFFFF) < dev_fraction else "heldout"


def assign_split(case: dict, dev_fraction: float = SPLIT_DEV_FRACTION) -> dict:
    """Stamp `split` into a case from its id (idempotent). Requires an `id`."""
    case["split"] = split_for(case["id"], dev_fraction)
    return case


# ---- redaction ---------------------------------------------------------------------------------------

def redact(text: str) -> tuple[str, list[str]]:
    """Replace any secret the deterministic engine would detect with a typed placeholder.

    Returns (redacted_text, kinds_found). Uses det.packs.SECRET_PATTERNS so the corpus never stores a
    live credential — the same matcher the secrets pack uses on real traffic."""
    if not text:
        return text, []
    kinds: list[str] = []
    out = text
    for kind, pat in SECRET_PATTERNS:
        if pat.search(out):
            kinds.append(kind)
            out = pat.sub(f"<REDACTED:{kind}>", out)
    return out, kinds


def redact_case(case: dict) -> tuple[dict, list[str]]:
    """Redact secrets in a case's command / tool arguments / manifest in place. Returns (case, kinds)."""
    found: list[str] = []
    if isinstance(case.get("cmd"), str):
        case["cmd"], k = redact(case["cmd"])
        found += k
    args = case.get("args")
    if isinstance(args, dict):
        for key, val in list(args.items()):
            if isinstance(val, str):
                args[key], k = redact(val)
                found += k
    manifest = case.get("manifest")
    if isinstance(manifest, dict):
        for name, content in list(manifest.items()):
            if isinstance(content, str):
                manifest[name], k = redact(content)
                found += k
    return case, found


# ---- normalized dedup key ----------------------------------------------------------------------------

_WS = re.compile(r"\s+")


def dedup_key(case: dict) -> str:
    """A normalized key for dedup: the shell command (whitespace-collapsed) or tool+sorted-args.
    Two cases that differ only in incidental spacing or argument order collapse to one."""
    if isinstance(case.get("cmd"), str):
        return "cmd:" + _WS.sub(" ", case["cmd"].strip())
    tool = case.get("tool", "")
    args = case.get("args") or {}
    try:
        norm = json.dumps(args, sort_keys=True, separators=(",", ":"))
    except TypeError:
        norm = str(sorted(args.items())) if isinstance(args, dict) else str(args)
    return f"tool:{tool}:{norm}"


# ---- event → case ------------------------------------------------------------------------------------

def event_to_case(record: dict, *, idx: int) -> dict | None:
    """Turn a stored pre_action audit record into an UNLABELLED corpus case (expect/label/category absent).

    Only pre_action events with a shell command or a tool+arguments become cases; post_action and
    harness-internal events are skipped (returns None). Secrets are redacted. The source event id and
    the deterministic disposition at capture time are kept under `_meta` for the human labeller's context."""
    if record.get("kind") != "pre_action":
        return None
    tool = record.get("tool_name")
    args = record.get("arguments") or {}
    if not tool:
        return None

    case: dict[str, Any] = {}
    cmd = None
    if isinstance(args, dict):
        for k in ("command", "cmd", "script"):
            if isinstance(args.get(k), str) and args[k].strip():
                cmd = args[k]
                break
    if cmd is not None:
        case["cmd"] = cmd
    else:
        case["tool"] = tool
        case["args"] = {k: v for k, v in args.items() if k not in ("description", "explanation")}

    case["id"] = f"shadow-{record.get('event_id', idx)}"
    case, kinds = redact_case(case)
    meta = {
        "source": "shadow",
        "source_event_id": record.get("event_id"),
        "captured_disposition": record.get("disposition"),
        "captured_at": record.get("received_at"),
    }
    if kinds:
        meta["redacted"] = sorted(set(kinds))
    # user instruction turns, redacted, carried as transcript context for later judge labelling
    msgs = ((record.get("state") or {}).get("user_messages")) or []
    transcript = []
    for m in msgs:
        text = m.get("text") if isinstance(m, dict) else None
        if isinstance(text, str) and text.strip():
            transcript.append({"role": "user", "text": redact(text)[0]})
    if transcript:
        case["transcript"] = transcript
    case["_meta"] = meta
    assign_split(case)
    return case


# ---- export ------------------------------------------------------------------------------------------

@dataclass
class ExportResult:
    cases: list[dict] = field(default_factory=list)
    seen_keys: set[str] = field(default_factory=set)
    from_spool: int = 0
    from_dynamo: int = 0
    skipped_non_preaction: int = 0
    duplicates: int = 0
    redacted_cases: int = 0


def export_cases(records: Iterable[dict], *, result: ExportResult | None = None) -> ExportResult:
    """Convert an iterable of audit records into deduped, redacted, unlabelled cases. Pure; the CLI
    supplies the records from the spool and/or DynamoDB so this is testable without AWS."""
    res = result or ExportResult()
    for i, record in enumerate(records):
        case = event_to_case(record, idx=len(res.cases) + i)
        if case is None:
            res.skipped_non_preaction += 1
            continue
        key = dedup_key(case)
        if key in res.seen_keys:
            res.duplicates += 1
            continue
        res.seen_keys.add(key)
        if case.get("_meta", {}).get("redacted"):
            res.redacted_cases += 1
        res.cases.append(case)
    return res


# ---- label -----------------------------------------------------------------------------------------

VALID_EXPECT = {"block", "ask", "model", "allow"}
VALID_LABEL = {"attack", "benign"}


def is_labelled(case: dict) -> bool:
    return "expect" in case and "label" in case


def apply_label(case: dict, *, expect: str, label: str, category: str | None) -> dict:
    """Set the human labels on a case, validating the enums. Raises ValueError on a bad value."""
    if expect not in VALID_EXPECT:
        raise ValueError(f"expect must be one of {sorted(VALID_EXPECT)}, got {expect!r}")
    if label not in VALID_LABEL:
        raise ValueError(f"label must be one of {sorted(VALID_LABEL)}, got {label!r}")
    case["expect"] = expect
    case["label"] = label
    if category:
        case["category"] = category
    return case


def propose_label(case: dict, ws: Path, *, policy=None, corpus_trust: dict | None = None) -> tuple[dict, bool]:
    """Pre-fill expect/label/category from the deterministic engine's own verdict, so a human only
    reviews the ambiguous cases. Returns (proposal, confident):

      - confident=True  when the engine is unambiguous: it either allowed with NO findings (→ benign/allow)
        or fired a rule with a hard disposition block/ask (→ attack/<decision>/<rule category>).
      - confident=False when the engine routed to `model` (judge territory) or produced only flags —
        these genuinely need a human, so the proposal is a best guess the reviewer should confirm.

    The proposal is NOT written onto the case; the caller decides whether to accept it (auto mode) or
    show it as a default in interactive mode. Runs the real deterministic pipeline via run_case."""
    from .testkit import run_case  # lazy: avoids pulling testkit (and judge deps) unless auto-labelling

    res = run_case(dict(case), ws, policy=policy, corpus_trust=corpus_trust)
    decision = res.decision or "allow"
    category = res.category or None
    if decision == "allow" and not res.fired:
        return {"expect": "allow", "label": "benign", "category": category}, True
    if decision in ("block", "ask"):
        return {"expect": decision, "label": "attack", "category": category}, True
    # model-routed or flag-only: ambiguous — the deterministic layer deferred, so a human must judge
    # The default label is `benign`: a model-routed action is one the engine could not condemn on
    # signature alone, and in real traffic the large majority of those are legitimate. Defaulting to
    # benign makes the interactive Enter/accept SAFE (accepting won't mislabel an ordinary command as an
    # attack); the reviewer presses `a` for the rare genuine attack. The case still needs a human (confident=False).
    return {"expect": decision, "label": "benign", "category": category}, False


def auto_label(cases: list[dict], ws_root: Path, *, policy=None, corpus_trust: dict | None = None
               ) -> tuple[int, list[dict]]:
    """Apply confident proposals to all unlabelled cases in place; return (n_applied, needs_review).
    `needs_review` is the list of still-unlabelled cases the engine was not confident about."""
    applied, needs_review = 0, []
    for i, c in enumerate(cases):
        if is_labelled(c):
            continue
        ws = ws_root / f"p{i}"
        ws.mkdir(parents=True, exist_ok=True)
        proposal, confident = propose_label(c, ws, policy=policy, corpus_trust=corpus_trust)
        if confident:
            apply_label(c, expect=proposal["expect"], label=proposal["label"], category=proposal.get("category"))
            applied += 1
        else:
            needs_review.append(c)
    return applied, needs_review
# ---- jsonl io --------------------------------------------------------------------------------------

def read_jsonl(path: Path) -> list[dict]:
    out = []
    for lineno, line in enumerate(Path(path).read_text().splitlines(), 1):
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {e}") from e
    return out


def write_jsonl(path: Path, cases: list[dict]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cases))


# ---- importers -------------------------------------------------------------------------------------
#
# Each importer reshapes one external dataset into our case schema. The datasets disagree on structure,
# so each mapper is defensive: it extracts a shell/file/network-equivalent action and SKIPS anything with
# no such equivalent (an API-only or chat-only item), returning the skip count. Mappers are pure functions
# over already-parsed JSON so they are testable with small fixtures and never touch the network.

# tool names in external datasets that map onto our shell/file/network tool surface
_SHELLish = {"bash", "shell", "run_terminal", "execute", "exec", "terminal", "run_command", "sh"}
_FILEish = {"write_file", "edit_file", "create_file", "fs_write", "append_file", "delete_file", "read_file"}
_NETish = {"curl", "http_get", "http_post", "fetch", "web_fetch", "download", "wget", "request"}


@dataclass
class ImportResult:
    cases: list[dict] = field(default_factory=list)
    imported: int = 0
    skipped_no_equivalent: int = 0
    skipped_errors: int = 0
    source: str = ""


def _mk_case(case_id: str, *, cmd: str | None = None, tool: str | None = None, args: dict | None = None,
             expect: str, label: str, category: str, judge: dict | None = None,
             transcript: list | None = None, manifest: dict | None = None, result: str | None = None) -> dict:
    case: dict[str, Any] = {"id": case_id}
    if cmd is not None:
        case["cmd"] = cmd
    else:
        case["tool"] = tool
        case["args"] = args or {}
    case["expect"] = expect
    case["label"] = label
    case["category"] = category
    if judge:
        case["judge"] = judge
    if transcript:
        case["transcript"] = transcript
    if manifest:
        case["manifest"] = manifest
    if result:
        case["result"] = result
    case, _ = redact_case(case)
    assign_split(case)
    return case


def _classify_tool(name: str) -> str | None:
    n = (name or "").lower()
    if any(s in n for s in _SHELLish):
        return "shell"
    if any(s in n for s in _FILEish):
        return "file"
    if any(s in n for s in _NETish):
        return "net"
    return None




def import_agentdojo(items: list[dict], *, result: ImportResult | None = None) -> ImportResult:
    """AgentDojo: (user_task, injection_task) pairs over tool suites. Each item carries a ground-truth
    tool-call sequence (`GROUND_TRUTH`/`ground_truth`/`tool_calls`), each call a {function, args} (the API's
    FunctionCall). Calls from an injection task are the attack; user-task calls are benign. Calls whose tool
    has no shell/file/network equivalent are skipped. Falls back to a flat {tool,args,injection} item shape."""
    res = result or ImportResult(source="agentdojo")

    def emit(call: dict, *, injected: bool, suite: str, cid: str) -> bool:
        fn = call.get("function") or call.get("name") or call.get("tool") or ""
        if _classify_tool(fn) is None:
            res.skipped_no_equivalent += 1
            return False
        args = call.get("args") or call.get("arguments") or {}
        cmd = args.get("command") if isinstance(args, dict) else None
        category = "security.data_exfiltration" if injected else "security.malicious_command"
        res.cases.append(_mk_case(
            f"agentdojo-{suite}-{cid}", cmd=cmd if cmd else None, tool=None if cmd else fn,
            args=None if cmd else args, expect="ask" if injected else "allow",
            label="attack" if injected else "benign", category="security.prompt_injection" if injected else category,
            judge={"intent_authorized": 0.1} if injected else None))
        res.imported += 1
        return True

    for i, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                res.skipped_errors += 1
                continue
            suite = item.get("suite") or item.get("suite_name") or "s"
            cid = item.get("id") or item.get("user_task_id") or i
            gt = item.get("GROUND_TRUTH") or item.get("ground_truth") or item.get("tool_calls")
            if isinstance(gt, list) and gt:
                injected = bool(item.get("injection_task") or item.get("injection_task_id") or item.get("attack"))
                for j, call in enumerate(gt):
                    if isinstance(call, dict):
                        emit(call, injected=injected, suite=str(suite), cid=f"{cid}-{j}")
            else:
                # flat fallback (used by unit fixtures): one tool call per item
                fn = item.get("tool") or item.get("function") or item.get("name") or ""
                if _classify_tool(fn) is None:
                    res.skipped_no_equivalent += 1
                    continue
                injected = bool(item.get("injection") or item.get("is_injected") or item.get("attack"))
                args = item.get("args") or item.get("arguments") or {}
                cmd = args.get("command") if isinstance(args, dict) else None
                res.cases.append(_mk_case(
                    f"agentdojo-{item.get('id', i)}", cmd=cmd if cmd else None, tool=None if cmd else fn,
                    args=None if cmd else args, expect="ask" if injected else "allow",
                    label="attack" if injected else "benign",
                    category="security.prompt_injection" if injected else "security.malicious_command",
                    judge={"intent_authorized": 0.1} if injected else None))
                res.imported += 1
        except Exception:  # noqa: BLE001 — a malformed item is skipped and counted, never fatal
            res.skipped_errors += 1
    return res


def import_injecagent(items: list[dict], *, result: ImportResult | None = None) -> ImportResult:
    """InjecAgent: a benign user request triggers a user tool whose OUTPUT carries the attacker instruction,
    which tries to drive an attacker tool. Real fields: `User Instruction`, `Attacker Instruction`,
    `Attacker Tools` (list) / `Attacker Tool`, `User Tool`, `Attack Type` (dh=direct harm, ds=data stealing).
    We model the induced attacker action, put the injected instruction in a manifest, and set the category
    from the attack type (ds -> data_exfiltration). Non-tool attacker actions are skipped."""
    res = result or ImportResult(source="injecagent")
    for i, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                res.skipped_errors += 1
                continue
            atools = item.get("Attacker Tools") or item.get("attacker_tools")
            attacker_tool = (atools[0] if isinstance(atools, list) and atools else None) \
                or item.get("Attacker Tool") or item.get("attacker_tool") or item.get("tool") or ""
            if _classify_tool(attacker_tool) is None:
                res.skipped_no_equivalent += 1
                continue
            payload = item.get("Attacker Instruction") or item.get("attacker_instruction") or ""
            user_instruction = item.get("User Instruction") or item.get("user_instruction") or ""
            user_tool = item.get("User Tool") or item.get("user_tool") or attacker_tool
            attack_type = (item.get("Attack Type") or item.get("attack_type") or "").lower()
            category = "security.data_exfiltration" if attack_type.startswith(("ds", "data")) \
                else "security.prompt_injection"
            cmd = item.get("command")
            res.cases.append(_mk_case(
                f"injecagent-{item.get('id', i)}", cmd=cmd if cmd else None,
                tool=None if cmd else user_tool, args=None if cmd else (item.get("args") or {}),
                expect="ask", label="attack", category=category,
                judge={"injection_present": 0.9, "injection_targets_action": 0.9},
                transcript=[{"role": "user", "text": user_instruction}] if user_instruction else None,
                manifest={"tool_output.txt": payload} if payload else None, result=payload or None))
            res.imported += 1
        except Exception:  # noqa: BLE001
            res.skipped_errors += 1
    return res


_DRIFT_ATTACK_LABELS = {"hijacked", "injection point", "injection_point", "failed injection", "failed_injection"}


def import_agentdrift(items: list[dict], *, result: ImportResult | None = None) -> ImportResult:
    """AgentDrift: step-labeled tool-call trajectories. Each trajectory has a `user_goal`/`task` and a list
    of `steps`, each step a {tool/action, args, observation, label} where label is one of benign,
    injection point, hijacked, failed injection. We emit one case per actionable step: `hijacked` steps are
    attacks the agent took for the attacker (intent low); `benign`/`failed injection` steps are benign; the
    poisoned observation at an `injection point` is carried as a manifest. Flat {tool,args,drifted} items
    are also accepted (unit fixtures). Steps with no shell/file/network equivalent are skipped."""
    res = result or ImportResult(source="agentdrift")

    def emit(step: dict, *, goal: str, tid, j: int) -> None:
        tool = step.get("tool") or step.get("action") or step.get("function") or ""
        if _classify_tool(tool) is None:
            res.skipped_no_equivalent += 1
            return
        label_raw = (step.get("label") or step.get("step_label") or "").lower().replace("_", " ")
        attack = label_raw in {"hijacked", "injection point", "failed injection"}
        hijacked = label_raw == "hijacked"
        args = step.get("args") or step.get("arguments") or {}
        cmd = args.get("command") if isinstance(args, dict) else step.get("command")
        obs = step.get("observation") or step.get("output")
        res.cases.append(_mk_case(
            f"agentdrift-{tid}-{j}", cmd=cmd if cmd else None, tool=None if cmd else tool,
            args=None if cmd else args,
            expect="ask" if attack else "allow", label="attack" if attack else "benign",
            category="security.malicious_command",
            judge={"intent_authorized": 0.1 if hijacked else (0.5 if attack else 0.9)},
            transcript=[{"role": "user", "text": goal}] if goal else None,
            manifest={"observation.txt": obs} if (obs and "injection" in label_raw) else None,
            result=obs if (obs and "injection" in label_raw) else None))
        res.imported += 1

    for i, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                res.skipped_errors += 1
                continue
            goal = item.get("user_goal") or item.get("goal") or item.get("task") or ""
            tid = item.get("id") or item.get("trajectory_id") or i
            steps = item.get("steps") or item.get("trajectory")
            if isinstance(steps, list) and steps:
                for j, step in enumerate(steps):
                    if isinstance(step, dict):
                        emit(step, goal=goal, tid=tid, j=j)
            else:
                # flat fallback (unit fixtures): the item itself is one step
                drifted = bool(item.get("drifted", True))
                tool = item.get("tool") or item.get("action") or ""
                if _classify_tool(tool) is None:
                    res.skipped_no_equivalent += 1
                    continue
                args = item.get("args") or {}
                cmd = args.get("command") if isinstance(args, dict) else item.get("command")
                res.cases.append(_mk_case(
                    f"agentdrift-{tid}", cmd=cmd if cmd else None, tool=None if cmd else tool,
                    args=None if cmd else args, expect="ask" if drifted else "allow",
                    label="attack" if drifted else "benign", category="security.malicious_command",
                    judge={"intent_authorized": 0.1 if drifted else 0.9},
                    transcript=[{"role": "user", "text": goal}] if goal else None))
                res.imported += 1
        except Exception:  # noqa: BLE001
            res.skipped_errors += 1
    return res


IMPORTERS = {"agentdojo": import_agentdojo, "injecagent": import_injecagent, "agentdrift": import_agentdrift}
