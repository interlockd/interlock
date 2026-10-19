"""Vendor-neutral injection detector on untrusted content: no AWS, no network, no model required.

Two layers, both local:
  1. heuristics: weighted patterns for instructions addressed to an AI agent (override, role, directive + action,
     concealment, hidden carriers such as HTML comments and zero-width text). Zero dependencies, ~sub-millisecond.
  2. optional classifier: a Hugging Face sequence classifier (e.g. Meta PromptGuard 2) when `classifier_model` is set
     and `transformers` is installed. Loaded lazily; a load or inference failure is reported, never raised.

Returns the same GuardrailsResult shape as the Bedrock probe, so the pipeline composes all detectors deny-wins.
The heuristics are deliberately conservative: content that only *talks about* prompt injection (docs, tests, this
file) scores low because a high score needs a directive aimed at the agent plus a concrete action or override.
"""

from __future__ import annotations

import logging
import re
import time
import unicodedata

from ..models import Finding
from .guardrails import GuardrailsResult

log = logging.getLogger("interlockd.judge.local_probe")

MAX_CHARS = 20_000

# Who the text is talking to. Injection is addressed to the model, not the human reader.
_ADDRESS = r"(?:ai|llm|agent|assistant|model|copilot|claude|codex|kiro|chatgpt|gpt|language model|coding assistant)"

# (name, weight, pattern). Weights add; the score is squashed into [0, 1].
# Scoring shape: an addressee or override framing, plus an action, plus a risky target crosses the threshold.
# Framing + action alone (an AGENTS.md saying "the assistant should run make test") stays just under it.
_SIGNALS: list[tuple[str, float, re.Pattern[str]]] = [
    ("override", 0.55, re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|the|user'?s?)\b"
        r"[^.\n]{0,30}\b(?:instructions?|guidelines?|directives?|prompts?|safety|guardrails?)\b"
        # rules / policies / tasks only with ignore-style verbs and an agent-facing determiner: docs say "bypass the X policy"
        r"|\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|your|user'?s?)\b"
        r"[^.\n]{0,30}\b(?:rules?|polic(?:y|ies)|requests?|task)\b"
        r"|\byour\s+(?:real|actual|true|new|only)\s+(?:task|job|goal|objective|instructions?)\b"
        r"|\b(?:stop what you are doing|from now on,? your (?:job|task|role) is)\b|\bsystem\s+override\b"
        # "ignore your previous ..." needs no object: attackers misspell it ("iunstructions")
        r"|\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:your|the|my|any)\s+(?:previous|prior|earlier|above|original)\b"
        # task hijack: put the injected goal ahead of the one the user gave
        r"|\bbefore\s+you\s+(?:can\s+)?(?:solve|complete|finish|do|continue(?:\s+with)?|start)\b[^.\n]{0,30}\btask\b"
        r"|\bthe\s+task\s+(?:that\s+)?(?:I|the\s+user)\s+gave\s+you\b", re.IGNORECASE)),
    ("new_instructions", 0.35, re.compile(
        r"\b(?:new|updated|real|actual|true|hidden|secret)\s+(?:system\s+)?(?:instructions?|directives?|objective|orders?)\b"
        r"|\b(?:fetch|get|read|load)\s+(?:your\s+)?(?:next|new|further)\s+instructions?\b"
        r"|\b(?:(?:strictly\s+)?adhere\s+to|obey|strictly\s+(?:follow|comply\s+with))\s+the\s+following\s+(?:instructions?|directives?|commands?)\b",
        re.IGNORECASE)),
    ("role_marker", 0.4, re.compile(
        r"(?:^|\n|<!--|\[)\s*(?:system|assistant|developer)\s*(?:prompt|message|override)?\s*[:\]>]|<\|?\s*(?:im_start|system)\s*\|?>"
        r"|#{2,}\s*[(\[]?\s*(?:system|developer)[_ ](?:message|prompt|instructions?)\s*[)\]]?",
        re.IGNORECASE)),
    ("addressed", 0.4, re.compile(
        rf"\b(?:note|message|instructions?|reminder|attention|hey|dear|important|notice)\b[^.\n]{{0,25}}\b(?:to|for)\s+"
        rf"(?:the\s+|any\s+|all\s+)?{_ADDRESS}s?\b"
        rf"|\b(?:if you are|you are an?|as an?)\s+(?:an?\s+)?{_ADDRESS}\b"
        rf"|(?:^|\n|<!--|\]|\*\*)\s*(?:the\s+)?(?:ai\s+)?{_ADDRESS}\s*[:,]"
        rf"|\b(?:the|this|any|all)\s+(?:ai\s+)?{_ADDRESS}s?\s+(?:should|must|needs? to|has to|is required to|will|shall)\b"
        rf"|\byou\s+are\s+(?:required|instructed|expected|authorized)\s+to\b"
        rf"|\b(?:message|note|request)\s+from\s+me\b[^.\n]{{0,60}}\bto\s+you\b", re.IGNORECASE | re.MULTILINE)),
    ("action", 0.4, re.compile(
        r"\b(?:run|execute|exec|call|invoke|send|upload|post|transmit|forward|email|exfiltrate|curl|wget|fetch|download|"
        r"install|apply|delete|remove|wipe|push|commit|copy|cp|move|cat|print|list|dump|read|modify|edit|change|add|append|"
        r"write|replace|disable|set|follow|grant|transfer|share|unlock|approve|pay|purchase|buy|withdraw|invite|retrieve|"
        r"cancel|schedule|book|deposit|enable)\b", re.IGNORECASE)),
    ("concealment", 0.35, re.compile(
        r"\b(?:do not|don't|never|without)\s+(?:tell|telling|inform|informing|mention|mentioning|notify|notifying|alert|"
        r"alerting|ask|asking)\b[^.\n]{0,20}\b(?:the\s+)?(?:user|human|developer|operator)\b"
        r"|\b(?:silently|secretly|quietly|covertly)\s+(?:run|execute|send|upload|post|copy|delete|remove|install|add|"
        r"modify|exfiltrate|forward|email|transfer|grant|share|do|perform|include|append|insert)\b", re.IGNORECASE)),
    ("false_authority", 0.25, re.compile(
        r"\b(?:the\s+)?user\s+(?:has\s+)?(?:already\s+)?(?:approved|authorized|confirmed|consented|agreed)\b"
        r"|\b(?:pre-?approved|authorized by (?:the )?(?:admin|security|owner))\b", re.IGNORECASE)),
    ("url", 0.2, re.compile(r"https?://[^\s)>\"']+", re.IGNORECASE)),
    ("email_address", 0.2, re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    # MCP tool poisoning: <IMPORTANT>-style blocks and instructions about how to use OTHER tools (shadowing)
    ("instruction_tag", 0.35, re.compile(r"<\s*/?\s*(?:important|system|instructions?|secret|hidden|information)\s*>", re.IGNORECASE)),
    ("tool_shadowing", 0.35, re.compile(
        r"\b(?:when|whenever|before|after)\b[^.\n]{0,40}\b(?:using|calling|invoking|you use|you call)\b[^.\n]{0,40}\btool\b"
        r"|\b(?:always|must)\b[^.\n]{0,40}\b(?:bcc|cc|forward|redirect|send a copy)\b", re.IGNORECASE)),
    ("secret_target", 0.25, re.compile(
        r"(?:\.env\b|\.ssh\b|id_rsa|id_ed25519|\.aws/credentials|authorized_keys|\bapi[_ -]?keys?\b|\bsecrets?\b|"
        r"\btokens?\b|\bpasswords?\b|\bcredentials?\b)", re.IGNORECASE)),
    ("config_target", 0.25, re.compile(
        r"(?:\.interlock/|\.claude/|\.kiro/|\.codex/|settings\.json|hooks\.json|mcp\.json|\.zshrc|\.bashrc|\.profile\b|"
        r"crontab|sudoers|\bpolicy\.ya?ml\b)", re.IGNORECASE)),
    ("dangerous_exec", 0.3, re.compile(
        r"\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:ba|z)?sh\b|\b(?:python3?|node|ruby|perl)\s+-[ce]\b|\bos\.system\b|\beval\(|"
        r"\brm\s+-rf\b|--(?:hard|force)\b|\bsolutions?\b", re.IGNORECASE)),
]

# Text that *quotes* an attack phrase while discussing it (security docs, tests) is data, not a directive.
_QUOTED = re.compile(r"[\"'`“‘]([^\"'`”’\n]{4,160})[\"'`”’]")
_META = re.compile(r"\b(?:prompt[- ]injection|jailbreak|attackers?|adversar\w*|malicious|payloads?|for example|e\.g\.|such as)\b", re.IGNORECASE)

# Carriers that hide text from a human reviewer but not from the model.
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")
_TAG_CHARS = re.compile(r"[\U000E0000-\U000E007F]")

# A score at or above this produces a finding; tuned so docs that merely discuss injection stay below it.
DEFAULT_THRESHOLD = 0.6


def _squash(x: float) -> float:
    """Map the summed weights onto [0, 1): 0.4 -> ~0.35, 0.8 -> ~0.57, 1.05 -> ~0.67, 1.6 -> ~0.82."""
    return round(1.0 - 2.0 ** (-x / 0.65), 3) if x > 0 else 0.0


def _decode_tags(text: str) -> str:
    """Unicode tag characters (U+E0000..E007F) are an invisible ASCII channel; recover what they spell."""
    return "".join(chr(ord(c) - 0xE0000) for c in _TAG_CHARS.findall(text))


def heuristic_score(text: str, *, assume_addressed: bool = False) -> tuple[float, list[str]]:
    """Score `text` for instructions aimed at an agent. Returns (score in [0,1], matched signal names).

    `assume_addressed` is for text whose only reader is the model, such as an MCP tool description: there an
    imperative needs no "note to the assistant" framing to be an instruction."""
    norm = unicodedata.normalize("NFKC", text)
    hidden = _decode_tags(norm)
    visible = _ZERO_WIDTH.sub("", _TAG_CHARS.sub("", norm))
    hits: list[str] = []
    total = 0.0
    # Discussion of attacks: drop quoted spans from the text the framing signals see, so a doc that says
    # attackers write "ignore previous instructions" is scored on its own words, not on the quote.
    framing_view = _QUOTED.sub(" ", visible) if _META.search(visible) else visible
    for name, weight, pat in _SIGNALS:
        view = framing_view if name in ("override", "role_marker", "addressed", "new_instructions") else visible
        if pat.search(view) or (hidden and pat.search(hidden)):
            hits.append(name)
            total += weight
    # A directive needs an addressee or an override/role framing to count as injection rather than prose.
    framed = {"override", "role_marker", "addressed", "new_instructions"} & set(hits)
    if not framed and not assume_addressed:
        total *= 0.3
    # Hidden carriers: directives inside HTML comments or invisible characters are a strong tell.
    comments = " ".join(_HTML_COMMENT.findall(visible))
    if comments and any(p.search(comments) for n, _, p in _SIGNALS if n in ("override", "action", "addressed", "role_marker")):
        hits.append("hidden_comment")
        total += 0.35
    if hidden.strip():
        hits.append("unicode_tags")
        total += 0.6
    elif len(_ZERO_WIDTH.findall(norm)) >= 8:
        hits.append("zero_width")
        total += 0.2
    return _squash(total), hits


class LocalInjectionProbe:
    name = "local"

    def __init__(self, *, threshold: float = DEFAULT_THRESHOLD, classifier_model: str | None = None,
                 classifier_threshold: float = 0.8):
        self.threshold = threshold
        self.classifier_model = classifier_model
        self.classifier_threshold = classifier_threshold
        self._clf = None
        self._clf_error: str | None = None

    def _classifier(self):
        if self._clf is None and self._clf_error is None and self.classifier_model:
            try:
                from transformers import pipeline  # optional; lazy

                self._clf = pipeline("text-classification", model=self.classifier_model, truncation=True, max_length=512)
            except Exception as e:  # noqa: BLE001  missing extra, missing weights, gated model: report, don't fail
                self._clf_error = f"{type(e).__name__}: {str(e)[:160]}"
                log.warning("local probe classifier unavailable: %s", self._clf_error)
        return self._clf

    def check(self, *, untrusted: str, user_context: str | None = None, path: str = "result.content",
              timeout_ms: int = 1500) -> GuardrailsResult:
        out = GuardrailsResult()
        content = untrusted[:MAX_CHARS]
        if not content.strip():
            return out
        t0 = time.perf_counter()
        score, hits = heuristic_score(content)
        out.scores["LOCAL_HEURISTIC"] = score
        if score >= self.threshold:
            out.findings.append(Finding(category="security.prompt_injection", severity="critical" if score >= 0.85 else "high",
                                        rule="local.injection_heuristic", detector="interlock.local_probe", path=path,
                                        score=score, subject=f"injection heuristics {score:.2f}: {', '.join(hits)}"))
        clf = self._classifier()
        if clf is not None:
            try:
                best = max(clf(content[:4000]), key=lambda r: r.get("score", 0.0))
                label = str(best.get("label", "")).upper()
                p = float(best["score"]) if label not in ("BENIGN", "LABEL_0", "SAFE") else 1.0 - float(best["score"])
                out.scores["LOCAL_CLASSIFIER"] = round(p, 3)
                if p >= self.classifier_threshold:
                    out.findings.append(Finding(category="security.prompt_injection", severity="critical" if p >= 0.95 else "high",
                                                rule="local.injection_classifier", detector=f"local:{self.classifier_model}",
                                                path=path, score=round(p, 3), subject=f"classifier P(injection)={p:.2f}"))
            except Exception as e:  # noqa: BLE001
                out.error = f"classifier: {type(e).__name__}: {str(e)[:120]}"
        elif self._clf_error:
            out.error = f"classifier: {self._clf_error}"
        out.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return out
