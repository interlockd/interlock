"""Policy: the YAML document in .interlock/policy.yaml (design §6), validated by pydantic, with defaults.

Resolution: built-in defaults <- ~/.interlock/policy.yaml (user) <- <workspace>/.interlock/policy.yaml.
Lists are replaced, mappings are merged one level deep, which is enough for `packs.overrides` and `trust`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

RuleAction = Literal["block", "ask", "flag", "allow", "model"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Trust(Strict):
    workspace_roots: list[str] = Field(default_factory=list)
    protected_paths: list[str] = Field(default_factory=lambda: [
        ".git/hooks/**", ".kiro/**", ".claude/**", ".codex/**", ".github/workflows/**", ".interlock/**",
    ])
    sensitive_paths: list[str] = Field(default_factory=lambda: [
        "~/.ssh/**", "~/.aws/**", "~/.config/gh/**", "~/.interlock/token", "~/.netrc", "~/.npmrc", "~/.pypirc",
        "~/.docker/config.json", "~/.kube/config", "**/.env", "**/.env.*", "**/*.pem", "**/id_rsa*", "**/id_ed25519*",
        "**/*.key", "**/credentials", "**/credentials.json", "**/serviceAccountKey.json",
    ])
    allowed_hosts: list[str] = Field(default_factory=lambda: [
        "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com",
        "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crates.io", "static.crates.io", "proxy.golang.org",
        "sum.golang.org", "repo.maven.apache.org", "localhost", "127.0.0.1",
    ])
    allowed_git_remotes: list[str] = Field(default_factory=list)
    protected_branches: list[str] = Field(default_factory=lambda: ["main", "master", "release/*", "prod", "production"])
    declared_packages_only: bool = True
    allowed_package_indexes: list[str] = Field(default_factory=lambda: [
        "https://pypi.org/simple", "https://registry.npmjs.org", "https://registry.yarnpkg.com",
    ])


class RuleOverride(Strict):
    action: RuleAction | None = None
    enabled: bool = True
    questions: list[str] = Field(default_factory=list)


class Packs(Strict):
    enabled: list[str] = Field(default_factory=lambda: ["shell", "git", "egress", "persistence", "secrets", "packages"])
    overrides: dict[str, RuleOverride] = Field(default_factory=dict)


class Mandate(Strict):
    cedar: str | None = None                  # path to a .cedar file, relative to the policy file
    mode: Literal["off", "log_only", "enforce"] = "off"
    inline: str | None = None                 # Cedar text, for tests and small policies


class JudgeBackend(Strict):
    type: Literal["strands_decider", "replay", "none"] = "none"
    transport: Literal["http", "sagemaker"] = "http"
    base_url: str = "http://127.0.0.1:8000"
    checkpoint: str = "StrandsAgents/strands-decider-2B-hobson-v21"
    sagemaker_endpoint: str | None = None
    timeout_ms: int = 700
    local_command: list[str] = Field(default_factory=list)   # daemon starts and supervises the server when set


class LocalProbeConfig(Strict):
    """Vendor-neutral injection detector (judges/local_probe.py): heuristics always, a classifier when configured."""
    enabled: bool = True
    threshold: float = 0.6
    classifier_model: str | None = None       # e.g. meta-llama/Llama-Prompt-Guard-2-86M; needs the `promptguard` extra
    classifier_threshold: float = 0.8


class ProbeConfig(Strict):
    enabled: bool = False                     # Amazon Bedrock Guardrails (needs AWS); the local detector is `local`
    local: LocalProbeConfig = Field(default_factory=LocalProbeConfig)
    prompt_attack: list[str] = Field(default_factory=lambda: ["PROMPT_INJECTION", "JAILBREAK"])
    entities: list[str] = Field(default_factory=lambda: ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PASSWORD"])
    injection_threshold: float = 0.6
    timeout_ms: int = 1500


class Bands(Strict):
    """Thresholds on judge answers (design §4.7). Wide ask band until recalibration on the M3 corpus."""
    intent_block_below: float = 0.20      # intent_authorized below this, with harm >= harm_block_min -> block
    harm_block_min: int = 2
    intent_ask_below: float = 0.65        # intent_authorized below this -> ask
    intent_allow_at: float = 0.65
    exfil_ask_at: float = 0.50
    confirm_allow_at: float = 0.80        # harnesses without a native ask: the user's confirmation in the transcript, judged
    injection_warn_at: float = 0.50       # post-action: Decider injection_present or Guardrails severity
    injection_withhold_at: float = 0.90
    max_intent_state_tokens: int = 1000
    max_untrusted_tokens: int = 3000


class Judge(Strict):
    primary: JudgeBackend = Field(default_factory=JudgeBackend)
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    bands: Bands = Field(default_factory=Bands)
    ask_intent_for_model_rules: bool = True     # rules routed to `model` consult the judge when a backend is configured


class DenialBudget(Strict):
    consecutive: int = 3
    total: int = 20
    then: Literal["ask", "block"] = "ask"


class TestThresholds(Strict):
    """Gates for `interlock test` (the deterministic corpus runner).

    FPR = benign cases wrongly escalated/blocked; FNR = attack cases wrongly allowed.
    `categories` overrides the global gate per OGR category (longest-prefix match), e.g.
    `security.malicious_command: {max_fnr: 0.0}` to forbid any miss on malicious commands.
    """
    max_fpr: float = 0.01
    max_fnr: float = 0.10
    categories: dict[str, dict[str, float]] = Field(default_factory=dict)


class Policy(Strict):
    version: int = 1
    workspace: str = ""
    mode: Literal["shadow", "enforce"] = "shadow"
    profile: Literal["laptop", "team"] = "laptop"
    trust: Trust = Field(default_factory=Trust)
    packs: Packs = Field(default_factory=Packs)
    mandate: Mandate = Field(default_factory=Mandate)
    denial_budget: DenialBudget = Field(default_factory=DenialBudget)
    judge: Judge = Field(default_factory=Judge)
    tests: TestThresholds = Field(default_factory=TestThresholds)
    fail_mode: dict[str, str] = Field(default_factory=lambda: {
        "security.data_exfiltration": "closed", "security.malicious_command": "closed", "security.persistence": "closed",
        "security.secret_leak.*": "closed", "security.privilege_escalation": "closed", "default": "open",
    })
    source_paths: list[str] = Field(default_factory=list)   # filled by the loader, not user-set
    sha256: str = ""                                          # filled by the loader

    def rule_action(self, rule_id: str, default: RuleAction) -> RuleAction | None:
        """None means the rule is disabled."""
        ov = self.packs.overrides.get(rule_id)
        if ov is None:
            return default
        if not ov.enabled:
            return None
        return ov.action or default


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out


def load_policy(workspace_root: str | Path | None, home: Path | None = None) -> Policy:
    layers: list[tuple[Path, dict[str, Any]]] = []
    candidates = []
    if home is not None:
        candidates.append(Path(home).expanduser() / "policy.yaml")
    if workspace_root is not None:
        candidates.append(Path(workspace_root).expanduser() / ".interlock" / "policy.yaml")
    merged: dict[str, Any] = {}
    for p in candidates:
        if p.exists():
            data = yaml.safe_load(p.read_text()) or {}
            if not isinstance(data, dict):
                raise ValueError(f"{p}: policy must be a mapping")
            data.pop("source_paths", None)
            data.pop("sha256", None)
            layers.append((p, data))
            merged = _merge(merged, data)
    pol = Policy.model_validate(merged)
    pol.source_paths = [str(p) for p, _ in layers]
    if pol.mandate.cedar and layers:
        base_dir = layers[-1][0].parent
        pol.mandate.cedar = str((base_dir / pol.mandate.cedar).resolve())
    h = hashlib.sha256()
    h.update(pol.model_dump_json(exclude={"source_paths", "sha256"}).encode())
    if pol.mandate.cedar and Path(pol.mandate.cedar).exists():
        h.update(Path(pol.mandate.cedar).read_bytes())
    pol.sha256 = h.hexdigest()
    return pol
