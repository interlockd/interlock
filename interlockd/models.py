"""Wire and audit models. Field names follow phase1-design.md §5.1 and §7."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Kind = Literal["pre_action", "post_action"]
Disposition = Literal["allow", "ask", "block", "pass", "warn", "withhold"]
Mode = Literal["shadow", "enforce"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AdapterInfo(Strict):
    name: str
    version: str = "0"


class Identity(Strict):
    agent_id: str = ""
    agent_type: str = ""
    agent_workspace: str = ""
    agent_user: str = ""


class ToolCall(Strict):
    id: str | None = None
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class UserMessage(Strict):
    n: int
    text: str


class Context(Strict):
    cwd: str | None = None
    user_messages: list[UserMessage] | None = None
    prior_tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    mcp_server: dict[str, Any] | None = None
    permission_mode: str | None = None
    transcript_path: str | None = None   # harness transcript the daemon may read for user messages


class ToolResult(Strict):
    content: str
    truncated: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)


class Capabilities(Strict):
    ask: bool = False
    rewrite: bool = False
    withhold: bool = False


class InterlockEvent(Strict):
    kind: Kind
    adapter: AdapterInfo
    identity: Identity = Field(default_factory=Identity)
    session_hint: str | None = None
    tool_call: ToolCall
    context: Context = Field(default_factory=Context)
    result: ToolResult | None = None
    capabilities: Capabilities = Field(default_factory=Capabilities)


class Finding(Strict):
    category: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    rule: str | None = None
    detector: str
    path: str | None = None
    start: int | None = None
    end: int | None = None
    score: float = 1.0
    subject: str | None = None
    whitelisted: bool = False


class Verdict(Strict):
    event_id: str
    disposition: Disposition
    reason: str | None = None
    notice: str | None = None
    updated_arguments: dict[str, Any] | None = None
    findings: list[Finding] = Field(default_factory=list)
    unjudged: list[str] = Field(default_factory=list)
    mode: Mode
    tier: int
    action_class: str
    timing_ms: dict[str, float] = Field(default_factory=dict)
    explanation_pending: bool = False
