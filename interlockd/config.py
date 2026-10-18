"""Daemon settings. M0: defaults plus an optional ~/.interlock/config.json; the policy YAML arrives in M1."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_LISTEN = "127.0.0.1:7391"
MAX_REQUEST_BYTES = 1_048_576

DEFAULT_PROTECTED = [".git/hooks/**", ".kiro/**", ".claude/**", ".codex/**", ".github/workflows/**", ".interlock/**"]
DEFAULT_SENSITIVE = [
    "~/.ssh/**", "~/.aws/**", "~/.config/gh/**", "~/.interlock/token", "**/.env", "**/.env.*", "**/*.pem",
    "**/id_rsa*", "**/id_ed25519*", "**/*.key",
]
DEFAULT_FAIL_MODE = {
    "security.data_exfiltration": "closed",
    "security.malicious_command": "closed",
    "security.persistence": "closed",
    "security.secret_leak.*": "closed",
    "security.privilege_escalation": "closed",
    "default": "open",
}


@dataclass
class Settings:
    home: Path = field(default_factory=lambda: Path(os.environ.get("INTERLOCK_HOME", "~/.interlock")).expanduser())
    listen: str = DEFAULT_LISTEN
    mode: str = "shadow"
    profile: str = "laptop"
    agent_id: str = ""
    workspace_roots: list[str] = field(default_factory=list)
    protected_paths: list[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED))
    sensitive_paths: list[str] = field(default_factory=lambda: list(DEFAULT_SENSITIVE))
    fail_mode: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_FAIL_MODE))
    kiro_sessions_dir: Path = field(default_factory=lambda: Path("~/.kiro/sessions").expanduser())
    user_messages_n: int = 3
    pre_timeout_ms: int = 1500
    post_timeout_ms: int = 2500
    dynamodb_table: str | None = None
    aws_region: str | None = None
    aws_profile: str | None = None
    otlp_endpoint: str | None = None               # e.g. http://localhost:4318/v1/traces (OpenTelemetry export)
    otlp_headers: dict[str, str] = field(default_factory=dict)

    @property
    def token_path(self) -> Path:
        return self.home / "token"

    @property
    def spool_dir(self) -> Path:
        return self.home / "spool"

    @property
    def config_path(self) -> Path:
        return self.home / "config.json"

    @classmethod
    def load(cls, home: Path | None = None) -> Settings:
        s = cls() if home is None else cls(home=Path(home).expanduser())
        if s.config_path.exists():
            data = json.loads(s.config_path.read_text())
            for k, v in data.items():
                if k == "kiro_sessions_dir":
                    v = Path(v).expanduser()
                if hasattr(s, k):
                    setattr(s, k, v)
        return s

    def host_port(self) -> tuple[str, int]:
        h, _, p = self.listen.rpartition(":")
        return h or "127.0.0.1", int(p)
