"""Repository checks for `interlock scan`: a project's own agent configuration, prompt files and agent code.

  agent.*   Claude Code project settings: hooks the repository ships (they run on every developer's machine once the
            project is trusted), allow rules that hand out shell interpreters, network or writes anywhere, hooks
            switched off, literal secrets in `env`.
  prompt.*  Prompts and instruction files (CLAUDE.md, AGENTS.md, .cursor/rules, Kiro steering, .claude/commands,
            .claude/agents, skills) and system prompts written in agent code: literal secrets, instructions that switch
            off confirmations or safety checks, and templates that interpolate untrusted input into the instructions.
  code.*    Python / TypeScript agent code (Strands, LangGraph / LangChain, OpenAI Agents SDK, CrewAI) that gives its
            tools shell, file-write or network access without going through Interlock.

Static and read-only: nothing is imported or executed, secret values are never shown. Pattern matching on source text,
not data flow: a tool built from a helper in another module, or a prompt assembled at run time, is not seen.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .det.packs import PLACEHOLDER, SECRET_PATTERNS
from .scan import Finding, _is_secret_value, _load

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "dist", "build", "__pycache__", "site-packages", ".tox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", "target", "vendor", ".idea"}
CODE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".mts", ".cts"}
MAX_FILES = 3000
MAX_BYTES = 512 * 1024


def _walk(project: Path):
    """Files of the project, skipping dependency and build directories; at most MAX_FILES."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(project):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d not in (
            ".claude", ".cursor", ".kiro", ".github", ".windsurf", ".clinerules")))
        for name in sorted(filenames):
            n += 1
            if n > MAX_FILES:
                return
            yield Path(dirpath) / name


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# ------------------------------------------------------------------------------------------------ prompt lint

# Instructions that switch off the agent's (or the developer's) safety net. Negated forms ("never skip the checks",
# "do not commit with --no-verify", "never act without asking for confirmation") say the opposite and are excluded.
SAFETY_OFF = [re.compile(p, re.IGNORECASE) for p in (
    (r"\b(?:skip|bypass|disable|ignore|turn off|switch off|circumvent|get around)\s+(?:all\s+|any\s+|the\s+|every\s+)?"
           r"(?:safety|security|guard[- ]?rails?|permission|approval|confirmation|sandbox(?:ing)?|pre-commit|interlock|"
           r"(?:git\s+)?hooks?)(?:\s+(?:checks?|prompts?|warnings?|rules?|policy|policies|hooks?))?\b"),
    r"\bwithout\s+(?:asking|waiting)\s+for\s+(?:confirmation|permission|approval)\b",
    r"(?:^|\s)--(?:no-verify|dangerously-skip-permissions|yolo)\b",
    r"\bbypassPermissions\b",
)]
# "never ask for confirmation" carries its own negation; only a negation before it would flip it
SAFETY_OFF_NEGATIVE_FORM = re.compile(
    r"\b(?:never|don'?t|do not)\s+(?:ask|wait|prompt)\s+(?:the user\s+)?(?:for\s+)?(?:confirmation|permission|approval)\b",
    re.IGNORECASE)
_NEGATION = re.compile(r"\b(?:not|never|no|avoid|without|forbidden|prohibited|must not|n't)\b|n't\b", re.IGNORECASE)


def _negated(text: str, start: int) -> bool:
    """A negation earlier in the same sentence (within 60 characters) turns the instruction around."""
    before = re.split(r"[.!?\n]", text[max(0, start - 60):start])[-1]
    return bool(_NEGATION.search(before))
# Names of template variables that carry text the agent's author does not control.
UNTRUSTED_NAMES = {"user", "input", "query", "question", "request", "message", "msg", "messages", "content", "document",
                   "doc", "docs", "page", "html", "email", "mail", "body", "text", "payload", "result", "results",
                   "output", "response", "search", "web", "url", "file", "ticket", "issue", "comment", "comments",
                   "review", "transcript", "chat", "context", "retrieved", "observation"}


def lint_prompt(text: str) -> list[tuple[str, str, str]]:
    """(severity, rule, message) for one prompt or instruction text. Interpolation is checked separately (code only)."""
    out: list[tuple[str, str, str]] = []
    for kind, pat in SECRET_PATTERNS:
        m = pat.search(text)
        if m and (kind in ("private_key", "aws_access_key", "github_token", "slack_token") or not PLACEHOLDER.search(m.group(0))):
            out.append(("high", "prompt.inline_secret", f"holds a literal secret ({kind}); value not shown"))
            break
    hit = next((m for pat in SAFETY_OFF for m in pat.finditer(text) if not _negated(text, m.start())), None)
    if hit is None:
        hit = next((m for m in SAFETY_OFF_NEGATIVE_FORM.finditer(text) if not _negated(text, m.start())), None)
    if hit is not None:
        out.append(("medium", "prompt.disables_safety",
                    f"tells the agent to switch off a safety check (\"{hit.group(0).strip()[:60]}\")"))
    return out


def _untrusted_placeholders(names: list[str]) -> list[str]:
    hits = []
    for n in names:
        tokens = {t.lower() for t in re.split(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])", n) if t}
        if tokens & UNTRUSTED_NAMES:
            hits.append(n)
    return hits


# ------------------------------------------------------------------------------------------------ prompt files

PROMPT_FILE_DIRS = ("/.claude/commands/", "/.claude/agents/", "/.claude/skills/", "/.github/prompts/",
                    "/.github/chatmodes/")


def check_prompt_files(project: Path) -> list[Finding]:
    """Instruction and prompt files committed to the repository, linted for secrets and safety-off instructions.
    (Injected instructions and hidden Unicode in them are scan.check_instruction_files.)"""
    from .det.memory import is_instruction_file

    out: list[Finding] = []
    for path in _walk(project):
        rel = "/" + path.relative_to(project).as_posix()
        prompt_dir = any(d in rel.lower() for d in PROMPT_FILE_DIRS) and path.suffix.lower() in (".md", ".mdc", ".txt")
        if not (prompt_dir or is_instruction_file(rel)):
            continue
        text = _read(path)
        if not text:
            continue
        for sev, rule, msg in lint_prompt(text):
            out.append(Finding(sev, rule, "repo", str(path), msg, _PROMPT_FIX[rule], str(path)))
    return out


_PROMPT_FIX = {
    "prompt.inline_secret": "remove the secret from the prompt and rotate it; give the agent a tool that reads it from the environment",
    "prompt.disables_safety": "remove the instruction; if a check is noisy, tune it in policy instead of telling the agent to skip it",
    "prompt.untrusted_interpolation": "keep untrusted text out of the instructions: pass it as a separate user message or tool result, delimited and labelled as data",
}


# ------------------------------------------------------------------------------------------------ Claude Code project settings

RISKY_ALLOW = {
    "shell interpreter": re.compile(r"^Bash\((?:bash|sh|zsh|python3?|node|ruby|perl|eval|exec|env|xargs)(?::\*|\s\*|\*)?\)$"),
    "network": re.compile(r"^(?:WebFetch|Bash\((?:curl|wget|nc|ncat|ssh|scp)(?::\*|\s\*|\*)\))$"),
    "destructive or privileged": re.compile(r"^Bash\((?:rm|sudo|git push|chmod|dd)(?::\*|\s\*|\*)\)$"),
    "writes anywhere": re.compile(r"^(?:Write|Edit|MultiEdit)(?:\((?:\*|\*\*|/\*\*|~/\*\*|//\*\*)\))?$"),
}


def _hook_commands(hooks: Any) -> list[tuple[str, str]]:
    """(event, command) for each command hook in a Claude Code `hooks` block."""
    out = []
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                if isinstance(h, dict) and isinstance(h.get("command"), str):
                    out.append((str(event), h["command"]))
    return out


def check_claude_project(home: Path, project: Path) -> list[Finding]:
    from .det.shellparse import parse

    out: list[Finding] = []
    for path, in_repo in ((home / ".claude" / "settings.json", False), (project / ".claude" / "settings.json", True),
                          (project / ".claude" / "settings.local.json", True)):
        d = _load(path) if path.is_file() else None
        if not isinstance(d, dict):
            continue

        def add(sev, rule, msg, fix, _p=path):
            out.append(Finding(sev, rule, "claude-code", str(_p), msg, fix, str(_p)))

        if d.get("disableAllHooks") is True:
            add("high", "agent.hooks_disabled", "disableAllHooks is true: no hook runs, Interlock's included",
                "remove disableAllHooks")
        for k, v in (d.get("env") or {}).items() if isinstance(d.get("env"), dict) else []:
            kind = _is_secret_value(str(k), str(v))
            if kind:
                add("high", "agent.inline_secret", f"env.{k} holds a literal secret ({kind}); value not shown",
                    "keep secrets out of settings files; use apiKeyHelper or the shell environment")
        perms = d.get("permissions") if isinstance(d.get("permissions"), dict) else {}
        for entry in perms.get("allow") or []:
            what = next((label for label, pat in RISKY_ALLOW.items() if isinstance(entry, str) and pat.match(entry)), None)
            if what:
                add("medium", "agent.risky_allow", f"permissions.allow contains {entry}: {what} without asking",
                    "allow the specific commands or domains the project needs")
        for extra in perms.get("additionalDirectories") or []:
            if str(extra).rstrip("/") in ("", "~", "$HOME", str(home)) or str(extra) == "/":
                add("medium", "agent.broad_directories", f"additionalDirectories gives the agent {extra}",
                    "add only the directories the project needs")
        if not in_repo:
            continue
        for event, cmd in _hook_commands(d.get("hooks")):
            if "interlock" in cmd:
                continue                                       # Interlock's own hook
            parsed = parse(cmd)
            fetches = [c for c in parsed.commands() if os.path.basename(c) in ("curl", "wget", "nc", "ncat", "socat")]
            if parsed.piped_to_shell or parsed.decode_exec:
                add("high", "agent.risky_hook", f"{event} hook runs downloaded or decoded code: {cmd[:80]}",
                    "remove the hook; a repository should not run fetched code on contributors' machines")
            elif fetches:
                add("medium", "agent.risky_hook", f"{event} hook reaches the network ({fetches[0]}): {cmd[:80]}",
                    "review the hook; keep network calls out of repository hooks")
            else:
                add("low", "agent.project_hook", f"the repository ships a {event} hook: {cmd[:80]}",
                    "review it: it runs on every machine that trusts this project")
    return out


# ------------------------------------------------------------------------------------------------ agent code

FRAMEWORKS_PY = [
    ("strands", re.compile(r"^\s*(?:from|import)\s+strands(?:_tools)?\b", re.MULTILINE)),
    ("langgraph", re.compile(r"^\s*(?:from|import)\s+(?:langgraph|langchain\w*)\b", re.MULTILINE)),
    ("openai-agents", re.compile(r"^\s*from\s+agents(?:\.\w+)*\s+import\b", re.MULTILINE)),
    ("crewai", re.compile(r"^\s*(?:from|import)\s+crewai(?:_tools)?\b", re.MULTILINE)),
]
FRAMEWORKS_TS = [
    ("strands", re.compile(r"""(?:from\s+|require\(\s*)['"]@strands-agents/""")),
    ("langgraph", re.compile(r"""(?:from\s+|require\(\s*)['"](?:@langchain/|langchain\b)""")),
    ("openai-agents", re.compile(r"""(?:from\s+|require\(\s*)['"]@openai/agents""")),
    ("crewai", re.compile(r"""(?:from\s+|require\(\s*)['"]crewai""")),
]
GATE_PY = re.compile(r"^\s*(?:from|import)\s+interlockd\b", re.MULTILINE)
GATE_TS = re.compile(r"""(?:from\s+|require\(\s*)['"]@interlockd/sdk""")
TOOL_DEF_PY = re.compile(r"@(?:\w+\.)?(?:tool|function_tool)\b|\bBaseTool\b|\bStructuredTool\b|\bFunctionTool\b|\btools\s*=\s*\[")
TOOL_DEF_TS = re.compile(r"\btool\s*\(|\btools\s*:\s*\[|\bnew\s+\w*Tool\s*\(|\bDynamicStructuredTool\b")
# capability -> (severity, patterns); prebuilt tools of the frameworks first, then the raw calls a custom tool makes
CAPS_PY = {
    "shell": ("high", re.compile(
        r"\bsubprocess\.(?:run|call|check_call|check_output|Popen|getoutput)\b|\bos\.(?:system|popen|exec\w*|spawn\w*)\s*\(|"
        r"\bpty\.spawn\b|\b(?:ShellTool|PythonREPLTool|PythonAstREPLTool|BashProcess|CodeInterpreterTool|LocalShellTool|"
        r"ComputerTool)\b|\bstrands_tools\b[^\n]*\b(?:shell|python_repl|use_computer)\b")),
    "file write": ("medium", re.compile(
        r"""\bopen\([^)\n]*['"][wax]\+?b?['"]|\.write_(?:text|bytes)\(|\bshutil\.(?:rmtree|move|copy\w*)\(|"""
        r"""\bos\.(?:remove|unlink|rename|replace)\(|\b(?:FileManagementToolkit|WriteFileTool|DeleteFileTool|"""
        r"""MoveFileTool|FileWriterTool)\b|\bstrands_tools\b[^\n]*\b(?:file_write|editor)\b""")),
    "network": ("medium", re.compile(
        r"\brequests\.(?:get|post|put|patch|delete|request)\(|\bhttpx\.(?:get|post|put|patch|delete|request|Client|AsyncClient)\b|"
        r"\burllib\.request\b|\baiohttp\.ClientSession\b|\b(?:RequestsToolkit|RequestsGetTool|RequestsPostTool|"
        r"ScrapeWebsiteTool|SerperDevTool)\b|\bstrands_tools\b[^\n]*\bhttp_request\b")),
}
CAPS_TS = {
    "shell": ("high", re.compile(r"""\bchild_process\b|\b(?:execSync|execFileSync|spawnSync)\s*\(|\bBun\.(?:spawn|\$)|\bexeca\b""")),
    "file write": ("medium", re.compile(r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|rmSync|unlinkSync|renameSync)\s*\(|"
                                        r"\bfs(?:\.promises)?\.(?:rm|unlink|rename)\s*\(")),
    "network": ("medium", re.compile(r"\bfetch\s*\(|\baxios\b|\bgot\s*\(|\bhttps?\.request\s*\(")),
}

# system prompts written in code: the keyword, then a string literal (f-strings and template literals included)
PROMPT_PY = re.compile(
    r"""\b(?P<key>(?i:system_prompt|instructions|system_message|system|backstory|goal|role|prompt))\s*=\s*"""
    r"""(?P<f>[fF]?)[rR]?(?P<lit>\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')(?P<fmt>\s*\.format\()?"""
    r"""|\bSystemMessage\(\s*(?:content\s*=\s*)?(?P<f2>[fF]?)[rR]?(?P<lit2>\"\"\"[\s\S]*?\"\"\"|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"""
    r"""|["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*(?P<f3>[fF]?)(?P<lit3>\"\"\"[\s\S]*?\"\"\"|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"""
    r"""|\(\s*["']system["']\s*,\s*[fF]?(?P<lit4>\"\"\"[\s\S]*?\"\"\"|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')\s*\)""")
# keys whose plain "{name}" placeholders are filled in by the framework (CrewAI inputs, LangChain prompt templates)
_TEMPLATE_KEYS = {"crewai": {"role", "goal", "backstory", "description", "expected_output"}}
PROMPT_TS = re.compile(
    r"""\b(?P<key>instructions|systemPrompt|system_prompt|system|systemMessage)\s*[:=]\s*(?P<lit>`(?:[^`\\]|\\.)*`|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"""
    r"""|role\s*:\s*["']system["']\s*,\s*content\s*:\s*(?P<lit3>`(?:[^`\\]|\\.)*`|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')""")
LLM_SDK_PY = re.compile(r"^\s*(?:from|import)\s+(?:openai|anthropic|google\.genai|litellm|mistralai)\b", re.MULTILINE)
LLM_SDK_TS = re.compile(r"""(?:from\s+|require\(\s*)['"](?:openai|@anthropic-ai/sdk|@google/genai|ai)['"]""")
# the prompt keywords that are too generic outside an agent constructor need an f-string/format to be considered
_WEAK_KEYS = {"role", "goal", "prompt", "system"}


def _prompt_findings(text: str, ts: bool, path: Path, agent: str) -> list[Finding]:
    out: list[Finding] = []
    for m in (PROMPT_TS if ts else PROMPT_PY).finditer(text):
        lit = m.group("lit") or m.group("lit3") or (None if ts else m.group("lit2") or m.group("lit4"))
        if not lit:
            continue
        key = (m.group("key") or "system").lower()
        line = _line_of(text, m.start())
        body = lit.strip("`\"'")
        for sev, rule, msg in lint_prompt(body):
            out.append(Finding(sev, rule, agent, str(path), f"system prompt ({key}) {msg}", _PROMPT_FIX[rule], str(path), line))
        if ts:
            names = re.findall(r"\$\{\s*([\w.]+)", lit) if lit.startswith("`") else []
        else:
            templated = bool(m.group("f") or m.group("f2") or m.group("f3") or m.group("fmt") or m.group("lit4")
                             or key in _TEMPLATE_KEYS.get(agent, ()))
            names = re.findall(r"(?<!\{)\{\s*([A-Za-z_][\w.]*)", lit) if templated else []
        if key in _WEAK_KEYS and not names:
            continue
        hits = _untrusted_placeholders(names)
        if hits:
            out.append(Finding("medium", "prompt.untrusted_interpolation", agent, str(path),
                               f"system prompt ({key}) interpolates {', '.join(hits[:3])} into the instructions",
                               _PROMPT_FIX["prompt.untrusted_interpolation"], str(path), line))
    return out


def check_agent_code(project: Path) -> list[Finding]:
    files: list[tuple[Path, str, bool]] = []
    gated_anywhere = False
    for path in _walk(project):
        if path.suffix not in CODE_SUFFIXES:
            continue
        text = _read(path)
        if not text:
            continue
        ts = path.suffix != ".py"
        if (GATE_TS if ts else GATE_PY).search(text):
            gated_anywhere = True
        files.append((path, text, ts))
    out: list[Finding] = []
    for path, text, ts in files:
        agent = next((name for name, pat in (FRAMEWORKS_TS if ts else FRAMEWORKS_PY) if pat.search(text)), None)
        if agent is None:
            if (LLM_SDK_TS if ts else LLM_SDK_PY).search(text):
                out += _prompt_findings(text, ts, path, "llm-sdk")
            continue
        out += _prompt_findings(text, ts, path, agent)
        if (GATE_TS if ts else GATE_PY).search(text) or not (TOOL_DEF_TS if ts else TOOL_DEF_PY).search(text):
            continue
        for cap, (sev, pat) in (CAPS_TS if ts else CAPS_PY).items():
            m = pat.search(text)
            if not m:
                continue
            fix = ("wrap the tools with the Interlock integration (see the user guide, Custom agents)"
                   if not gated_anywhere else "route these tools through the Interlock integration the project already uses")
            msg = f"{agent} tools get {cap} access ({m.group(0).strip()[:40]}) and no Interlock gate in this file"
            if gated_anywhere:
                msg += "; the project imports Interlock elsewhere"
            out.append(Finding("low" if gated_anywhere else sev, f"code.ungated_{cap.replace(' ', '_')}_tool", agent,
                               str(path), msg, fix, str(path), _line_of(text, m.start())))
    return out


def check_repository(home: Path, project: Path) -> list[Finding]:
    return check_claude_project(home, project) + check_prompt_files(project) + check_agent_code(project)
