"""Memory poisoning: writes that persist into every future agent session.

Agent instruction files (CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, Copilot instructions, Kiro steering, ...) and
MCP memory servers are read back into the model's context in later sessions, so an agent that was tricked into
writing to them keeps an injected instruction alive indefinitely. Writing them is normal when the user asks, so:

  memory.instruction_file_write   any write to an instruction file is recorded (flag)
  memory.injected_instructions    the written content reads as instructions aimed at the agent (ask)
  flow.memory_poisoning           the session already took in untrusted content (see flow.py) (ask)
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from ..judges.local_probe import heuristic_score
from ..policy import Policy
from . import DetResult, rule

R_MEMORY_WRITE = rule("memory.instruction_file_write", "security.memory_poisoning", "medium", "flag")
R_MEMORY_INJECTED = rule("memory.injected_instructions", "security.memory_poisoning", "high", "ask")

INSTRUCTION_NAMES = ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
                     ".clinerules", "copilot-instructions.md", "CONVENTIONS.md")
INSTRUCTION_DIRS = ("/.kiro/steering/", "/.cursor/rules/", "/.github/instructions/", "/.clinerules/", "/.windsurf/rules/")
MEMORY_TOOLS = ("*memory*/create*", "*memory*/add*", "*memory*/save*", "*memory*/store*", "*memory*/update*",
                "*memory*/write*", "*memory*/remember*", "*/remember*", "*/save_memory*", "*/add_observations*")


def is_instruction_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name in INSTRUCTION_NAMES or any(d in path for d in INSTRUCTION_DIRS)


def is_memory_tool(target: str | None) -> bool:
    return bool(target) and any(fnmatchcase(target, p) for p in MEMORY_TOOLS)


def check_instruction_write(path: str, content: str | None, res: DetResult, policy: Policy, where: str) -> bool:
    """Record an instruction-file write and ask when its content reads as injected instructions. True if it matched."""
    if not is_instruction_file(path):
        return False
    res.add(policy, R_MEMORY_WRITE, path=where, subject=path)
    if content:
        score, hits = heuristic_score(content, assume_addressed=False)
        if score >= 0.6:
            res.add(policy, R_MEMORY_INJECTED, path="tool_call.arguments.content",
                    subject=f"{path}: content reads as instructions to the agent ({score:.2f}: {', '.join(hits[:4])})")
    res.normalized["memory_write"] = path
    return True
