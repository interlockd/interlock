"""Google ADK with Interlock: guard_agent() adds before/after tool callbacks."""

import subprocess

from google.adk.agents import LlmAgent

from interlockd.integrations.google_adk import guard_agent


def shell(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60, check=False).stdout


root_agent = guard_agent(LlmAgent(name="dev", model="gemini-2.5-flash", tools=[shell]))   # run with `adk run`
