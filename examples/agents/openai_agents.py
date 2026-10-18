"""OpenAI Agents SDK with Interlock: guard_agent_tools() adds native tool guardrails."""

import subprocess

from agents import Agent, Runner, function_tool

from interlockd.integrations.openai_agents import guard_agent_tools


@function_tool
def shell(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60, check=False).stdout


agent = guard_agent_tools(Agent(name="dev", tools=[shell]))
print(Runner.run_sync(agent, "Show the git status of this repository.").final_output)
