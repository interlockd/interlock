"""CrewAI with Interlock: install() once, before building crews; every crew in the process is covered."""

import subprocess

from crewai import Agent, Crew, Task
from crewai.tools import tool

from interlockd.integrations import crewai as interlock

interlock.install()


@tool("shell")
def shell(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60, check=False).stdout


dev = Agent(role="developer", goal="Report repository state", backstory="Careful engineer.", tools=[shell])
task = Task(description="Show the git status of this repository.", expected_output="The status.", agent=dev)
print(Crew(agents=[dev], tasks=[task]).kickoff())
