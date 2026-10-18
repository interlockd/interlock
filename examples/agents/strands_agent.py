"""Strands Agents with Interlock: one line, `hooks=[InterlockHooks()]`."""

import subprocess

from strands import Agent, tool

from interlockd.integrations.strands import InterlockHooks


@tool
def shell(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60, check=False).stdout


agent = Agent(tools=[shell], hooks=[InterlockHooks()])
agent("Show the git status of this repository.")
