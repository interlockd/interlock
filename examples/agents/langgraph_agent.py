"""LangGraph with Interlock: wrap the tools with guard_tools()."""

import subprocess

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from interlockd.integrations.langchain import guard_tools


@tool
def shell(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60, check=False).stdout


agent = create_react_agent(ChatOpenAI(model="gpt-5"), guard_tools([shell]))
print(agent.invoke({"messages": [("user", "Show the git status of this repository.")]})["messages"][-1].content)
