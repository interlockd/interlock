"""Claude Agent SDK with Interlock: guard_options() adds PreToolUse / PostToolUse hooks."""

import asyncio

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from interlockd.integrations.claude_agent_sdk import guard_options

options = guard_options(ClaudeAgentOptions(allowed_tools=["Bash", "Read"]))


async def main():
    async for message in query(prompt="Show the git status of this repository.", options=options):
        if isinstance(message, ResultMessage):
            print(message.result)


asyncio.run(main())
