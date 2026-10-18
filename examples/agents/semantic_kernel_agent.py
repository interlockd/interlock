"""Semantic Kernel with Interlock: guard_kernel() adds a function-invocation filter."""

import asyncio
import subprocess

from semantic_kernel import Kernel
from semantic_kernel.connectors.ai.function_choice_behavior import FunctionChoiceBehavior
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion, OpenAIChatPromptExecutionSettings
from semantic_kernel.functions import KernelArguments, kernel_function

from interlockd.integrations.semantic_kernel import guard_kernel


class Dev:
    @kernel_function(name="shell", description="Run a shell command and return its output.")
    def shell(self, command: str) -> str:
        return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60, check=False).stdout


kernel = guard_kernel(Kernel())
kernel.add_service(OpenAIChatCompletion(ai_model_id="gpt-5"))
kernel.add_plugin(Dev(), plugin_name="dev")
settings = OpenAIChatPromptExecutionSettings(function_choice_behavior=FunctionChoiceBehavior.Auto())
print(asyncio.run(kernel.invoke_prompt("Show the git status of this repository.", arguments=KernelArguments(settings=settings))))
