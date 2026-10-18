# Interlock in your own agents

Each file is the smallest working setup for one framework. They need the framework installed and its model
credentials; Interlock itself needs `interlock init` (or `interlock start`) so the local daemon is running.

| File | Framework | Install |
|---|---|---|
| `claude_agent_sdk_agent.py` | Claude Agent SDK | `pip install 'interlockd[claude-agent-sdk]'` |
| `strands_agent.py` | Strands Agents | `pip install 'interlockd[strands]'` |
| `langgraph_agent.py` | LangChain / LangGraph | `pip install 'interlockd[langchain]' langgraph langchain-openai` |
| `openai_agents.py` | OpenAI Agents SDK | `pip install 'interlockd[openai-agents]'` |
| `google_adk_agent.py` | Google ADK | `pip install 'interlockd[google-adk]'` |
| `crewai_crew.py` | CrewAI | `pip install 'interlockd[crewai]'` |
| `semantic_kernel_agent.py` | Semantic Kernel | `pip install 'interlockd[semantic-kernel]'` |

In every case a refused tool call never runs (the model receives Interlock's notice instead), and a tool result
that carries injected instructions is replaced before the model reads it. Decisions show up in `interlock log`.
