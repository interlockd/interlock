# @interlockd/sdk

Interlock for JavaScript and TypeScript agents: every tool call is checked before it runs, and every tool result
before the model reads it, by the local Interlock daemon, with the same policy and audit log as the agent hooks.
No dependencies; Node 18+.

```sh
pipx install interlockd && interlock init      # the daemon (once per machine)
npm install @interlockd/sdk
```

## Vercel AI SDK, Mastra, or any `{ name: { execute } }` tool map

```js
import { generateText, tool } from "ai";
import { guardTools } from "@interlockd/sdk";

const tools = guardTools({ shell: tool({ description: "Run a command", inputSchema, execute: runShell }) });
await generateText({ model, tools, prompt });
```

A refused call never runs: the model receives Interlock's notice as the tool result. A result carrying injected
instructions is replaced before the model reads it. Verified with `ai` 7.0 (a real `generateText` loop).

## Claude Agent SDK (TypeScript)

```js
import { query } from "@anthropic-ai/claude-agent-sdk";
import { guardOptions } from "@interlockd/sdk";

for await (const m of query({ prompt, options: guardOptions({ allowedTools: ["Bash", "Read"] }) })) { ... }
```

`guardOptions` adds PreToolUse / PostToolUse hooks and keeps yours. Verified live with
`@anthropic-ai/claude-agent-sdk` 0.3 (a refused force-push, a withheld injected README).

## Anything else

```js
import { InterlockClient, guardExecute } from "@interlockd/sdk";
const safeRun = guardExecute("shell", runShell);           // same signature, guarded
const v = await new InterlockClient().decide("pre_action", "shell", { command: "rm -rf build" });
```

The client reads the token and daemon address from `~/.interlock` (or `INTERLOCK_HOME`, `INTERLOCK_URL`). With the
daemon unreachable, calls run unless the fail mode is closed (`INTERLOCK_FAIL_MODE=closed`).

License: Apache-2.0.
