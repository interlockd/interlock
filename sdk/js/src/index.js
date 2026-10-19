// Interlock for JavaScript and TypeScript agents. No dependencies; Node 18+ (global fetch).
//
//   import { guardTools } from "@interlockd/sdk";             // Vercel AI SDK, Mastra, any { name: { execute } } map
//   const tools = guardTools({ shell, readFile });
//
//   import { guardOptions } from "@interlockd/sdk";           // Claude Agent SDK (TypeScript)
//   for await (const m of query({ prompt, options: guardOptions({ allowedTools: ["Bash"] }) })) { ... }
//
// Every call is decided by the local Interlock daemon (`interlock init` or `interlock start`), with the same policy
// and audit log as the agent hooks. A refused call never runs: the model receives Interlock's notice as the tool
// result. A result carrying injected instructions is replaced before the model reads it. With the daemon
// unreachable, calls run unless the fail mode is closed (INTERLOCK_FAIL_MODE=closed or ~/.interlock/fail-mode.json).

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const VERSION = "0.1.1";
export const UNREACHABLE =
  "[interlock] This action was NOT executed: the Interlock daemon is unreachable and this machine fails closed.";

function read(path) {
  try { return readFileSync(path, "utf8"); } catch { return null; }
}

export class InterlockClient {
  constructor({ home, url, token, agentType = "js-sdk", session, timeoutMs = 1500 } = {}) {
    this.home = home || process.env.INTERLOCK_HOME || join(homedir(), ".interlock");
    this._url = url || process.env.INTERLOCK_URL || null;
    this._token = token ?? null;
    this.agentType = agentType;
    this.session = session || null;
    this.timeoutMs = timeoutMs;
  }

  get url() {
    if (this._url) return this._url.replace(/\/$/, "");
    let listen = "127.0.0.1:7391";
    try { listen = JSON.parse(read(join(this.home, "daemon.json")) || "{}").listen || listen; } catch {}
    return `http://${listen}`;
  }

  get token() {
    if (this._token === null) this._token = (read(join(this.home, "token")) || "").trim();
    return this._token;
  }

  failsClosed() {
    const env = process.env.INTERLOCK_FAIL_MODE;
    if (env === "open" || env === "closed") return env === "closed";
    try { return JSON.parse(read(join(this.home, "fail-mode.json")) || "{}").default === "closed"; } catch { return false; }
  }

  async _post(path, body, timeoutMs) {
    if (!this.token) return null;
    try {
      const r = await fetch(this.url + path, {
        method: "POST",
        headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!r.ok) return null;
      const text = await r.text();
      return text.trim() ? JSON.parse(text) : {};
    } catch {
      return null;                                   // unreachable daemon: the caller applies the fail mode
    }
  }

  /** The daemon's verdict, or null when it can't be reached. */
  decide(kind, tool, args = {}, { content, session, cwd, withhold = true } = {}) {
    const event = {
      kind, adapter: { name: this.agentType, version: VERSION },
      session_hint: session || this.session, identity: { agent_type: this.agentType },
      tool_call: { name: String(tool), arguments: args && typeof args === "object" && !Array.isArray(args) ? args : { value: args } },
      context: { cwd: cwd || process.cwd() }, capabilities: { ask: false, rewrite: false, withhold },
    };
    if (content !== undefined) event.result = { content: String(content).slice(0, 200_000) };
    return this._post("/interlock/v1/decide", event, kind === "pre_action" ? this.timeoutMs : this.timeoutMs + 1000);
  }

  static stops(v) { return !!v && v.mode === "enforce" && (v.disposition === "block" || v.disposition === "ask"); }
  static withholds(v) { return !!v && v.mode === "enforce" && v.disposition === "withhold"; }
}

function asText(value) {
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

/**
 * Wrap one tool's execute function. `execute(args, ...rest)` keeps its signature; a refused call returns Interlock's
 * notice instead of running, and an injected result is replaced by the notice.
 */
export function guardExecute(name, execute, client = new InterlockClient(), { session } = {}) {
  const wrapped = async function (args, ...rest) {
    const v = await client.decide("pre_action", name, args, { session });
    if (v === null && client.failsClosed()) return UNREACHABLE;
    if (InterlockClient.stops(v)) return v.notice || `[interlock] refused: ${v.reason}`;
    const result = await execute.call(this, args, ...rest);
    const text = asText(result);
    if (text && text.trim()) {
      const p = await client.decide("post_action", name, args, { content: text, session });
      if (InterlockClient.withholds(p)) return p.notice || "[interlock] tool result withheld";
    }
    return result;
  };
  wrapped.__interlock = true;
  return wrapped;
}

/**
 * Guard a tool map ({ name: { execute, ... } }): the Vercel AI SDK `tools` object, Mastra tools, and similar.
 * Returns a new map; tools without `execute` (client-side tools) are passed through. Idempotent.
 */
export function guardTools(tools, client = new InterlockClient({ agentType: "js-sdk" }), opts = {}) {
  const out = {};
  for (const [name, t] of Object.entries(tools || {})) {
    if (!t || typeof t.execute !== "function" || t.execute.__interlock) { out[name] = t; continue; }
    out[name] = { ...t, execute: guardExecute(t.id || name, t.execute, client, opts) };
  }
  return out;
}

// ---- Claude Agent SDK (TypeScript) ------------------------------------------------------------------------------

const SDK_ROUTE = "/interlock/v1/hooks/claude-agent-sdk?format=claude-code";

/**
 * PreToolUse / PostToolUse hook callbacks for the Claude Agent SDK. Its hooks receive the same payloads as Claude
 * Code's command hooks, so the daemon replies with the hook output Claude Code applies (deny with a reason, or a
 * replaced tool result).
 */
export function interlockHooks(client = new InterlockClient({ agentType: "claude-agent-sdk" })) {
  const call = (event) => async (input) => {
    const body = { adapter: { name: "claude-agent-sdk", version: VERSION, event }, payload: input };
    const out = await client._post(SDK_ROUTE, body, event === "pre" ? client.timeoutMs : client.timeoutMs + 1000);
    if (out === null && event === "pre" && client.failsClosed()) {
      return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: UNREACHABLE } };
    }
    return out || {};
  };
  const pre = call("pre"); pre.__interlock = true;
  const post = call("post"); post.__interlock = true;
  return { PreToolUse: [{ hooks: [pre] }], PostToolUse: [{ hooks: [post] }] };
}

/** Add Interlock's hooks to Claude Agent SDK options, keeping yours (Interlock runs first). Idempotent. */
export function guardOptions(options = {}, client) {
  const ours = interlockHooks(client);
  const hooks = { ...(options.hooks || {}) };
  for (const [event, matchers] of Object.entries(ours)) {
    const existing = hooks[event] || [];
    const has = existing.some((m) => (m.hooks || []).some((h) => h.__interlock));
    hooks[event] = has ? existing : [...matchers, ...existing];
  }
  return { ...options, hooks };
}
