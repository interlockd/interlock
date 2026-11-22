// Interlock plugin for OpenCode (https://opencode.ai/docs/plugins/). Installed by `interlock init` into
// ~/.config/opencode/plugins/. Asks the local Interlock daemon about every tool call before it runs and
// throws to refuse it (OpenCode's documented way to block); checks tool results afterwards (record-only:
// replacing a result is not documented). No dependencies; runs on OpenCode's own runtime.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const VERSION = "__VERSION__";
const HOME = process.env.INTERLOCK_HOME || join(homedir(), ".interlock");

function read(p) { try { return readFileSync(join(HOME, p), "utf8"); } catch { return ""; } }

function base() {
  if (process.env.INTERLOCK_URL) return process.env.INTERLOCK_URL.replace(/\/$/, "");
  try { return `http://${JSON.parse(read("daemon.json")).listen || "127.0.0.1:7391"}`; } catch { return "http://127.0.0.1:7391"; }
}

function failsClosed() {
  const env = process.env.INTERLOCK_FAIL_MODE;
  if (env === "open" || env === "closed") return env === "closed";
  try { return JSON.parse(read("fail-mode.json")).default === "closed"; } catch { return false; }
}

async function decide(kind, tool, args, cwd, session, content) {
  const token = read("token").trim();
  if (!token) return null;
  const event = {
    kind, adapter: { name: "opencode", version: VERSION }, session_hint: session || null,
    identity: { agent_type: "opencode" }, tool_call: { name: String(tool || ""), arguments: args || {} },
    context: { cwd: cwd || process.cwd() }, capabilities: { ask: false, rewrite: false, withhold: false },
  };
  if (content !== undefined) event.result = { content: String(content).slice(0, 200000) };
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), kind === "pre_action" ? 1500 : 2500);
  try {
    const r = await fetch(`${base()}/interlock/v1/decide`, {
      method: "POST", signal: ctl.signal, body: JSON.stringify(event),
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    });
    return r.ok ? await r.json() : null;
  } catch { return null; } finally { clearTimeout(timer); }
}

export const Interlock = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    const v = await decide("pre_action", input.tool, output.args, directory, input.sessionID);
    if (v === null) {
      if (failsClosed()) throw new Error("[interlock] This action was NOT executed: the Interlock daemon is unreachable and this machine fails closed.");
      return;
    }
    if (v.mode === "enforce" && (v.disposition === "block" || v.disposition === "ask")) {
      throw new Error(v.notice || `[interlock] refused: ${v.reason || "policy"}`);
    }
  },
  "tool.execute.after": async (input, output) => {
    const text = typeof output?.output === "string" ? output.output : JSON.stringify(output?.output ?? output?.result ?? "");
    await decide("post_action", input.tool, output?.args || {}, directory, input.sessionID, text);
  },
});
