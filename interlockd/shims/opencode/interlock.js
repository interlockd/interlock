// Interlock plugin for OpenCode (https://opencode.ai/docs/plugins/). Installed by `interlock init` into
// ~/.config/opencode/plugins/. Asks the local Interlock daemon about every tool call before it runs and
// throws to refuse it (OpenCode's documented way to block); checks tool results afterwards (record-only:
// replacing a result is not documented). No dependencies; runs on OpenCode's own runtime.
//
// A reply is applied only when it carries an X-Interlock-Identity header equal to <Home>/identity (written by this
// home's daemon at start); any other process answering on the address is not trusted. When a call cannot be judged
// the outcome is classified:
//   tamper token_rejected   the process at the address answered 401/403 to this home's token
//   tamper daemon_identity  a reply without, with several, or with a wrong identity header
//   tamper daemon_lost      the daemon is unreachable and no valid <Home>/stop-marker.json explains it
//   unjudged <why>          an operator stop or restart (stop marker), another HTTP error, a malformed verdict
// Tamper causes use fail-mode.json's `tamper` (closed when missing or invalid), the others its `default`;
// INTERLOCK_FAIL_MODE=closed tightens both and no other value loosens either. Each outcome appends one line to
// <Home>/hook.log (no token, identity value or tool arguments). A refusal throws; "no opinion" returns.
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = "__VERSION__";
const HOME = process.env.INTERLOCK_HOME || join(homedir(), ".interlock");
const MAX_STATE_BYTES = 64 * 1024;     // a larger state file is treated as absent
const TAMPER_CAUSES = new Set(["token_rejected", "daemon_identity", "daemon_lost", "enforcement_point"]);
const UNREACHABLE = "[interlock] This action was NOT executed: the Interlock daemon is unreachable and this machine fails closed.";
let SHIM = "";
try { SHIM = fileURLToPath(import.meta.url); } catch { SHIM = ""; }

function read(p) {
  try {
    const buf = readFileSync(join(HOME, p));
    return buf.length > MAX_STATE_BYTES ? "" : buf.toString("utf8");
  } catch { return ""; }
}

function parse(text) {
  try { const v = JSON.parse(text); return v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; }
}

function listen(daemonJson) {
  const doc = parse(daemonJson);
  return doc && typeof doc.listen === "string" && doc.listen ? doc.listen : "127.0.0.1:7391";
}

function failMode(cause) {
  if (process.env.INTERLOCK_FAIL_MODE === "closed") return "closed";
  const doc = parse(read("fail-mode.json")) || {};
  if (TAMPER_CAUSES.has(cause)) return doc.tamper === "open" ? "open" : "closed";
  return doc.default === "closed" ? "closed" : "open";
}

// "operator_stopped" (valid marker without expiry), "restarting" (expires_epoch later than now) or null.
function markerState(now) {
  const m = parse(read("stop-marker.json"));
  if (!m || typeof m.action !== "string" || !m.action || typeof m.written_at !== "string" || !m.written_at) return null;
  if (!("expires_epoch" in m) && !("expires_at" in m)) return "operator_stopped";
  return Number.isInteger(m.expires_epoch) && now < m.expires_epoch ? "restarting" : null;
}

function tamperMessage(cause, addr) {
  if (cause === "token_rejected") {
    return `[interlock] This action was NOT executed: the process at ${addr} rejected this hook's token (token_rejected). Run \`interlock doctor\`.`;
  }
  if (cause === "daemon_identity") {
    return `[interlock] This action was NOT executed: the process answering at ${addr} is not this home's Interlock daemon (daemon_identity). Run \`interlock doctor\`.`;
  }
  return `[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly (daemon_lost). Home: ${HOME}. Run \`interlock doctor\`, then \`interlock start\`.`;
}

function word(s) { const w = String(s ?? "").replace(/\s+/g, "_").slice(0, 128); return w || "?"; }

function logLocal(line) {
  try {
    mkdirSync(HOME, { recursive: true });
    appendFileSync(join(HOME, "hook.log"), `${new Date().toISOString().replace(/\.\d+Z$/, "Z")} ${line}\n`);
    return true;
  } catch { return false; }
}

// {outcome: "apply", verdict} | {outcome: "tamper", cause, status, addr} | {outcome: "unjudged", why, addr} | {outcome: "inert"}
async function decide(kind, tool, args, cwd, session, content) {
  const token = read("token").trim();
  if (!token) return { outcome: "inert" };
  const url = process.env.INTERLOCK_URL;
  const daemonJson = read("daemon.json");
  const addr = url ? url.replace(/\/$/, "") : `http://${listen(daemonJson)}`;
  const adapter = { name: "opencode", version: VERSION };
  if (SHIM) adapter.shim = SHIM;
  const event = {
    kind, adapter, session_hint: session || null,
    identity: { agent_type: "opencode" }, tool_call: { name: String(tool || ""), arguments: args || {} },
    context: { cwd: cwd || process.cwd() }, capabilities: { ask: false, rewrite: false, withhold: false },
  };
  if (content !== undefined) event.result = { content: String(content).slice(0, 200000) };
  let res = null, text = "";
  if (url || daemonJson) {               // no daemon.json: no daemon has been started for this home
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), kind === "pre_action" ? 1500 : 2500);
    try {
      res = await fetch(`${addr}/interlock/v1/decide`, {
        method: "POST", signal: ctl.signal, body: JSON.stringify(event),
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      });
      text = await res.text();
    } catch { res = null; } finally { clearTimeout(timer); }
  }
  if (res === null) {
    const state = markerState(Math.floor(Date.now() / 1000));
    return state ? { outcome: "unjudged", why: state, addr } : { outcome: "tamper", cause: "daemon_lost", status: "-", addr };
  }
  if (res.status === 401 || res.status === 403) return { outcome: "tamper", cause: "token_rejected", status: res.status, addr };
  if (res.status >= 400) return { outcome: "unjudged", why: `http_${res.status}`, addr };
  const want = read("identity").trim();
  if (!/^[0-9a-f]{32}$/.test(want) || res.headers.get("x-interlock-identity") !== want) {
    return { outcome: "tamper", cause: "daemon_identity", status: res.status, addr };
  }
  if (!res.ok) return { outcome: "unjudged", why: `http_${res.status}`, addr };
  const verdict = parse(text);
  return verdict ? { outcome: "apply", verdict } : { outcome: "unjudged", why: "bad_reply", addr };
}

// A call that could not be judged: log it, then refuse (pre-tool, closed) or give no opinion.
function unjudgedOrTamper(r, kind, tool) {
  if (r.outcome === "inert") { logLocal(`inert: no token at ${join(HOME, "token")}`); return; }
  const ctx = `harness=opencode tool=${word(tool)} kind=${kind} addr=${word(r.addr)}`;
  if (r.outcome === "unjudged") {
    const mode = failMode(r.why);
    logLocal(`unjudged why=${r.why} ${ctx} fail_mode=${mode}`);
    if (kind === "pre" && mode === "closed") throw new Error(UNREACHABLE);
    return;
  }
  const mode = failMode(r.cause);
  if (!logLocal(`tamper ${r.cause} ${ctx} status=${r.status} fail_mode=${mode}`)) {
    try { process.stderr.write(`[interlock] could not write ${join(HOME, "hook.log")}\n`); } catch { /* nothing left to report to */ }
  }
  if (kind === "pre" && mode === "closed") throw new Error(tamperMessage(r.cause, r.addr));
}

export const Interlock = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    const r = await decide("pre_action", input.tool, output.args, directory, input.sessionID);
    if (r.outcome !== "apply") return unjudgedOrTamper(r, "pre", input.tool);
    const v = r.verdict;
    if (v.mode === "enforce" && (v.disposition === "block" || v.disposition === "ask")) {
      throw new Error(v.notice || `[interlock] refused: ${v.reason || "policy"}`);
    }
  },
  "tool.execute.after": async (input, output) => {
    const text = typeof output?.output === "string" ? output.output : JSON.stringify(output?.output ?? output?.result ?? "");
    const r = await decide("post_action", input.tool, output?.args || {}, directory, input.sessionID, text);
    if (r.outcome !== "apply") unjudgedOrTamper(r, "post", input.tool);   // post-tool: log only, never throws
  },
});
