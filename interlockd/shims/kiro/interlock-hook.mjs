#!/usr/bin/env node
// Interlock hook shim for Kiro (PreToolUse and PostToolUse). Zero dependencies, Node >= 18.
//
// Reads the hook event from stdin, posts it to the local daemon, and renders the verdict in Kiro's
// vocabulary (adapters/kiro/PAYLOADS.md §5): exit 0 = allow, exit 2 + stderr = block. Kiro has no
// hook-driven "ask", so an ask renders as a block whose notice asks the agent to confirm with the user.
// PostToolUse is record-only on Kiro: always exit 0.
//
// A reply is applied only when it carries exactly one X-Interlock-Identity header equal to <Home>/identity (this
// home's daemon). A token rejection (401/403), a missing or wrong identity, and an unreachable daemon with no
// operator Stop_Marker are tamper causes and use fail_mode.tamper (default closed); other unjudged calls use
// fail_mode.default (default open). INTERLOCK_FAIL_MODE=closed forces both closed; other values are ignored.
// Every miss is logged to <Home>/hook.log without the token, the identity value or the tool's arguments.

import { readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = "0.2.0";
const HOME = process.env.INTERLOCK_HOME || path.join(homedir(), ".interlock");
const MAX_STATE_BYTES = 64 * 1024;
const LISTEN = readListen();
const BASE = (process.env.INTERLOCK_URL || LISTEN.url || "http://127.0.0.1:7391").replace(/\/$/, "");
const PRE_TIMEOUT_MS = Number(process.env.INTERLOCK_PRE_TIMEOUT_MS || 1500);
const POST_TIMEOUT_MS = Number(process.env.INTERLOCK_POST_TIMEOUT_MS || 2500);

function readHomeFile(name) {
  // null when absent, unreadable or above the state-file size limit (Requirement 12.4: treated as absent)
  try {
    const text = readFileSync(path.join(HOME, name), "utf8");
    return Buffer.byteLength(text, "utf8") > MAX_STATE_BYTES ? null : text;
  } catch { return null; }
}

function readJson(name) {
  const text = readHomeFile(name);
  if (text === null) return null;
  try {
    const doc = JSON.parse(text);
    return doc && typeof doc === "object" && !Array.isArray(doc) ? doc : null;
  } catch { return null; }
}

function readListen() {
  const text = readHomeFile("daemon.json");
  if (text === null) return { present: false, url: null };
  try {
    const d = JSON.parse(text);
    return { present: true, url: d && d.listen ? `http://${d.listen}` : null };
  } catch { return { present: true, url: null }; }
}

function logLocal(line) {
  try {
    mkdirSync(HOME, { recursive: true });
    appendFileSync(path.join(HOME, "hook.log"), `${new Date().toISOString()} ${line}\n`);
    return true;
  } catch { return false; } // never let logging break the hook
}

function failModes() {
  // fail_mode.default (open unless "closed") and fail_mode.tamper (closed unless "open"); env can only tighten
  const t = readJson("fail-mode.json") || {};
  const modes = { default: t.default === "closed" ? "closed" : "open", tamper: t.tamper === "open" ? "open" : "closed" };
  if (process.env.INTERLOCK_FAIL_MODE === "closed") { modes.default = "closed"; modes.tamper = "closed"; }
  return modes;
}

function stopMarker() {
  // the operator's Stop_Marker: "operator_stopped" (no expiry), "restarting" (expiry in the future), or null
  const m = readJson("stop-marker.json");
  if (!m || typeof m.action !== "string" || !m.action || typeof m.written_at !== "string" || !m.written_at) return null;
  if (!("expires_epoch" in m)) return "operator_stopped";
  if (!Number.isInteger(m.expires_epoch)) return null;
  return Date.now() / 1000 < m.expires_epoch ? "restarting" : null;
}

const MESSAGES = {
  token_rejected: () => `[interlock] This action was NOT executed: the process at ${BASE} rejected this hook's token (token_rejected). Run \`interlock doctor\`.`,
  daemon_identity: () => `[interlock] This action was NOT executed: the process answering at ${BASE} is not this home's Interlock daemon (daemon_identity). Run \`interlock doctor\`.`,
  daemon_lost: () => `[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly (daemon_lost). Home: ${HOME}. Run \`interlock doctor\`, then \`interlock start\`.`,
};
const UNREACHABLE = "[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace fails closed. Start it with `interlock start`, then retry.";

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function block(notice) {
  process.stderr.write(notice.endsWith("\n") ? notice : notice + "\n");
  process.exit(2);
}

function unjudged(payload, isPost, outcome) {
  // outcome: {cause, status} for a tamper cause, {why} otherwise. Logs one line, then refuses or stays silent.
  const modes = failModes();
  const mode = outcome.cause ? modes.tamper : modes.default;
  const tool = String(payload.tool_name || "?").split(/\s/)[0] || "?";
  const common = `harness=kiro tool=${tool} kind=${isPost ? "post" : "pre"} addr=${BASE}`;
  const line = outcome.cause
    ? `tamper ${outcome.cause} ${common} status=${outcome.status ?? "-"} fail_mode=${mode}`
    : `unjudged why=${outcome.why} ${common} fail_mode=${mode}`;
  if (!logLocal(line)) process.stderr.write(`[interlock] could not write ${path.join(HOME, "hook.log")}\n`);
  if (!isPost && mode === "closed") block(outcome.cause ? MESSAGES[outcome.cause]() : UNREACHABLE);
  process.exit(0);
}

function whenUnreachable() {
  const marker = stopMarker();
  return marker ? { why: marker } : { cause: "daemon_lost" };
}

async function main() {
  const raw = await readStdin();
  let payload;
  try { payload = JSON.parse(raw); } catch { logLocal("skip: stdin was not JSON"); process.exit(0); }
  if (!payload || typeof payload !== "object") { logLocal("skip: stdin was not JSON"); process.exit(0); }
  const isPost = String(payload.hook_event_name || "").toLowerCase() === "posttooluse";
  const timeout = isPost ? POST_TIMEOUT_MS : PRE_TIMEOUT_MS;

  let token;
  try { token = readFileSync(path.join(HOME, "token"), "utf8").trim(); }
  catch { logLocal("inert: no token at " + path.join(HOME, "token")); process.exit(0); }
  if (!token) { logLocal("inert: no token at " + path.join(HOME, "token")); process.exit(0); }
  const want = (readHomeFile("identity") || "").trim();

  // no daemon.json and no explicit URL: no daemon is serving this home
  if (!process.env.INTERLOCK_URL && !LISTEN.present) unjudged(payload, isPost, whenUnreachable());

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  let res, text;
  try {
    res = await fetch(`${BASE}/interlock/v1/hooks/kiro`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ adapter: { name: "kiro", version: VERSION, shim: fileURLToPath(import.meta.url) }, payload }),
      signal: ctl.signal,
      redirect: "manual",
    });
    text = await res.text();
  } catch {
    clearTimeout(timer);
    unjudged(payload, isPost, whenUnreachable()); // refused, reset or timed out
  }
  clearTimeout(timer);

  if (res.status === 401 || res.status === 403) unjudged(payload, isPost, { cause: "token_rejected", status: res.status });
  if (res.status >= 400) unjudged(payload, isPost, { why: `http_${res.status}` });
  // Headers.get joins repeated headers with ", ", so a duplicated identity fails the equality check
  const got = res.headers.get("x-interlock-identity");
  if (!want || got !== want) unjudged(payload, isPost, { cause: "daemon_identity", status: res.status });
  if (!res.ok) unjudged(payload, isPost, { why: `http_${res.status}` });
  let verdict;
  try { verdict = JSON.parse(text); } catch { verdict = null; }
  if (!verdict || typeof verdict !== "object") unjudged(payload, isPost, { why: "bad_reply" });

  if (isPost) process.exit(0); // record-only on Kiro
  if (verdict.mode === "shadow") process.exit(0); // shadow: decided and recorded, never enforced

  if (verdict.disposition === "block") {
    block(verdict.notice || `[interlock] This action was refused by a security policy and was NOT executed. Reason: ${verdict.reason || "policy"}. You may pursue the user's goal by other legitimate means, but you MUST NOT retry this action in a disguised form.`);
  }
  if (verdict.disposition === "ask") {
    block(verdict.notice || `[interlock] This action was NOT executed because it needs the user's confirmation. Reason: ${verdict.reason || "policy"}. Ask the user whether to proceed, and only retry after they confirm.`);
  }
  process.exit(0);
}

main().catch((e) => { logLocal(`shim error: ${e && e.message}`); process.exit(0); });
