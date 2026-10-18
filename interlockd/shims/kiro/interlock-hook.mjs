#!/usr/bin/env node
// Interlock hook shim for Kiro (PreToolUse and PostToolUse). Zero dependencies, Node >= 18.
//
// Reads the hook event from stdin, posts it to the local daemon, and renders the verdict in Kiro's
// vocabulary (adapters/kiro/PAYLOADS.md §5): exit 0 = allow, exit 2 + stderr = block. Kiro has no
// hook-driven "ask", so an ask renders as a block whose notice asks the agent to confirm with the user.
// PostToolUse is record-only on Kiro: always exit 0. If the daemon does not answer, the configured
// fail mode decides (default open) and the miss is logged locally.

import { readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

const VERSION = "0.1.0";
const HOME = process.env.INTERLOCK_HOME || path.join(homedir(), ".interlock");
const BASE = (process.env.INTERLOCK_URL || readListen() || "http://127.0.0.1:7391").replace(/\/$/, "");
const PRE_TIMEOUT_MS = Number(process.env.INTERLOCK_PRE_TIMEOUT_MS || 1500);
const POST_TIMEOUT_MS = Number(process.env.INTERLOCK_POST_TIMEOUT_MS || 2500);

function readListen() {
  try {
    const d = JSON.parse(readFileSync(path.join(HOME, "daemon.json"), "utf8"));
    return d.listen ? `http://${d.listen}` : null;
  } catch { return null; }
}

function logLocal(line) {
  try {
    mkdirSync(HOME, { recursive: true });
    appendFileSync(path.join(HOME, "hook.log"), `${new Date().toISOString()} ${line}\n`);
  } catch { /* never let logging break the hook */ }
}

function failMode() {
  // M0: no finding categories are known at the shim, so the table's default applies.
  const env = process.env.INTERLOCK_FAIL_MODE;
  if (env === "open" || env === "closed") return env;
  try {
    const t = JSON.parse(readFileSync(path.join(HOME, "fail-mode.json"), "utf8"));
    return t.default === "closed" ? "closed" : "open";
  } catch { return "open"; }
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function block(notice) {
  process.stderr.write(notice.endsWith("\n") ? notice : notice + "\n");
  process.exit(2);
}

async function main() {
  const raw = await readStdin();
  let payload;
  try { payload = JSON.parse(raw); } catch { logLocal("skip: stdin was not JSON"); process.exit(0); }
  const isPost = String(payload.hook_event_name || "").toLowerCase() === "posttooluse";
  const timeout = isPost ? POST_TIMEOUT_MS : PRE_TIMEOUT_MS;

  let token;
  try { token = readFileSync(path.join(HOME, "token"), "utf8").trim(); }
  catch { logLocal("inert: no token at " + path.join(HOME, "token")); process.exit(0); }

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  let verdict;
  try {
    const res = await fetch(`${BASE}/interlock/v1/hooks/kiro`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ adapter: { name: "kiro", version: VERSION }, payload }),
      signal: ctl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    verdict = await res.json();
  } catch (e) {
    clearTimeout(timer);
    const mode = failMode();
    logLocal(`unjudged tool=${payload.tool_name} kind=${isPost ? "post" : "pre"} reason=${e.name === "AbortError" ? "timeout" : e.message} fail_mode=${mode}`);
    if (!isPost && mode === "closed") {
      block("[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace fails closed. Start it with `interlock serve`, then retry.");
    }
    process.exit(0);
  }
  clearTimeout(timer);

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
