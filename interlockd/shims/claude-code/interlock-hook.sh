#!/bin/sh
# Interlock hook shim for JSON-on-stdin / JSON-on-stdout harnesses: Claude Code and Codex (PreToolUse/PostToolUse),
# Cursor (preToolUse/postToolUse), Gemini CLI (BeforeTool/AfterTool). POSIX sh + curl.
#
# The daemon normalizes the payload and renders the exact reply each harness applies (deny with a reason, a warning,
# or a replaced result), so this shim only forwards and prints. An empty daemon reply means "no opinion", which
# leaves the harness's own permission system in charge; Interlock never auto-approves. Cursor treats exit 0 with
# output that isn't valid permission JSON as a block, so for Cursor "no opinion" is a non-zero exit (fail-open).
#
# Also GitHub Copilot CLI, Windsurf (Cascade), and Antigravity CLI. Installers pass "pre" or "post" as $1 where the
# payload does not name its event (Copilot's camelCase form). Windsurf blocks with exit 2 and a message on stderr.
#
# Install writes HARNESS into the copied shim: claude-code | codex | cursor | gemini-cli | copilot-cli | windsurf | antigravity.

HARNESS="__HARNESS__"
HOME_DIR="${INTERLOCK_HOME:-$HOME/.interlock}"
PRE_TIMEOUT="${INTERLOCK_PRE_TIMEOUT_MS:-1500}"
POST_TIMEOUT="${INTERLOCK_POST_TIMEOUT_MS:-2500}"
VERSION="0.1.2"

log_local() {
  mkdir -p "$HOME_DIR" 2>/dev/null
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$HOME_DIR/hook.log" 2>/dev/null
}

payload=$(cat)
[ -n "$payload" ] || exit 0
is_post=0
EVENT="$1"
case "$HARNESS" in
  cursor)     case "$payload" in *'postToolUse'*|*'afterShellExecution'*|*'afterMCPExecution'*) is_post=1 ;; esac ;;
  gemini-cli) case "$payload" in *'AfterTool'*) is_post=1 ;; esac ;;
  windsurf)   case "$payload" in *'"agent_action_name":"post_'*|*'"agent_action_name": "post_'*) is_post=1 ;; esac ;;
  *)          case "$payload" in *PostToolUse*|*postToolUse*) is_post=1 ;; esac ;;
esac
case "$EVENT" in post) is_post=1 ;; pre) is_post=0 ;; esac
EVENT=pre; [ "$is_post" = 1 ] && EVENT=post
timeout_ms=$PRE_TIMEOUT; [ "$is_post" = 1 ] && timeout_ms=$POST_TIMEOUT

no_opinion() { # leave the decision to the harness
  if [ "$HARNESS" = cursor ] && [ "$is_post" = 0 ]; then exit 1; fi
  if [ "$HARNESS" = antigravity ]; then   # a pre-tool decision is required; post-tool hooks return {}
    if [ "$is_post" = 0 ]; then printf '{"decision":"allow"}\n'; else printf '{}\n'; fi
  fi
  exit 0
}

token=""; [ -r "$HOME_DIR/token" ] && read -r token < "$HOME_DIR/token"
if [ -z "$token" ]; then log_local "inert: no token at $HOME_DIR/token"; no_opinion; fi
if [ -n "$INTERLOCK_URL" ]; then base="${INTERLOCK_URL%/}"
else
  listen=""
  if [ -r "$HOME_DIR/daemon.json" ]; then
    read -r line < "$HOME_DIR/daemon.json"
    case "$line" in *'"listen": "'*) listen=${line#*'"listen": "'}; listen=${listen%%\"*} ;; esac
  fi
  base="http://${listen:-127.0.0.1:7391}"
fi

FORMAT=claude-code; case "$HARNESS" in cursor|gemini-cli|copilot-cli|antigravity) FORMAT=$HARNESS ;; windsurf) FORMAT=text ;; esac
secs=$(( timeout_ms / 1000 )).$(( (timeout_ms % 1000) / 100 ))
# prefer the daemon's Unix socket (mode 0600: only this user can connect) unless a URL was given explicitly
sock=""; [ -z "$INTERLOCK_URL" ] && [ -S "$HOME_DIR/interlockd.sock" ] && sock="$HOME_DIR/interlockd.sock"
if [ -n "$sock" ]; then base="http://localhost"; set -- --unix-socket "$sock"; else set --; fi
reply=$(printf '{"adapter":{"name":"%s","version":"%s","event":"%s"},"payload":%s}' "$HARNESS" "$VERSION" "$EVENT" "$payload" | \
  curl -sf -m "$secs" "$@" -H "authorization: Bearer $token" -H "content-type: application/json" \
    --data-binary @- "$base/interlock/v1/hooks/$HARNESS?format=$FORMAT" 2>/dev/null)
rc=$?

if [ $rc -ne 0 ]; then
  mode=open
  case "$INTERLOCK_FAIL_MODE" in open|closed) mode=$INTERLOCK_FAIL_MODE ;; *)
    [ -r "$HOME_DIR/fail-mode.json" ] && grep -q '"default": *"closed"' "$HOME_DIR/fail-mode.json" && mode=closed ;;
  esac
  case "$payload" in
    *'"tool_name":"'*)  tool=${payload#*'"tool_name":"'} ;;
    *'"tool_name": "'*) tool=${payload#*'"tool_name": "'} ;;
    *) tool="?" ;;
  esac
  tool=${tool%%\"*}
  kind=pre; [ "$is_post" = 1 ] && kind=post
  log_local "unjudged harness=$HARNESS tool=$tool kind=$kind curl_rc=$rc fail_mode=$mode"
  if [ "$is_post" = 0 ] && [ "$mode" = "closed" ]; then
    msg='[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace fails closed. Start it with `interlock start`, then retry.'
    case "$HARNESS" in
      cursor)     printf '{"permission":"deny","agent_message":"%s","user_message":"Interlock daemon unreachable (fail closed)"}\n' "$msg" ;;
      gemini-cli|antigravity) printf '{"decision":"deny","reason":"%s"}\n' "$msg" ;;
      copilot-cli) printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' "$msg" ;;
      windsurf)   printf '%s\n' "$msg" >&2; exit 2 ;;
      *)          printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$msg" ;;
    esac
    exit 0
  fi
  no_opinion
fi

# Windsurf: the daemon replies in text form ("<disposition> <mode> <tier>" then the notice); block via exit 2
if [ "$HARNESS" = windsurf ]; then
  first=${reply%%
*}
  set -- $first
  if [ "$2" = enforce ] && { [ "$1" = block ] || [ "$1" = ask ]; }; then
    printf '%s\n' "${reply#*
}" >&2
    exit 2
  fi
  exit 0
fi

# the daemon's reply is the hook's stdout; empty means no opinion
[ -n "$reply" ] || no_opinion
printf '%s\n' "$reply"
exit 0
