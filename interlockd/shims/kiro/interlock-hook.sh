#!/bin/sh
# Interlock hook shim for Kiro (PreToolUse and PostToolUse). POSIX sh + curl, nothing else.
#
# Hot path is two forks (cat for stdin, curl for the request); everything else is shell builtins, because
# each fork costs 5-10 ms on macOS. Measured on an M4 Pro: ~30 ms end to end for a tier-0 call, against
# ~108 ms for the Node shim (whose startup alone is ~79 ms). The daemon answers shims in text:
#   line 1: "<disposition> <mode> <tier>"    following lines: the notice or reason
# Kiro vocabulary (adapters/kiro/PAYLOADS.md §5): exit 0 = allow, exit 2 + stderr = block. Kiro has no
# hook-driven "ask", so ask renders as a block whose notice asks the agent to confirm with the user.
# PostToolUse is record-only on Kiro: always exit 0. No answer from the daemon -> fail mode (default open).

HOME_DIR="${INTERLOCK_HOME:-$HOME/.interlock}"
PRE_TIMEOUT="${INTERLOCK_PRE_TIMEOUT_MS:-1500}"
POST_TIMEOUT="${INTERLOCK_POST_TIMEOUT_MS:-2500}"
VERSION="0.1.1"
nl='
'

log_local() {  # failure path only; forks are fine here
  mkdir -p "$HOME_DIR" 2>/dev/null
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$HOME_DIR/hook.log" 2>/dev/null
}

payload=$(cat)
[ -n "$payload" ] || exit 0
case "$payload" in
  *PostToolUse*|*postToolUse*) is_post=1; timeout_ms=$POST_TIMEOUT ;;
  *)                           is_post=0; timeout_ms=$PRE_TIMEOUT ;;
esac

# token and daemon address with builtins only
token=""; [ -r "$HOME_DIR/token" ] && read -r token < "$HOME_DIR/token"
if [ -z "$token" ]; then log_local "inert: no token at $HOME_DIR/token"; exit 0; fi
if [ -n "$INTERLOCK_URL" ]; then base="${INTERLOCK_URL%/}"
else
  listen=""
  if [ -r "$HOME_DIR/daemon.json" ]; then
    read -r line < "$HOME_DIR/daemon.json"
    case "$line" in *'"listen": "'*) listen=${line#*'"listen": "'}; listen=${listen%%\"*} ;; esac
  fi
  base="http://${listen:-127.0.0.1:7391}"
fi

secs=$(( timeout_ms / 1000 )).$(( (timeout_ms % 1000) / 100 ))
verdict=$(printf '{"adapter":{"name":"kiro","version":"%s"},"payload":%s}' "$VERSION" "$payload" | \
  curl -sf -m "$secs" -H "authorization: Bearer $token" -H "content-type: application/json" \
    --data-binary @- "$base/interlock/v1/hooks/kiro?format=text" 2>/dev/null)
rc=$?

if [ $rc -ne 0 ] || [ -z "$verdict" ]; then
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
  log_local "unjudged tool=$tool kind=$kind curl_rc=$rc fail_mode=$mode"
  if [ "$is_post" = 0 ] && [ "$mode" = "closed" ]; then
    printf '[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace fails closed. Start it with `interlock serve`, then retry.\n' >&2
    exit 2
  fi
  exit 0
fi

[ "$is_post" = 1 ] && exit 0                       # record-only on Kiro
first=${verdict%%"$nl"*}
notice=${verdict#*"$nl"}; [ "$notice" = "$verdict" ] && notice=""
set -- $first                                      # disposition mode tier
disposition=$1; mode=$2
[ "$mode" = "shadow" ] && exit 0                   # decided and recorded, never enforced
case "$disposition" in
  block|ask)
    [ -n "$notice" ] || notice="[interlock] This action was refused by a security policy and was NOT executed. You may pursue the user's goal by other legitimate means, but you MUST NOT retry this action in a disguised form."
    printf '%s\n' "$notice" >&2
    exit 2 ;;
esac
exit 0
