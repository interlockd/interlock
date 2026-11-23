#!/bin/sh
# Interlock hook shim for JSON-on-stdin / JSON-on-stdout harnesses: Claude Code and Codex (PreToolUse/PostToolUse),
# Cursor (preToolUse/postToolUse), Gemini CLI (BeforeTool/AfterTool). POSIX sh + curl (+ date on failure paths).
#
# The daemon normalizes the payload and renders the exact reply each harness applies (deny with a reason, a warning,
# or a replaced result), so this shim only forwards and prints. An empty daemon reply means "no opinion", which
# leaves the harness's own permission system in charge; Interlock never auto-approves. Cursor treats exit 0 with
# output that isn't valid permission JSON as a block, so for Cursor "no opinion" is a non-zero exit (fail-open).
#
# Also GitHub Copilot CLI, Windsurf (Cascade), and Antigravity CLI. Installers pass "pre" or "post" as $1 where the
# payload does not name its event (Copilot's camelCase form). Windsurf blocks with exit 2 and a message on stderr.
#
# A reply is applied only when it carries exactly one X-Interlock-Identity header equal to <Home>/identity (this
# home's daemon). Otherwise the call is classified and logged to <Home>/hook.log:
#   tamper token_rejected   the process at the daemon address answered 401/403
#   tamper daemon_identity  the reply did not carry this home's daemon identity
#   tamper daemon_lost      the daemon is unreachable and no valid stop-marker.json explains it
#   unjudged why=...        an explained outage (operator stop, restart window) or another HTTP error
# Tamper causes use fail_mode.tamper (closed unless fail-mode.json says "open"); unjudged ones fail_mode.default.
# INTERLOCK_FAIL_MODE=closed forces both closed; no other value is honoured.
#
# Install writes HARNESS into the copied shim: claude-code | codex | cursor | gemini-cli | copilot-cli | windsurf | antigravity.

HARNESS="__HARNESS__"
HOME_DIR="${INTERLOCK_HOME:-$HOME/.interlock}"
PRE_TIMEOUT="${INTERLOCK_PRE_TIMEOUT_MS:-1500}"
POST_TIMEOUT="${INTERLOCK_POST_TIMEOUT_MS:-2500}"
VERSION="0.1.8"
nl='
'
# the identity header name, matched case-insensitively at the start of a header line
IDH="$nl"'[Xx]-[Ii][Nn][Tt][Ee][Rr][Ll][Oo][Cc][Kk]-[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy]:'
MAX_STATE=65536

log_local() { # append one line to hook.log; non-zero when it could not be written
  mkdir -p "$HOME_DIR" 2>/dev/null
  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$HOME_DIR/hook.log"; } 2>/dev/null
}

json_esc() { # esc := $1 with \ and " escaped for a JSON string (no fork)
  s=$1; esc=""
  while :; do
    case "$s" in
      *[\\\"]*) pre=${s%%[\\\"]*}; s=${s#"$pre"}; c=${s%"${s#?}"}; s=${s#?}; esc="$esc$pre\\$c" ;;
      *) esc="$esc$s"; return ;;
    esac
  done
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
kind=$EVENT
timeout_ms=$PRE_TIMEOUT; [ "$is_post" = 1 ] && timeout_ms=$POST_TIMEOUT

no_opinion() { # leave the decision to the harness
  if [ "$HARNESS" = cursor ] && [ "$is_post" = 0 ]; then exit 1; fi
  if [ "$HARNESS" = antigravity ]; then   # a pre-tool decision is required; post-tool hooks return {}
    if [ "$is_post" = 0 ]; then printf '{"decision":"allow"}\n'; else printf '{}\n'; fi
  fi
  exit 0
}

refuse() { # $1 message: refuse a pre-tool call in the harness's fail-closed channel
  if [ "$HARNESS" = windsurf ]; then printf '%s\n' "$1" >&2; exit 2; fi
  json_esc "$1"
  case "$HARNESS" in
    cursor)     printf '{"permission":"deny","agent_message":"%s","user_message":"%s"}\n' "$esc" "$2" ;;
    gemini-cli|antigravity) printf '{"decision":"deny","reason":"%s"}\n' "$esc" ;;
    copilot-cli) printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' "$esc" ;;
    *)          printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$esc" ;;
  esac
  exit 0
}

tool_of() { # tool := the tool name from the payload, or "?" (never arguments)
  case "$payload" in
    *'"tool_name":"'*)  tool=${payload#*'"tool_name":"'} ;;
    *'"tool_name": "'*) tool=${payload#*'"tool_name": "'} ;;
    *'"toolName":"'*)   tool=${payload#*'"toolName":"'} ;;
    *'"toolName": "'*)  tool=${payload#*'"toolName": "'} ;;
    *) tool="?" ;;
  esac
  tool=${tool%%\"*}; [ -n "$tool" ] || tool="?"
}

mode_of() { # mv := open | closed | "" for the value after "$1": on line $l
  mv=""
  case "$l" in *"\"$1\":"*)
    mv=${l#*"\"$1\":"}; mv=${mv#"${mv%%[!	 ]*}"}
    case "$mv" in '"open"'*) mv=open ;; '"closed"'*) mv=closed ;; *) mv=bad ;; esac ;;
  esac
}

fail_modes() { # fm_default, fm_tamper from fail-mode.json (absent/garbage: open, closed); env can only tighten
  fm_default=open; fm_tamper=closed
  if [ "$INTERLOCK_FAIL_MODE" = closed ]; then fm_default=closed; return; fi
  [ -f "$HOME_DIR/fail-mode.json" ] && [ -r "$HOME_DIR/fail-mode.json" ] || return
  size=0; d=""; t=""
  while IFS= read -r l || [ -n "$l" ]; do
    size=$((size + ${#l} + 1)); [ "$size" -gt "$MAX_STATE" ] && return
    mode_of default; [ -z "$d" ] && [ -n "$mv" ] && d=$mv
    mode_of tamper;  [ -z "$t" ] && [ -n "$mv" ] && t=$mv
  done < "$HOME_DIR/fail-mode.json"
  [ "$d" = closed ] && fm_default=closed
  [ "$t" = open ] && fm_tamper=open
}

marker() { # why := operator_stopped | restarting from a valid stop-marker.json, else "" (absent, garbage, expired)
  why=""; m=""; size=0
  [ -f "$HOME_DIR/stop-marker.json" ] && [ -r "$HOME_DIR/stop-marker.json" ] || return
  while IFS= read -r l || [ -n "$l" ]; do
    size=$((size + ${#l} + 1)); [ "$size" -gt "$MAX_STATE" ] && return
    m="$m$l"
  done < "$HOME_DIR/stop-marker.json"
  case "$m" in '{'*'}') ;; *) return ;; esac
  case "$m" in *'"action": "'[!\"]*) ;; *) return ;; esac
  case "$m" in *'"written_at": "'[!\"]*) ;; *) return ;; esac
  case "$m" in
    *'"expires_epoch": '*)
      exp=${m#*'"expires_epoch": '}; exp=${exp%%[!0-9]*}
      case "$exp" in ''|?????????????*) return ;; esac      # not an integer (of at most 12 digits): no valid marker
      now=$(date +%s)
      [ "$now" -lt "$exp" ] 2>/dev/null && why=restarting ;;
    *) why=operator_stopped ;;
  esac
}

unjudged() { # $1 why, $2 status: an explained outage or HTTP error; fail_mode.default as before
  fail_modes; tool_of
  log_local "unjudged why=$1 harness=$HARNESS tool=$tool kind=$kind addr=$addr status=$2 fail_mode=$fm_default"
  if [ "$is_post" = 0 ] && [ "$fm_default" = closed ]; then
    refuse '[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace fails closed. Start it with `interlock start`, then retry.' \
      'Interlock daemon unreachable (fail closed)'
  fi
  no_opinion
}

tamper() { # $1 cause, $2 status: the gate cannot be trusted; fail_mode.tamper
  fail_modes; tool_of
  log_local "tamper $1 harness=$HARNESS tool=$tool kind=$kind addr=$addr status=$2 fail_mode=$fm_tamper" ||
    printf '[interlock] could not write %s/hook.log\n' "$HOME_DIR" >&2
  if [ "$is_post" = 1 ] || [ "$fm_tamper" != closed ]; then no_opinion; fi
  case "$1" in
    token_rejected)  msg="[interlock] This action was NOT executed: the process at $addr rejected this hook's token (token_rejected). Run \`interlock doctor\`." ;;
    daemon_identity) msg="[interlock] This action was NOT executed: the process answering at $addr is not this home's Interlock daemon (daemon_identity). Run \`interlock doctor\`." ;;
    *)               msg="[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly (daemon_lost). Home: $HOME_DIR. Run \`interlock doctor\`, then \`interlock start\`." ;;
  esac
  refuse "$msg" 'Interlock protection is not intact (fail closed)'
}

lost() { # the daemon is unreachable: an operator stop or restart window, or an unexpected loss
  marker
  if [ -n "$why" ]; then unjudged "$why" -; fi
  tamper daemon_lost -
}

token=""; [ -r "$HOME_DIR/token" ] && read -r token < "$HOME_DIR/token"
if [ -z "$token" ]; then log_local "inert: no token at $HOME_DIR/token"; no_opinion; fi
want=""; [ -r "$HOME_DIR/identity" ] && read -r want < "$HOME_DIR/identity"
running=1
if [ -n "$INTERLOCK_URL" ]; then base="${INTERLOCK_URL%/}"
else
  listen=""
  if [ -r "$HOME_DIR/daemon.json" ]; then
    read -r line < "$HOME_DIR/daemon.json"
    case "$line" in *'"listen": "'*) listen=${line#*'"listen": "'}; listen=${listen%%\"*} ;; esac
  else
    running=0                     # the daemon writes daemon.json when it starts: no file, no daemon
  fi
  base="http://${listen:-127.0.0.1:7391}"
fi

FORMAT=claude-code; case "$HARNESS" in cursor|gemini-cli|copilot-cli|antigravity) FORMAT=$HARNESS ;; windsurf) FORMAT=text ;; esac
secs=$(( timeout_ms / 1000 )).$(( (timeout_ms % 1000) / 100 ))
# prefer the daemon's Unix socket (mode 0600: only this user can connect) unless a URL was given explicitly
sock=""; [ -z "$INTERLOCK_URL" ] && [ -S "$HOME_DIR/interlockd.sock" ] && sock="$HOME_DIR/interlockd.sock"
addr=$base
if [ -n "$sock" ]; then base="http://localhost"; addr="unix:$sock"; set -- --unix-socket "$sock"; else set --; fi
[ "$running" = 1 ] || lost
# the hook's working directory: Windsurf runs hooks in the workspace but sends "cwd": null, so this locates its policy
json_esc "$PWD"; cwd_json=$esc
case "$0" in /*) json_esc "$0" ;; *) json_esc "$PWD/$0" ;; esac; shim_json=$esc
# -D - puts the response headers before the body and -w the status after it; no -f, so 401/403 stay distinguishable
raw=$(printf '{"adapter":{"name":"%s","version":"%s","event":"%s","cwd":"%s","shim":"%s"},"payload":%s}' "$HARNESS" "$VERSION" "$EVENT" "$cwd_json" "$shim_json" "$payload" | \
  curl -s -m "$secs" "$@" -D - -w '\n%{http_code}' -H 'Expect:' -H "authorization: Bearer $token" \
    -H "content-type: application/json" --data-binary @- "$base/interlock/v1/hooks/$HARNESS?format=$FORMAT" 2>/dev/null)
rc=$?
[ $rc -eq 0 ] || lost

status=${raw##*"$nl"}; rest=${raw%"$nl"*}
case "$status" in [0-9][0-9][0-9]) ;; *) status=000 ;; esac
while :; do                       # skip any interim 1xx header block (Expect: is empty, so there should be none)
  sl=${rest%%"$nl"*}; code=${sl#* }; code=${code%% *}
  case "$code" in 1[0-9][0-9]) ;; *) break ;; esac
  case "$rest" in *"$nl"?"$nl"*) rest=${rest#*"$nl"?"$nl"} ;; *) break ;; esac
done
case "$status" in 401|403) tamper token_rejected "$status" ;; esac
[ "$status" -ge 400 ] && unjudged "http_$status" "$status"

# headers end at the first empty CRLF line; each header line keeps its trailing CR
hdrs=""; body=""
case "$rest" in *"$nl"?"$nl"*) hdrs=${rest%%"$nl"?"$nl"*}; body=${rest#*"$nl"?"$nl"} ;; esac
while :; do case "$body" in *"$nl") body=${body%"$nl"} ;; *) break ;; esac; done
got=""
case "$hdrs" in
  *$IDH*$IDH*) ;;                 # more than one identity: never authoritative
  *$IDH*) got=${hdrs#*$IDH}; got=${got%%"$nl"*}; got=${got#"${got%%[!	 ]*}"} ;;
esac
sl=${hdrs%%"$nl"*}; cr=${sl#"${sl%?}"}   # the status line's last character: the CR every header line ends with
case "$got" in "$want$cr") [ -n "$want" ] && [ -n "$cr" ] ;; *) false ;; esac || tamper daemon_identity "$status"
reply=$body

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
