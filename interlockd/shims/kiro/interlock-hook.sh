#!/bin/sh
# Interlock hook shim for Kiro (PreToolUse and PostToolUse). POSIX sh + curl (+ date on the failure path only).
#
# Hot path is two forks (cat for stdin, curl for the request); everything else is shell builtins, because
# each fork costs 5-10 ms on macOS. Measured on an M4 Pro: ~30 ms end to end for a tier-0 call, against
# ~108 ms for the Node shim (whose startup alone is ~79 ms). The daemon answers shims in text:
#   line 1: "<disposition> <mode> <tier>"    following lines: the notice or reason
# Kiro vocabulary (adapters/kiro/PAYLOADS.md §5): exit 0 = allow, exit 2 + stderr = block. Kiro has no
# hook-driven "ask", so ask renders as a block whose notice asks the agent to confirm with the user.
# PostToolUse is record-only on Kiro: always exit 0.
#
# A reply is applied only when it carries exactly one X-Interlock-Identity header equal to <Home>/identity (this
# home's daemon). A token rejection (401/403), a missing or wrong identity, and an unreachable daemon with no
# operator Stop_Marker are tamper causes and use fail_mode.tamper (default closed); other unjudged calls use
# fail_mode.default (default open). INTERLOCK_FAIL_MODE=closed forces both closed; other values are ignored.

HOME_DIR="${INTERLOCK_HOME:-$HOME/.interlock}"
PRE_TIMEOUT="${INTERLOCK_PRE_TIMEOUT_MS:-1500}"
POST_TIMEOUT="${INTERLOCK_POST_TIMEOUT_MS:-2500}"
VERSION="0.2.0"
nl='
'
bs='\'
dq='"'

log_local() {  # failure path only; forks are fine here. Returns non-zero when hook.log cannot be written.
  mkdir -p "$HOME_DIR" 2>/dev/null
  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$HOME_DIR/hook.log"; } 2>/dev/null
}

json_str() {  # $1 -> $esc, with backslashes and double quotes escaped (builtins only)
  r=$1; esc=""
  while :; do case "$r" in *"$bs"*) esc="$esc${r%%"$bs"*}$bs$bs"; r=${r#*"$bs"} ;; *) break ;; esac; done
  r="$esc$r"; esc=""
  while :; do case "$r" in *"$dq"*) esc="$esc${r%%"$dq"*}$bs$dq"; r=${r#*"$dq"} ;; *) break ;; esac; done
  esc="$esc$r"
}

jget() {  # $1 document, $2 key -> $jv: the text after `"key":` (one optional space), $jhas: 1 when the key is there
  jv=""; jhas=0
  case "$1" in
    *"$dq$2$dq: "*) jv=${1#*"$dq$2$dq: "}; jhas=1 ;;
    *"$dq$2$dq:"*)  jv=${1#*"$dq$2$dq:"}; jhas=1 ;;
  esac
}

jstr() {  # $1 document, $2 key -> $js: the key's string value ("" when absent or not a string)
  jget "$1" "$2"; js=""
  case "$jv" in "$dq"*) js=${jv#?}; js=${js%%"$dq"*} ;; esac
}

payload=$(cat)
[ -n "$payload" ] || exit 0
case "$payload" in
  *PostToolUse*|*postToolUse*) is_post=1; timeout_ms=$POST_TIMEOUT ;;
  *)                           is_post=0; timeout_ms=$PRE_TIMEOUT ;;
esac

# token, identity and daemon address with builtins only
token=""; [ -r "$HOME_DIR/token" ] && read -r token < "$HOME_DIR/token"
if [ -z "$token" ]; then log_local "inert: no token at $HOME_DIR/token"; exit 0; fi
want=""; [ -r "$HOME_DIR/identity" ] && read -r want < "$HOME_DIR/identity"
want=${want%[[:cntrl:]]}
reachable=1
if [ -n "$INTERLOCK_URL" ]; then base="${INTERLOCK_URL%/}"
else
  listen=""
  if [ -r "$HOME_DIR/daemon.json" ]; then
    read -r line < "$HOME_DIR/daemon.json"
    case "$line" in *'"listen": "'*) listen=${line#*'"listen": "'}; listen=${listen%%\"*} ;; esac
  else
    reachable=0                                    # no daemon.json: no daemon is serving this home
  fi
  base="http://${listen:-127.0.0.1:7391}"
fi
case "$0" in /*) shim_path=$0 ;; *) shim_path="$PWD/$0" ;; esac
json_str "$shim_path"; shim_json=$esc

status=-; body=""; why=""; cause=""
if [ "$reachable" = 1 ]; then
  secs=$(( timeout_ms / 1000 )).$(( (timeout_ms % 1000) / 100 ))
  # -D - puts the response headers on stdout ahead of the body, -w appends the status on its own line; no -f, so
  # 401/403 are told apart from other errors. "Expect:" keeps a 100 Continue block out of the headers.
  raw=$(printf '{"adapter":{"name":"kiro","version":"%s","shim":"%s"},"payload":%s}' "$VERSION" "$shim_json" "$payload" | \
    curl -s -m "$secs" -D - -w '\n%{http_code}' -H 'Expect:' -H "authorization: Bearer $token" \
      -H "content-type: application/json" --data-binary @- "$base/interlock/v1/hooks/kiro?format=text" 2>/dev/null)
  rc=$?
  status=${raw##*"$nl"}
  case "$status" in [1-5][0-9][0-9]) ;; *) [ "$rc" -ne 0 ] || rc=1 ;; esac   # no status: a broken reply
  if [ "$rc" -ne 0 ]; then reachable=0; status=-
  else
    # header lines (CRLF) up to the first blank line, then the body; count X-Interlock-Identity lines (any case)
    r=${raw%"$nl"*}; ids=0; got=""
    while [ -n "$r" ]; do
      case "$r" in *"$nl"*) l=${r%%"$nl"*}; r=${r#*"$nl"} ;; *) l=$r; r="" ;; esac
      l=${l%[[:cntrl:]]}
      if [ -z "$l" ]; then body=$r; break; fi
      case "$l" in
        [Xx]-[Ii][Nn][Tt][Ee][Rr][Ll][Oo][Cc][Kk]-[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy]:*)
          ids=$((ids + 1)); got=${l#*:}
          while :; do case "$got" in [[:blank:]]*) got=${got#?} ;; *[[:blank:]]) got=${got%?} ;; *) break ;; esac; done ;;
      esac
    done
    while :; do case "$body" in *"$nl") body=${body%"$nl"} ;; *) break ;; esac; done
    case "$status" in
      401|403) cause=token_rejected ;;
      [45]??)  why=http_$status ;;
      *)
        if [ "$ids" -ne 1 ] || [ -z "$want" ] || [ "$got" != "$want" ]; then cause=daemon_identity
        else
          case "$status" in 2??) [ -n "$body" ] || why=bad_reply ;; *) why=http_$status ;; esac
        fi ;;
    esac
  fi
fi

if [ "$reachable" = 0 ]; then                      # read the operator's Stop_Marker (ignored when reachable)
  m=""
  if [ -f "$HOME_DIR/stop-marker.json" ] && [ -r "$HOME_DIR/stop-marker.json" ]; then
    while IFS= read -r l || [ -n "$l" ]; do
      m="$m$l"; [ ${#m} -le 65536 ] || { m=""; break; }
    done < "$HOME_DIR/stop-marker.json"
  fi
  case "$m" in '{'*'}') ;; *) m="" ;; esac         # not one JSON object: unparseable, treated as absent
  jstr "$m" action; m_action=$js
  jstr "$m" written_at; m_written=$js
  if [ -n "$m_action" ] && [ -n "$m_written" ]; then
    jget "$m" expires_epoch
    exp=${jv%%[!0-9]*}
    if [ "$jhas" = 0 ]; then why=operator_stopped
    elif [ -z "$exp" ]; then cause=daemon_lost   # an expiry that is not a number: unparseable
    else
      now=$(date +%s)
      if [ "$now" -lt "$exp" ] 2>/dev/null; then why=restarting; else cause=daemon_lost; fi
    fi
  else
    cause=daemon_lost
  fi
fi

if [ -n "$cause" ] || [ -n "$why" ]; then
  # fail-mode.json: absent, unreadable, above 64 KiB or without the keys -> default open, tamper closed
  fm_default=open; fm_tamper=closed
  if [ -f "$HOME_DIR/fail-mode.json" ] && [ -r "$HOME_DIR/fail-mode.json" ]; then
    size=0; d=open; t=closed
    while IFS= read -r l || [ -n "$l" ]; do
      size=$((size + ${#l} + 1)); [ "$size" -le 65536 ] || { d=open; t=closed; break; }
      case "$l" in *'"default": "closed"'*) d=closed ;; esac
      case "$l" in *'"tamper": "open"'*) t=open ;; esac
    done < "$HOME_DIR/fail-mode.json"
    fm_default=$d; fm_tamper=$t
  fi
  [ "$INTERLOCK_FAIL_MODE" = closed ] && { fm_default=closed; fm_tamper=closed; }
  case "$payload" in
    *'"tool_name":"'*)  tool=${payload#*'"tool_name":"'} ;;
    *'"tool_name": "'*) tool=${payload#*'"tool_name": "'} ;;
    *) tool="?" ;;
  esac
  tool=${tool%%\"*}; tool=${tool%%[[:space:]]*}; [ -n "$tool" ] || tool="?"
  kind=pre; [ "$is_post" = 1 ] && kind=post
  if [ -n "$cause" ]; then
    mode=$fm_tamper
    line="tamper $cause harness=kiro tool=$tool kind=$kind addr=$base status=$status fail_mode=$mode"
  else
    mode=$fm_default
    line="unjudged why=$why harness=kiro tool=$tool kind=$kind addr=$base fail_mode=$mode"
  fi
  log_local "$line" || printf '[interlock] could not write %s/hook.log\n' "$HOME_DIR" >&2
  if [ "$is_post" = 0 ] && [ "$mode" = "closed" ]; then
    case "$cause" in
      token_rejected)  msg="[interlock] This action was NOT executed: the process at $base rejected this hook's token (token_rejected). Run \`interlock doctor\`." ;;
      daemon_identity) msg="[interlock] This action was NOT executed: the process answering at $base is not this home's Interlock daemon (daemon_identity). Run \`interlock doctor\`." ;;
      daemon_lost)     msg="[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly (daemon_lost). Home: $HOME_DIR. Run \`interlock doctor\`, then \`interlock start\`." ;;
      *)               msg='[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace fails closed. Start it with `interlock start`, then retry.' ;;
    esac
    printf '%s\n' "$msg" >&2
    exit 2
  fi
  exit 0
fi

verdict=$body
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
