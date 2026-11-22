#!/usr/bin/env bash
# Repository hygiene, run in CI on every push and pull request: nothing that identifies a real machine, account or
# person, and no leftovers from private tooling, may be committed. Run it locally before you push: scripts/check-hygiene.sh
set -euo pipefail
cd "$(dirname "$0")/.."
git rev-parse --is-inside-work-tree >/dev/null      # never report "ok" without having looked at anything
files=$(git ls-files | wc -l | tr -d ' ')
[ "$files" -gt 0 ] || { echo "::error::no tracked files to check"; exit 1; }

fail=0
report() { echo "::error::$1"; echo "$2" | head -20; fail=1; }
scan() { git ls-files -z | xargs -0 grep -nIE "$@" -- 2>/dev/null || true; }

hits=$(scan '(arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:|[0-9]{12}:(user|role|root|table)/)')
[ -z "$hits" ] || report "AWS account id in an ARN or principal" "$hits"
hits=$(scan '\b(AKIA|ASIA)[0-9A-Z]{16}\b' | grep -vE '(AKIA|ASIA)[0-9A-Z]{9}EXAMPLE' || true)   # AWS's documented example key is fine
[ -z "$hits" ] || report "AWS access key id" "$hits"
hits=$(scan 'internal:(begin|end)|docs/''strategy/')    # split so this line doesn't match itself
[ -z "$hits" ] || report "private-tooling marker" "$hits"
# a real home directory: /Users/<name> or /home/<name>, other than the placeholder names docs and fixtures use
hits=$(git ls-files -z | xargs -0 grep -nIoE '/(Users|home)/[A-Za-z0-9._-]+' -- 2>/dev/null \
       | grep -viE ':/(Users|home)/(me|you|user|username|dev|runner|runneradmin|alice|bob|example|linuxbrew)$' || true)
[ -z "$hits" ] || report "real home directory path" "$hits"

# shim test fixtures (tracked or not yet added): recordings use placeholders ($HOME_DIR, $CWD) and dummy tokens, so
# no token-shaped value (secrets.token_urlsafe(32): 43 url-safe characters), no home or temp path of any user, and not
# this machine's own Interlock token (only file names are printed for that one)
fx=tests/fixtures/shims-0.1.8
if [ -d "$fx" ]; then
  fxscan() { find "$fx" -type f -print0 | xargs -0 grep -nIE "$@" -- 2>/dev/null || true; }
  hits=$(fxscan '(^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{43}([^A-Za-z0-9_-]|$)')
  [ -z "$hits" ] || report "token-shaped value in a shim fixture" "$hits"
  hits=$(fxscan '/(Users|home)/[A-Za-z0-9._-]+|/var/folders/')
  [ -z "$hits" ] || report "home or temp directory path in a shim fixture (use \$HOME_DIR / \$CWD)" "$hits"
  tokfile="${INTERLOCK_HOME:-${HOME:-/nonexistent}/.interlock}/token"
  tok=""; [ -r "$tokfile" ] && read -r tok < "$tokfile" || true
  if [ -n "$tok" ]; then
    hits=$(find "$fx" -type f -print0 | xargs -0 grep -lIF -e "$tok" -- 2>/dev/null || true)
    [ -z "$hits" ] || report "this machine's Interlock token in a shim fixture" "$hits"
  fi
fi

[ "$fail" = 0 ] && echo "hygiene: ok ($files files)"
exit "$fail"
