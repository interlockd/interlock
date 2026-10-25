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

[ "$fail" = 0 ] && echo "hygiene: ok ($files files)"
exit "$fail"
