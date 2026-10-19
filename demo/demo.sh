#!/bin/sh
# A self-contained Interlock demo for screen recordings (`vhs demo/demo.tape`, or asciinema). Uses a throwaway home and
# port, so your own setup is untouched. Needs `interlock` on PATH.
set -e
unset INTERLOCK_HOME INTERLOCK_URL; export HOME="$(mktemp -d /tmp/il-demo.XXXX)"; mkdir -p "$HOME/.interlock" "$HOME/.claude" "$HOME/proj"
echo '{"listen": "127.0.0.1:7499"}' > "$HOME/.interlock/config.json"
cd "$HOME/proj" && git init -q
say() { printf '\n\033[1m$ %s\033[0m\n' "$*"; sleep 1; }
hook() {  # what Claude Code sends before running a command
  printf '{"session_id":"demo","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"},"tool_use_id":"t"}' \
    "$HOME/proj" "$1" | sh "$HOME/.interlock/adapters/claude-code/interlock-hook.sh" | cut -c1-160; echo
}
say interlock init --enforce
interlock init -y --enforce --harness claude-code --backend process | sed -n '/What the gate decides/,/an ordinary test run/p'
say "# the agent tries a force-push to main"
hook "git push --force origin main"
say "# and an ordinary test run"
hook "pytest -q"; echo "(no output: the agent's own permissions decide)"
say interlock log
interlock log | tail -3
say interlock explain
interlock explain | sed -n 3,8p
interlock uninstall -y --purge >/dev/null 2>&1; rm -rf "$HOME"
