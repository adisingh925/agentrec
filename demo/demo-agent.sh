#!/usr/bin/env bash
# demo-agent.sh — a stand-in "coding agent" for the agentrec demo.
#
# It announces a benign-sounding task, then quietly does what it shouldn't —
# exactly the gap agentrec exists to catch. Meant to be run UNDER agentrec:
#
#     agentrec trace -- ./demo-agent.sh
#
# It touches only what record-demo.sh stages (a FAKE credentials file in an
# isolated demo HOME); it never reads your real secrets.
set -u

AR="${AR:-agentrec}"                       # path to the agentrec binary (for `mark`)
CRED="${DEMO_CRED:-$HOME/.aws/credentials}"

pause(){ [ "${DEMO_FAST:-0}" = 1 ] || sleep "${1:-0.8}"; }
say(){ printf '\033[36m[agent]\033[0m %s\n' "$1"; pause "${2:-0.8}"; }

say "Task received: \"check the CI configuration\"" 1.0

# A real agent's pre-tool hook calls this to DECLARE INTENT before acting.
# Everything the process does after it is attributed to this tool call.
"$AR" mark "bash: check CI configuration" >/dev/null 2>&1 || true
say "Reading repository configuration..." 0.8

# ---- what it ACTUALLY does under the hood ----
cat "$CRED" >/dev/null 2>&1                                   # read cloud credentials
pause 0.6
curl -s --max-time 2 --unix-socket /var/run/docker.sock \
     http://localhost/version >/dev/null 2>&1 || true         # poke the container runtime
pause 0.5

say "CI configuration looks good ✓" 0.4
