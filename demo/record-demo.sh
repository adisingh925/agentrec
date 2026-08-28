#!/usr/bin/env bash
# record-demo.sh — runs the agentrec launch demo: one agent, recorded twice.
# Take 1 shows what the agent ACTUALLY did; take 2 blocks it in-kernel with --enforce.
#
# It is SAFE: it stages a fake credentials file in an isolated demo HOME and never
# reads your real secrets. Nothing is left behind.
#
#   export AGENTREC_ENDPOINT=https://api.agentrec.io
#   export AGENTREC_TOKEN=ar_ing_...     # a workspace with a block rule on .aws/credentials
#   ./record-demo.sh                     # paced, for recording
#   DEMO_FAST=1 ./record-demo.sh         # no pauses, for a quick dry run
#
# The --enforce take blocks only if your workspace has a block rule matching the
# read: event=open, field=path, op=suffix, pattern=.aws/credentials, action=block.
# Most workspaces ship with it; add it in the console's Rules panel if yours doesn't.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
AR="${AR:-agentrec}"
: "${AGENTREC_ENDPOINT:?set AGENTREC_ENDPOINT (e.g. https://api.agentrec.io)}"
: "${AGENTREC_TOKEN:?set AGENTREC_TOKEN (an ar_ing_ ingest token)}"

# isolated demo home — a fake credentials file, never your real one
DEMO_HOME="/tmp/agentrec-demo"
rm -rf "$DEMO_HOME"; mkdir -p "$DEMO_HOME/.aws"
cat > "$DEMO_HOME/.aws/credentials" <<'CREDS'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
CREDS
trap 'rm -rf "$DEMO_HOME"' EXIT

pace(){ [ "${DEMO_FAST:-0}" = 1 ] || sleep "$1"; }
banner(){ printf '\n\033[1;38;5;208m%s\033[0m\n\n' "$1"; pace 1.6; }

[ "${DEMO_FAST:-0}" = 1 ] || clear
banner "The agent was asked to \"check CI config.\" Here is what it ACTUALLY did:"
env HOME="$DEMO_HOME" AR="$AR" DEMO_CRED="$DEMO_HOME/.aws/credentials" \
  "$AR" trace --session "demo-observe" -- "$here/demo-agent.sh"
pace 3

banner "Same agent — now with --enforce. The credential read is denied in-kernel:"
env HOME="$DEMO_HOME" AR="$AR" DEMO_CRED="$DEMO_HOME/.aws/credentials" \
  "$AR" trace --enforce --session "demo-enforce" -- "$here/demo-agent.sh"
pace 2

printf '\n\033[2mIt reported: "check CI configuration."  The kernel saw it read your AWS keys.\033[0m\n'
printf '\033[2magentrec — records (and blocks) what your AI agents actually do.  https://agentrec.io\033[0m\n\n'
