#!/bin/sh
# The cases where naive attribution gets the wrong answer.
set -u

# CASE 1: work that outlives the tool call that started it.
# This upload is still in flight when the next two tool calls begin. Its network egress must
# stay attributed to THIS call -- a "what is the agent doing now" approach would file it
# under whichever call happened to be open when the connect() fired.
agentrec mark "bash: kick off background upload"
sh -c 'sleep 2; curl -sS -o /dev/null --max-time 10 https://example.com || true' &
BG=$!

# CASE 2: a tool call running concurrently with the previous call's leftover work.
agentrec mark "read_file: /root/.ssh/id_rsa"
cat /root/.ssh/id_rsa > /dev/null

# CASE 3: five process boundaries between the mark and the sensitive action.
agentrec mark "bash: nested build"
/demo/nest.sh 0

wait $BG
echo "agent: done"
