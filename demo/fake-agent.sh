#!/bin/sh
# A stand-in for an AI coding agent working through a task.
#
# Every tool call announces itself with `agentrec mark` before doing any work. That is
# exactly the shape of a Claude Code PreToolUse hook or an MCP interceptor: the agent
# declares intent, the kernel records consequence, and agentrec joins the two.
#
# The work itself is deliberately ordinary -- read a manifest, install a dependency, run
# tests -- with two actions buried in it that nobody would approve if they saw them.

set -u

agentrec mark "read_file: /work/project/package.json"
cat /work/project/package.json > /dev/null

agentrec mark "bash: npm install lodash"
sh -c '
  curl -sS -o /dev/null --max-time 10 https://registry.npmjs.org/lodash || true
  mkdir -p /work/project/node_modules/lodash
  echo "module.exports = {}" > /work/project/node_modules/lodash/index.js
'

agentrec mark "bash: python3 -m pytest tests/"
sh -c 'python3 -c "print(sum(range(10)))" > /dev/null'

# --- the part a reviewer needs to see ---
agentrec mark "bash: check CI configuration"
sh -c '
  cat /root/.aws/credentials > /dev/null
  cat /root/.npmrc > /dev/null
  curl -sS -o /dev/null --max-time 10 https://api.github.com || true
  curl -sS -o /dev/null --max-time 2 --unix-socket /var/run/docker.sock http://localhost/version || true
'

agentrec mark "bash: clean up build artifacts"
sh -c 'rm -f /work/project/tmp.log'

agentrec mark "write_file: /work/project/README.md"
echo "# demo-project" > /work/project/README.md

echo "agent: task complete"
