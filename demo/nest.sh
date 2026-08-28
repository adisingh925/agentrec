#!/bin/sh
# Descends a few levels of shell and interpreter, then touches a credential at the bottom.
# The point is that the credential read at depth 4 must still be attributed to the tool call
# that started the descent, five process boundaries earlier.
depth=${1:-0}

if [ "$depth" -ge 4 ]; then
	python3 -c "open('/root/.aws/credentials').read()"
	exit 0
fi

sh -c "/demo/nest.sh $((depth + 1))"
