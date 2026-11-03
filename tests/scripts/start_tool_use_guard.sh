#!/bin/bash

log_file=""
if [ "$#" -gt 0 ]; then
    log_file="$1"
fi

model="claude-3-5-sonnet-20241022"
if [ "$#" -gt 1 ]; then
    model="$2"
fi

# The audit request limit does not cover audit-without-tracer mode: it has no
# way to hold stopped processes on abort, so it must run with an explicit 0.
ANTHROPIC_API_KEY=xxx \
../../agent-sentinel -debug=1 \
-output=$log_file \
-mount-path=~/.anthropic \
-audit-without-tracer \
-audit-request-limit=0 \
-model=$model