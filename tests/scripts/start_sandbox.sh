#!/bin/bash

source /home/arcana/experiment/agent-sentinel/.env

if [ "$#" -lt 1 ]; then
    echo "invalid container id"
    exit
fi

cid="$1"

log_file=""
if [ "$#" -gt 1 ]; then
    log_file="$2"
fi

model="claude-3-5-sonnet-20241022"
if [ "$#" -gt 2 ]; then
    model="$3"
fi

#ANTHROPIC_API_KEY="$OPENROUTER_API_KEY" \
aa-exec --profile=unconfined -- ../../agent-sentinel -debug=1 \
-output=$log_file \
-cid=$cid \
-mount-path=/home/arcana/.anthropic \
-audit=1 \
-process-trace-level=4 \
-binary-level-cache=1 \
-tool-use-timeout=110 \
-model=$model