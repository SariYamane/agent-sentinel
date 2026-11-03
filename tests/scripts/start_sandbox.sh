#!/bin/bash

# Machine-specific: the DNS server containers actually use on this host
# (verify with `docker run --rm alpine cat /etc/resolv.conf`). Excluded
# from network audit so the agent's own DNS lookups don't get routed
# through the LLM security query and killed before a task can run.
export AGENTSENTINEL_DNS_EXCLUDE="192.168.10.1:53"

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

# sudo resets the environment, so the env file and the limit are positional.
env_file="${4:-/home/arcana/experiment/agent-sentinel/.env}"
limit="${5:-100}"

# Never fall back to the default .env when an explicit one is missing.
if [ ! -f "$env_file" ]; then
    echo "env file not found: $env_file" >&2
    exit 1
fi
echo "start_sandbox: sourcing env file $env_file" >&2
source "$env_file"

#ANTHROPIC_API_KEY="$OPENROUTER_API_KEY" \
aa-exec --profile=unconfined -- ../../agent-sentinel -debug=1 \
-output=$log_file \
-cid=$cid \
-mount-path=/home/arcana/.anthropic \
-audit=1 \
-process-trace-level=4 \
-binary-level-cache=1 \
-tool-use-timeout=110 \
-audit-request-limit=$limit \
-model=$model
