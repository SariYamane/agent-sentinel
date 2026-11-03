"""Refuse to start a verification run unless every LLM route is fake.

Verification only. A run calls no paid API only if the auditor (env file read
by start_sandbox.sh), the agent (runner environment) and basic_config's api_key
are all dummy values. Exits non-zero if any of them is not.

  python check_no_paid_api.py --base-url http://172.17.0.1:8765/v1 \
      --basic-config basic.json [--basic-config other.json]
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import urlparse

DUMMY_KEY = "dummy-key-not-valid"
ENV_LINE = re.compile(r"^export\s+(OPENROUTER_API_KEY|OPENROUTER_BASE_URL)=(\S+)$")


def read_env_file(path, errors):
    """Parse the env file. It gets sourced as root, so only the two expected
    export lines are accepted; anything else could reach the real key."""
    values = {}
    with open(path) as f:
        for number, raw in enumerate(f, 1):
            line = raw.strip()
            if line == "" or line.startswith("#"):
                continue
            match = ENV_LINE.match(line)
            if match is None:
                # do not echo the line: it may hold a secret
                errors.append(f"{path}:{number}: only `export OPENROUTER_API_KEY=...` and `export OPENROUTER_BASE_URL=...` are allowed")
                continue
            values[match.group(1)] = match.group(2)
    return values


def check_route(label, key, base_url, expected_base_url, errors):
    if key != DUMMY_KEY:
        errors.append(f"{label}: OPENROUTER_API_KEY is not the dummy key")
    if base_url != expected_base_url:
        errors.append(f"{label}: OPENROUTER_BASE_URL is not the fake server")
    host = urlparse(base_url or "").hostname or ""
    if host == "" or host == "openrouter.ai" or host.endswith(".openrouter.ai"):
        errors.append(f"{label}: base URL host `{host}` is not allowed")


def find_errors(expected_base_url, basic_configs, environ):
    errors = []

    check_route("runner env", environ.get("OPENROUTER_API_KEY"), environ.get("OPENROUTER_BASE_URL"), expected_base_url, errors)

    env_file = environ.get("AGENTSENTINEL_ENV_FILE", "")
    if not os.path.isabs(env_file) or not os.path.isfile(env_file):
        errors.append("AGENTSENTINEL_ENV_FILE must be the absolute path of an existing file")
    else:
        values = read_env_file(env_file, errors)
        check_route("env file", values.get("OPENROUTER_API_KEY"), values.get("OPENROUTER_BASE_URL"), expected_base_url, errors)

    if not environ.get("AUDIT_REQUEST_LIMIT", "").isdigit():
        errors.append("AUDIT_REQUEST_LIMIT must be set to a non-negative integer")

    for path in basic_configs:
        with open(path) as f:
            if json.load(f).get("api_key") != DUMMY_KEY:
                errors.append(f"{path}: api_key is not the dummy key")

    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", required=True, help="base URL of the fake server")
    parser.add_argument("--basic-config", action="append", required=True)
    args = parser.parse_args()

    found = find_errors(args.base_url, args.basic_config, os.environ)
    for error in found:
        print(f"[check_no_paid_api] NG: {error}", file=sys.stderr)
    if found:
        sys.exit(1)
    print("[check_no_paid_api] OK")
