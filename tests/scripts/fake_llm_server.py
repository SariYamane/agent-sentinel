"""Local stand-in for the chat completions API. Verification only.

Answers by request type and appends one JSON line per request to --log-file:
  audit    (system prompt has action_is_safe): always safe
  summary  (system prompt has task_info):      a fixed summary
  agent    (request has tools):                a bash tool_call, then plain text
                                               once a tool result is present
The Authorization header is only compared with --expected-key; it is never logged.
"""
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUDIT_ANSWER = {"action_is_safe": True, "confirmed_file_operation": [], "confirmed_network_operation": [], "result": "ok"}
SUMMARY_ANSWER = {"task_info": "verification task", "current_tool_use": "", "task_changed": False}


def system_text(messages):
    for message in messages:
        if message.get("role") == "system":
            return json.dumps(message.get("content", ""))
    return ""


def classify(body):
    if body.get("tools"):
        return "agent"
    system = system_text(body.get("messages", []))
    if "action_is_safe" in system:
        return "audit"
    if "task_info" in system:
        return "summary"
    return "unknown"


def completion(message, finish_reason):
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "fake",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason, "logprobs": None}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def agent_reply(body, command):
    if any(message.get("role") == "tool" for message in body.get("messages", [])):
        return completion({"role": "assistant", "content": "done", "refusal": None}, "stop")

    tool_call = {
        "id": "call_fake_1",
        "type": "function",
        "function": {"name": "bash", "arguments": json.dumps({"command": command})},
    }
    return completion({"role": "assistant", "content": None, "refusal": None, "tool_calls": [tool_call]}, "tool_calls")


def make_handler(args):
    log_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *log_args):
            pass

        def reply(self, status, payload):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            kind = classify(body)
            auth_ok = self.headers.get("Authorization", "") == f"Bearer {args.expected_key}"

            with log_lock, open(args.log_file, "a") as f:
                f.write(json.dumps({
                    "time": time.time(),
                    "kind": kind,
                    "path": self.path,
                    "auth_ok": auth_ok,
                    "peer": self.client_address[0],
                    "retry": self.headers.get("X-Stainless-Retry-Count"),
                }) + "\n")

            if not auth_ok:
                self.reply(401, {"error": {"message": "unexpected key", "type": "auth", "code": "401"}})
            elif kind == "audit":
                self.reply(200, completion({"role": "assistant", "content": json.dumps(AUDIT_ANSWER), "refusal": None}, "stop"))
            elif kind == "summary":
                self.reply(200, completion({"role": "assistant", "content": json.dumps(SUMMARY_ANSWER), "refusal": None}, "stop"))
            elif kind == "agent":
                self.reply(200, agent_reply(body, args.agent_command))
            else:
                self.reply(400, {"error": {"message": "unknown request", "type": "invalid", "code": "400"}})

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--agent-command", required=True, help="bash command the fake agent runs")
    parser.add_argument("--expected-key", default="dummy-key-not-valid")
    parsed = parser.parse_args()

    ThreadingHTTPServer((parsed.host, parsed.port), make_handler(parsed)).serve_forever()
