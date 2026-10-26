import json
import sys
import os
import random
import uuid
from datetime import datetime
from enum import StrEnum

from computer_use_demo.agent import (
    Agent,
)

# TODO: __init__
from computer_use_demo.attacks.backdoor import Backdoor
from computer_use_demo.attacks.indirect_prompt_injection import IndirectPromptInjection
from computer_use_demo.attacks.hallucination import  Hallucination
from computer_use_demo.attacks.attack4agent import  Attack4Agent
from computer_use_demo.attacks.bad_tool_result import BadToolResult
from computer_use_demo.attacks.third_party_app import ThirdPartyApp
from computer_use_demo.attacks.direct_task_injection import DirectTaskInjection
from computer_use_demo.attacks.agentdojo import AgentDojo
from computer_use_demo.attacks.adaptive_attack import AdaptiveAttack
from computer_use_demo.defenses.combination import DefensesCombination
from computer_use_demo.defenses.delimiters_defense import DelimitersDefender
from computer_use_demo.defenses.instructional_prevention import \
    InstructionalPrevention
from computer_use_demo.defenses.sandbox import LLMSandbox
from computer_use_demo.defenses.tool_use_guard import ToolUseGuard


def log_json_str(message_type: str, message_content: str, output_console = False, output_file = ""):
    message = {
        "time": datetime.now().isoformat(),
        "type": message_type,
        "data": message_content,
    }

    output = json.dumps(message)
    if output_console:
            print(output)
    if output_file != "":
        with open(output_file, "a") as output_file_fp:
            output_file_fp.write(output)
            output_file_fp.write("\n")

# TODO: load config
def load_config(config_file):
    random.seed()

    with open(config_file, "r") as config_file_fp:
        data = json.load(config_file_fp)

    # basic config
    config = {
        "system_prompt": data["system_prompt"],
        "model": data["model"],
        "api_key": data["api_key"],
        "n_images": data["n_images"],
        "task_input": data["task_input"],
        "messages": data["messages"],
        "max_requests": data["max_requests"]
    }

    # additional context

    if "post_task_input" in data:
        config["post_task_input"] = data["post_task_input"]

    # logger config
    enable_console_log = False
    output_file_log = ""
    if "enable_console_log" in data:
        enable_console_log = data["enable_console_log"]
    if "output_file_log" in data:
        output_file_log = data["output_file_log"]

    if enable_console_log or output_file_log:
        def action_log_func(message):
            log_json_str("action", message, enable_console_log, output_file_log)

        def tool_use_result_log_func(message):
            log_json_str("tool_use_result", message, enable_console_log, output_file_log)

        def task_input_log_func(message):
            log_json_str("task", message, enable_console_log, output_file_log)

        def api_req_rep_log_func(req, res, e):
            log_json_str("api_request", req.read().decode(), enable_console_log, output_file_log)
            if e:
                log_json_str("api_error", str(e), enable_console_log, output_file_log)
            if hasattr(res, "text"):
                log_json_str("api_response", res.text, enable_console_log, output_file_log)
            else:
                log_json_str("api_response", res, enable_console_log, output_file_log)

        config["action_log_func"] = action_log_func
        config["tool_use_result_log_func"] = tool_use_result_log_func
        config["task_input_log_func"] = task_input_log_func
        config["api_req_rep_log_func"] = api_req_rep_log_func

    # attack config
    if "attack" in data:
        attack = data["attack"]
        if attack["type"] == "backdoor":
            config["attack"] = Backdoor(attack["config"]["system_prompt"], attack["config"]["trigger"], attack["config"]["tool_uses"] if "tool_uses" in attack["config"] else [])
        elif attack["type"] == "indirect_prompt_inject":
            config["attack"] = IndirectPromptInjection(attack["config"]["tool_result_suffix"])
        elif attack["type"] == "hallucination":
            config["attack"] = Hallucination()
        elif attack["type"] == "attack4agent":
            # FIXME: core file
            config["attack"] = Attack4Agent(os.getpid(), '/home/computeruse/scripts/computer_use_demo/loop.py', os.path.realpath(config_file))
        elif attack["type"] == "bad_tool_result":
            config["attack"] = BadToolResult()
        elif attack["type"] == "third_party_app":
            config["attack"] = ThirdPartyApp()
        elif attack["type"] == "direct_task_inject":
            config["attack"] = DirectTaskInjection(attack["config"]["task_input_suffix"])
        elif attack["type"] == "agentdojo":
            config["attack"] = AgentDojo()
        elif attack["type"] == "adaptive_attack":
            config["attack"] = AdaptiveAttack()
        else:
            print(f"Unkown attack {attack}")

    if "defenses" in data and data["defenses"]:
        config["defense"] = DefensesCombination()
        for defense in data["defenses"]:
            if defense["type"] == "sandbox":
                config["defense"].add_defense(LLMSandbox({
                    "pid": os.getpid(),
                    "core_file_paths": ["/home/computeruse/scripts"]
                }))
            elif defense["type"] == "delimiters_defense":
                config["defense"].add_defense(DelimitersDefender())
            elif defense["type"] == "instructional_prevention":
                config["defense"].add_defense(InstructionalPrevention())
            elif defense["type"] == "tool_use_guard":
                config["defense"].add_defense(ToolUseGuard({"pid": os.getpid()}))
            else:
                # unknown defense
                print(f"Unknown defense {defense}")

    # print(config)
    return config

def run_test(config_file):
    config = load_config(config_file)
    agent = Agent(config)
    agent.run_task(config["task_input"])
    if "post_task_input" in config:
        agent.run_task(config["post_task_input"])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Please input target config files. i.e., python test.py config.json")

    run_test(sys.argv[1])