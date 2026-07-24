import json
import os
import signal
import subprocess
import sys
import time
import io
import datetime
import tarfile
import traceback

import docker
import docker.errors


HOST_MOUNT_DIR = "/home/arcana/.anthropic"
CON_MOUNT_DIR = "/home/computeruse/.anthropic"
AGENT_IMAGE = "computer-use-demo-test"
AGENT_USER = "computeruse"
AGENT_LOG_FILE = "/tmp/agent_running.log"
AGENT_TEST_FILE = "/home/computeruse/scripts/test_config.json"

# change it to absolute path
TIMEOUT_TABLE = {
    "/home/arcana/experiment/agent-sentinel/tests/dataset/attacks/attack4agent2/attack4agent2.json" : 300
}

def copy_from_host_to_container(con, host_path, con_path):
    stream = io.BytesIO()

    with tarfile.open(fileobj=stream, mode="w") as tar:
        tar.add(name=host_path, arcname=os.path.basename(con_path))

    con.put_archive(os.path.dirname(con_path), stream.getvalue())

def copy_from_container_to_host(con, con_path, host_path):
    buf, stat = con.get_archive(con_path)
    stream = io.BytesIO()
    for chunk in buf:
        stream.write(chunk)
    stream.seek(0)

    with tarfile.open(fileobj=stream, mode="r") as tar:
        if tar.getmember(os.path.basename(con_path)).isfile():
            # write the content if the target file is a regular file
            with open(host_path, "wb") as f:
                f.write(tar.extractfile(os.path.basename(con_path)).read())
        else:
            tar.extract(os.path.basename(con_path), os.path.dirname(host_path))
            os.rename(os.path.dirname(host_path) + "/" + os.path.basename(con_path), host_path)

def get_container_ip(con_id):
    client = docker.from_env()
    return client.api.inspect_container(con_id)['NetworkSettings']['Networks']['bridge']['IPAddress']

def start_mock_server(image_name):
    client = docker.from_env()
    con = client.containers.run(
        image=image_name,
        auto_remove=True,
        detach=True
    )

    # check the container is ready
    while True:
        log = con.logs()
        if b"Mock server is ready" in log:
            break
        time.sleep(2)

    print(f"[*] Mock server {con.short_id} is ready")
    return con

def load_basic_config(config_file):
    with open(config_file, "r") as f:
        data = json.load(f)

    config = {
        "model": data["model"],
        "api_key": data["api_key"],
        "n_images": data["n_images"],
        "max_requests": 30,
        "enable_console_log": False,
        "output_dir": ""
    }

    if "max_requests" in data:
        config["max_requests"] = data["max_requests"]

    if "enable_console_log" in data:
        config["enable_console_log"] = data["enable_console_log"]

    if "output_dir" in data:
        config["output_dir"] = os.path.realpath(data["output_dir"], strict=True)
    else:
        config["output_dir"] = os.path.join(os.getcwd(), "task_output_" + str(round(datetime.datetime.now().timestamp())))

    if not os.path.exists(config["output_dir"]):
        os.makedirs(config["output_dir"])

    if "attack" in data:
        config["attack"] = data["attack"]
    if "defenses" in data:
        config["defenses"] = data["defenses"]

    config["mock_servers"] = {}
    if "mock_servers" in data:
        for server in data["mock_servers"]:
            config["mock_servers"][server] = start_mock_server(server)

    return config

# task config
def load_task_config(config_file):
    with open(config_file, "r") as f:
        data = json.load(f)

    config = {
        "id": data["id"],
        # TODO system prompt
        "instruction": data["instruction"],
        "config": data["config"],
    }

    if "post_instruction" in data:
        config["post_instruction"] = data["post_instruction"]

    return config

# test config for run agent test
def generate_test_config(basic, task):
    test = {
        "model": basic["model"],
        "api_key": basic["api_key"],
        "n_images": basic["n_images"],
        "system_prompt": "",
        "messages": [],
        "max_requests": basic["max_requests"],
        "task_input": task["instruction"],
        "enable_console_log": basic["enable_console_log"],
    }

    if "output_dir" in basic:
        test["output_file_log"] = AGENT_LOG_FILE
    if "attack" in basic:
        test["attack"] = basic["attack"]
    if "defenses" in basic:
        test["defenses"] = basic["defenses"]

    if "post_instruction" in task:
        test["post_task_input"] = task["post_instruction"]

    test_file = basic["output_dir"] + "/" + task["id"] + "_test_config.json"
    with open(test_file, "w") as f:
        json.dump(test, f)

    print("[*] Task input: {}".format(test["task_input"]))
    if "post_task_input" in test:
        print("[*] Post task input: {}".format(test["post_task_input"]))
    print("[*] Enabled defenses: {}".format(".".join(map(lambda x: x["type"], test["defenses"])) if "defenses" in test else "None"))
    print("[*] Enabled attack: {}".format(test["attack"]["type"] if "attack" in test else "None"))

    return test, test_file

def setup_running_env(con, setup, mock_servers):
    for step in setup:
        if step["type"] == "docker_cp":
            files = step["parameters"]["files"]
            for file in files:
                copy_from_host_to_container(con, file["src"], file["dest"])
            # FIXME: error check?
        elif step["type"] == "docker_exec":
            cmd = step["parameters"]["cmd"]
            user = step["parameters"]["user"] if "user" in step["parameters"] else "root"
            detach = step["parameters"]["detach"] if "detach" in step["parameters"] else False

            exitcode, output = con.exec_run(
                detach=detach,
                user=user,
                cmd=cmd,
            )
            # FIXME: error check???
        elif step["type"] == "docker_network":
            hosts = step["parameters"]["hosts"]
            for host in hosts:
                con_name = host["image_name"]
                hostname = host["hostname"]
                mock_con = mock_servers[con_name]
                mock_con_ip = get_container_ip(mock_con.short_id)
                host_pair = f"{mock_con_ip} {hostname}"
                exitcode, output = con.exec_run(
                    # FIXME: parameterize???
                    user="root",
                    cmd=f"bash -c \"echo '{host_pair}' >> /etc/hosts\""
                )

    print(f"[*] Task environment is ready")

def preload_running_env(setup):
    params = {}
    for step in setup:
        if step["type"] == "docker_evn":
            params["env"] = []
            env = step["parameters"]["env"]
            for e in env:
                params["env"].append(e)

    return params

def start_computer_use_demo_env(params):
    env = [
        "COMPUTER_MONITOR_SOCK=/home/computeruse/.anthropic/computer-monitor.sock",
        f"OPENROUTER_API_KEY={os.environ['OPENROUTER_API_KEY']}",
        f"OPENROUTER_BASE_URL={os.environ['OPENROUTER_BASE_URL']}",
    ]

    if "env" in params:
        env.extend(params["env"])

    client = docker.from_env()
    con = client.containers.run(
        image=AGENT_IMAGE,
        volumes=[
            f"{HOST_MOUNT_DIR}:{CON_MOUNT_DIR}"
        ],
        environment=env,
        # ports={
        #     5900:5900,
        #     8501:8501,
        #     6080:6080,
        #     8080:8080,
        # },
        auto_remove=True,
        detach=True
    )

    # check the container is ready
    while True:
        log = con.logs()
        if b"Computer Use Demo is ready" in log:
            break
        time.sleep(2)

    print(f"[*] Computer use demo {con.short_id} is ready")

    return con

def setup_sandbox(computer_use_con, log_file, model):
    con_id = computer_use_con.short_id
    args = ["sudo","./start_sandbox.sh", f"{con_id}"]
    if log_file != "":
        args.append(log_file)
        args.append(model)

    proc = subprocess.Popen(
        args=args,
        # stderr=subprocess.PIPE,
        # stdout=subprocess.PIPE,
        bufsize=0,
    )

    while True:
        if os.path.exists(log_file):
            with open(log_file) as f:
                lines = f.readlines()
                if len(lines) > 0 and "server started, waiting incoming connection" in lines[-1]:
                    break
        time.sleep(1)

    print("[*] sandbox is ready")

    return proc


def stop_sandbox():
    subprocess.run(
        ["sudo", "./stop_sandbox.sh"]
    )

def setup_tool_use_guard(log_file, model):
    args = ["./start_tool_use_guard.sh"]
    if log_file != "":
        args.append(log_file)
        args.append(model)

    proc = subprocess.Popen(
        args=args,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        bufsize=0,
    )

    while True:
        if os.path.exists(log_file):
            with open(log_file) as f:
                lines = f.readlines()
                if len(lines) > 0 and "server started, waiting incoming connection" in lines[-1]:
                    break
        time.sleep(1)

    print("[*] tool_use_guard is ready")

    return proc

def stop_tool_use_guard(proc):
    proc.terminate()

def run_single_task(con, test_file, stream = False, timeout = -1):
    # put test_config.json into container
    copy_from_host_to_container(con, test_file, AGENT_TEST_FILE)

    # some tasks never stop by themselves, so we need force kill them
    if timeout != -1:
        cmdline = f"timeout {timeout}s python scripts/test.py {AGENT_TEST_FILE}"
    else:
        cmdline = f"python scripts/test.py {AGENT_TEST_FILE}"

    exitcode, output = con.exec_run(
        user="computeruse",
        stream=stream,
        cmd=cmdline,
        demux=True
    )

    if stream:
        print("--------output_stream--------")
        stdout_data = b""
        stderr_data = b""
        for chunk in output:
            if chunk[0] is not None:
                stdout_data = stdout_data + chunk[0]
                print(chunk[0].decode(), end="")
            if chunk[1] is not None:
                stderr_data = stderr_data + chunk[1]
                print(chunk[1].decode(), end="")
        return 0, stdout_data, stderr_data
    else:
        return exitcode, output[0], output[1]

def run (basic_config_file, task_config_file):
    run_single_task_error_file = ""
    basic_config_file = os.path.realpath(basic_config_file, strict=True)
    task_config_file = os.path.realpath(task_config_file, strict=True)
    container = None
    sandbox_proc = None
    tool_use_guard_proc = None
    basic_config = None

    try:
        # load config
        basic_config = load_basic_config(basic_config_file)
        task_config = load_task_config(task_config_file)
        test_config, test_file = generate_test_config(basic_config, task_config)

        # setup log files
        run_single_task_error_file = basic_config["output_dir"] + "/" + task_config["id"] + "_run_single_task_error.log"
        agent_log_file = basic_config["output_dir"] + "/" + task_config["id"] + "_agent_output.log"
        agent_error_file = basic_config["output_dir"] + "/" + task_config["id"] + "_agent_error.log"
        sandbox_log_file = basic_config["output_dir"] + "/" + task_config["id"] + "_sandbox_output.log"
        sandbox_error_file = basic_config["output_dir"] + "/" + task_config["id"] + "_sandbox_error.log"
        tool_use_guard_log_file = basic_config["output_dir"] + "/" + task_config["id"] + "_tool_use_guard_output.log"
        tool_use_guard_error_file = basic_config["output_dir"] + "/" + task_config["id"] + "_tool_use_guard_error.log"

        # setup running environment
        preload_params = preload_running_env(task_config["config"])
        container = start_computer_use_demo_env(preload_params)
        # switch to task dir
        cwd = os.getcwd()
        os.chdir(os.path.dirname(task_config_file))
        setup_running_env(container, task_config["config"], basic_config["mock_servers"])
        # switch back cwd
        os.chdir(cwd)

        if "defenses" in test_config:
            for defense in test_config["defenses"]:
                if defense["type"] == "sandbox" and sandbox_proc is None:
                    sandbox_proc = setup_sandbox(container, sandbox_log_file, basic_config["model"])
                if defense["type"] == "tool_use_guard" and tool_use_guard_proc is None:
                    tool_use_guard_proc = setup_tool_use_guard(tool_use_guard_log_file, basic_config["model"])

        if task_config_file in TIMEOUT_TABLE:
            exitcode, stdout, stderr = run_single_task(container, test_file, basic_config["enable_console_log"], TIMEOUT_TABLE[task_config_file])
        else:
            exitcode, stdout, stderr = run_single_task(container, test_file, basic_config["enable_console_log"])

        if stdout is not None and stdout != b"":
            print("----------agent_stdout-------------")
            print(stdout.decode())

        if agent_log_file != "":
            copy_from_container_to_host(container, AGENT_LOG_FILE, agent_log_file)

        # handle errors from agent
        if stderr is not None and stderr != b"":
            print("----------agent_stderr-------------")
            print(stderr.decode())
            if agent_error_file != "":
                with open(agent_error_file, "wb") as f:
                    f.write(stderr)

        stop_sandbox()
        if sandbox_proc is not None:
            # FIXME: blocking???
            sandbox_output = sandbox_proc.communicate()
            # handle errors from sandbox
            if sandbox_output[1] is not None and sandbox_output[1] != b"":
                print("----------sandbox_stderr-------------")
                print(sandbox_output[1].decode())
                if sandbox_error_file != "":
                    with open(sandbox_error_file, "wb") as f:
                        f.write(sandbox_output[1])

        if tool_use_guard_proc is not None:
            stop_tool_use_guard(tool_use_guard_proc)
            tool_use_guard_output = tool_use_guard_proc.communicate()
            if tool_use_guard_output[1] is not None and tool_use_guard_output[1] != b"":
                print("----------tool_use_guard_stderr-------------")
                print(tool_use_guard_output[1].decode())
                if tool_use_guard_error_file != "":
                    with open(tool_use_guard_error_file, "wb") as f:
                        f.write(tool_use_guard_output[1])

        # close containers
        container.stop()
        for name in basic_config["mock_servers"]:
            basic_config["mock_servers"][name].stop()

    except Exception as e:
        if container is not None:
            container.stop()
        if basic_config is not None and "mock_servers" in basic_config:
            for name in basic_config["mock_servers"]:
                basic_config["mock_servers"][name].stop()
        stop_sandbox()
        if tool_use_guard_proc is not None:
            stop_tool_use_guard(tool_use_guard_proc)

        print("----------run_single_task_exception-------------")
        print(str(e))
        print(traceback.format_exc())
        # TODO: better log
        if run_single_task_error_file != "":
            with open(run_single_task_error_file, "w") as f:
                f.write(str(e))
                f.write(traceback.format_exc())

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Please input config files. i.e., python run_single_tast.py basic.json task.json")

    run(sys.argv[1], sys.argv[2])