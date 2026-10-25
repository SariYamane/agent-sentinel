## Environment Requirement

Our test environment configuration as follows.

- Ubuntu 24.04
- Docker version 27.2.1
- LLVM-12 (required by ebpf-go)
- libbpf-dev (ubuntu24.04)
- Enable BPF-LSM. Check `cat /sys/kernel/security/lsm` to ensure it is enabled.
- Golang: go1.23.3 linux/amd64
- Python 3.11


## Build Test Environment

### Compile AgentSentinel
Download (by `git clone git@github.com:m4p1e/agent-sentinel.git`) and move this entire project to `$GOPATH`.

```bash
# install go dependency
go mod download

# (optional) manually compile eBPF program
go generate ./...

# compile
go build
```
You will get a binary named `agent-sentinel`.

### Build Computer-Use Agent
```bash
cd tests/claude_computer_use_demo_test/
docker build . -t computer-use-demo-test
```
Ensure that no image name collsion for `computer-use-demo-test`.

### Build Mock Server

```bash
cd tests/scripts/attack_mock_server
docker build . -t computer-use-demo-test-attack-server
```
Ensure that no image name collsion for `computer-use-demo-test-attack-server`.


### Create Basic Mount Directory

For mounting the monitoring server socket file.

```
mkdir ~/.anthropic
```

### Configure SUDO Permission for Run AgentSentinel

Add `$project_dir/tests/scripts/start_sandbox.sh` and `$project_dir/tests/scripts/stop_sandbox.sh` to `/etc/sudoers`. To make sure that AgentSentinel can run with ROOT permission.

For example
```
sudo cat /etc/sudoers
# ...
# your_username ALL = NOPASSWD:$project_dir/tests/scripts/start_sandbox.sh
# your_username ALL = NOPASSWD:$project_dir/tests/scripts/stop_sandbox.sh
```

### Set API Key

Add related envrionmenet variables.
```bash
# for claude models
export ANTHROPIC_API_KEY=xxx
# for openai models
export OPENAI_API_KEY=xxx
```
Modify these envrionmenet variables in `tests/scripts/start_sandbox.sh` and `tests/scripts/start_tool_use_guard.sh`.


Modify `api_key` in following basic config files:

- `tests/scripts/claude35_basic_config.json`
- `tests/scripts/claude37_basic_config.json`
- `tests/scripts/gpt_4_turbo_basic_config.json`
- `tests/scripts/gpt_4o_basic_config.json`


### Install Require Python Package for Run Test Scripts

```
pip install docker
```

### Patch some File Paths

For `tests/scripts/run_single_task.py`:
```diff
- HOST_MOUNT_DIR = "~/.anthropic"
+ HOST_MOUNT_DIR = "absolute_path_of_your_home_dir/.anthropic"

- "../dataset/attacks/attack4agent2/attack4agent2.json" : 300
+ "absolute_path_of_agentsentinel_dir/tests/dataset/attacks/attack4agent2/attack4agent2.json" : 300
```

For `tests/scripts/start_sandbox.sh` and `tests/scripts/start_tool_use_guard.sh`:
```diff
- -mount-path=~/.anthropic \
+ -mount-path=absolute_path_of_your_home_dir/.anthropic \
```

## Run Test

Ensure that above environment configuration is done.

First, move workdir to `cd tests/scripts`.

Try for a test:
```
python run_single_task.py example_basic_config_normal.json example_task_config.json
```

To run a experiment:
```bash
# run direct task injection attacks, with agent (claude 3.5 sonnet), no defense
python run_all_tasks.py -c claude35_basic_config.json -t all_attack_task.json -a direct_task_inject

# run direct task injection attacks, with agent (gpt-4o), no defense
python run_all_tasks.py -c gpt_4o_basic_config.json -t all_attack_task.json -a direct_task_inject

# run direct task injection attacks, with agent (claude 3.5 sonnet), with AgentSentinel defense
python run_all_tasks.py -c claude35_basic_config.json -t all_attack_task.json -a direct_task_inject -d sandbox

# ...
```
More experiment commands can be seen in `run_all_tasks.py`.