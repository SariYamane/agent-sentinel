package helper

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// const cgroupPath = "/sys/fs/cgroup/unified/docker"
const cgroupRoot = "/sys/fs/cgroup"

func FindCgroupV2Path(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] != "0" {
			continue
		}

		path := filepath.Join(
			cgroupRoot,
			strings.TrimPrefix(fields[2], "/"),
		)

		var st syscall.Statfs_t
		if err := syscall.Statfs(path, &st); err != nil {
			return "", err
		}
		if st.Type != unix.CGROUP2_SUPER_MAGIC {
			return "", fmt.Errorf("cgroup v2 is not enabled")
		}

		return path, nil
	}

	return "", fmt.Errorf("cgroup v2 path not found for pid %d", pid)
}
