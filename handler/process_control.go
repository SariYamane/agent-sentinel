package handler

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"os"
	"strings"
	"syscall"
	"time"
)

func resumeProcess(pid int) error {
	err := syscall.Kill(pid, syscall.SIGCONT)

	if err != nil {
		return err
	}

	log.Debug().Msgf("handler_process_control: resume process %d", pid)
	return nil
}

// readProcessState returns the state character from /proc/<pid>/stat
// (e.g. "R", "S", "T"), or "" if the process no longer exists.
func readProcessState(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	// Format is "pid (comm) state ...". comm can itself contain
	// spaces/parens, so find the state field after the last ')'.
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx == -1 || idx+2 >= len(s) {
		return "", fmt.Errorf("handler_process_control: unexpected /proc/%d/stat format", pid)
	}

	fields := strings.Fields(s[idx+2:])
	if len(fields) == 0 {
		return "", fmt.Errorf("handler_process_control: unexpected /proc/%d/stat format", pid)
	}

	return fields[0], nil
}

// resumeProcessReliably sends SIGCONT and then double-checks that the
// process actually left the stopped state before giving up.
//
// bpf_send_signal(SIGSTOP) is delivered asynchronously by the kernel: the
// process can still transition into the stopped state slightly after our
// SIGCONT has already been sent and processed. When that race is lost, the
// process is left stopped with nobody left to wake it up, since we already
// consider this enforcement event resolved. Re-checking and re-sending
// SIGCONT a few times over roughly one second closes that window without
// touching any actual security decision (the decision to resume was already
// made by the filter or the auditor before this function is called).
func resumeProcessReliably(pid int) error {
	if err := resumeProcess(pid); err != nil {
		return err
	}

	go func() {
		delays := []time.Duration{
			50 * time.Millisecond,
			150 * time.Millisecond,
			300 * time.Millisecond,
			500 * time.Millisecond,
		}

		for _, d := range delays {
			time.Sleep(d)

			state, err := readProcessState(pid)
			if err != nil || state == "" {
				return
			}

			if state != "T" {
				return
			}

			log.Warn().Msgf("handler_process_control: process %d still stopped after resume, retrying SIGCONT", pid)
			if err := resumeProcess(pid); err != nil {
				return
			}
		}
	}()

	return nil
}

func terminateProcess(pid int) error {
	err := syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		return err
	}

	log.Debug().Msgf("handler_process_control: terminate process %d", pid)
	return nil
}
