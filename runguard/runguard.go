// Package runguard holds the run-wide abort state. Once Trip returns, no
// signal sent through DoUnlessAborted can reach a process, whichever goroutine
// sends it. It imports nothing from this module, so any package can use it.
package runguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

var (
	mu      sync.RWMutex
	aborted bool
	onAbort func(reason string, details map[string]any)

	statusMu   sync.Mutex
	statusFile string
)

// Trip aborts the run. It returns true only for the call that aborted it; the
// callback set by SetOnAbort runs once, on that call, after the lock is released.
func Trip(reason string, details map[string]any) bool {
	mu.Lock()
	if aborted {
		mu.Unlock()
		return false
	}
	aborted = true
	callback := onAbort
	mu.Unlock()

	if callback != nil {
		callback(reason, details)
	}
	return true
}

func Aborted() bool {
	mu.RLock()
	defer mu.RUnlock()
	return aborted
}

// DoUnlessAborted runs fn unless the run has aborted. Trip waits for running
// calls, so nothing fn does can happen after Trip has returned.
func DoUnlessAborted(fn func() error) (ran bool, err error) {
	mu.RLock()
	defer mu.RUnlock()

	if aborted {
		return false, nil
	}
	return true, fn()
}

func SetOnAbort(callback func(reason string, details map[string]any)) {
	mu.Lock()
	onAbort = callback
	mu.Unlock()
}

func ConfigureStatusFile(path string) {
	statusMu.Lock()
	statusFile = path
	statusMu.Unlock()
}

// WriteStatus atomically replaces the status file with details plus status.
// It does nothing when no status file is configured.
func WriteStatus(status string, details map[string]any) error {
	statusMu.Lock()
	defer statusMu.Unlock()

	if statusFile == "" {
		return nil
	}

	record := make(map[string]any, len(details)+1)
	for k, v := range details {
		record[k] = v
	}
	record["status"] = status

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(statusFile), filepath.Base(statusFile)+".tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	// the runner reads this file without root
	if err := tmp.Chmod(0644); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), statusFile)
}
