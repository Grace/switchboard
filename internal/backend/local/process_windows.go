//go:build windows

package local

import (
	"os"
	"os/exec"
)

// configureProcess is a no-op on Windows, which has no POSIX process groups.
func configureProcess(cmd *exec.Cmd) {}

// signalGroup can only terminate on Windows. Graceful interrupts are not
// deliverable to a child console process, so the interrupt attempt is skipped
// and halt's escalation to Kill does the work.
func signalGroup(cmd *exec.Cmd, sig os.Signal) {
	if cmd.Process == nil || sig == os.Interrupt {
		return
	}
	_ = cmd.Process.Kill()
}
