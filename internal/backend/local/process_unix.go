//go:build !windows

package local

import (
	"os"
	"os/exec"
	"syscall"
)

// configureProcess puts the child in its own process group so we can signal it
// and everything it spawns as a unit.
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// signalGroup delivers sig to the child's process group, falling back to the
// child alone if the group is already gone.
func signalGroup(cmd *exec.Cmd, sig os.Signal) {
	if cmd.Process == nil {
		return
	}
	sysSig, ok := sig.(syscall.Signal)
	if !ok {
		_ = cmd.Process.Signal(sig)
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, sysSig); err != nil {
		_ = cmd.Process.Signal(sig)
	}
}
