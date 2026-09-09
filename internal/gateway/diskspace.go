package gateway

import "syscall"

// freeBytes reports the space available to an unprivileged writer on the
// filesystem holding path, or an error if that cannot be determined.
//
// Used to cross-check the three store budgets at startup rather than to police
// them at runtime: the stores enforce their own limits, and this exists so that
// a config promising more than the volume holds is rejected before it is
// discovered as three simultaneous write failures with no shared explanation.
//
// syscall rather than golang.org/x/sys, deliberately: this is one call on the
// startup path and it does not justify a dependency. Bavail rather than Bfree,
// because the blocks Bfree includes are reserved and not available to the
// gateway's user. The conversions are what make one expression compile on both
// Linux, where Bsize is int64, and Darwin, where it is uint32.
func freeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
