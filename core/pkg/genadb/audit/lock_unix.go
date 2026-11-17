//go:build unix

package audit

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock so that several processes
// appending to one log (two connect agents sharing a state directory) keep a
// single unbroken chain.
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
