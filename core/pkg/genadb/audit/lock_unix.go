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

// openShared opens a log or anchor file. On Unix an open file never stops
// another process from renaming or deleting it, so this is os.OpenFile.
func openShared(path string, flag int) (*os.File, error) { return os.OpenFile(path, flag, 0o600) }

func renameFile(from, to string) error { return os.Rename(from, to) }
