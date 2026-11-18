//go:build windows

package audit

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const lockfileExclusiveLock = 0x2

// Windows byte-range locks are mandatory: locking bytes that hold records
// would make every other handle's reads fail (scanLog, verify, reports).
// The lock therefore covers one byte far past any real log size; it still
// serialises writers across processes, exactly like flock on Unix.
const lockOffsetHigh = 0x7fffffff

// lockFile blocks until this handle holds the log's exclusive write lock.
func lockFile(f *os.File) error {
	ol := syscall.Overlapped{OffsetHigh: lockOffsetHigh}
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return &os.PathError{Op: "lock", Path: f.Name(), Err: err}
	}
	return nil
}

func unlockFile(f *os.File) error {
	ol := syscall.Overlapped{OffsetHigh: lockOffsetHigh}
	r, _, err := procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return &os.PathError{Op: "unlock", Path: f.Name(), Err: err}
	}
	return nil
}

// openShared opens a log or anchor file with FILE_SHARE_DELETE, which
// os.OpenFile does not request on Windows. Without it, an audit.jsonl held
// open by a writer (in this or another process) cannot be renamed by
// RotateFile or deleted when its directory is cleaned up, and the anchor
// cannot be replaced while a verifier is reading it. Writers that hold a
// renamed log notice the rotation (os.SameFile) and reopen the new one.
// O_APPEND is not mapped: FileSink seeks to the end, under the lock,
// before every write.
func openShared(path string, flag int) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	access := uint32(syscall.GENERIC_READ)
	if flag&(os.O_WRONLY|os.O_RDWR) != 0 {
		access |= syscall.GENERIC_WRITE
	}
	mode := uint32(syscall.OPEN_EXISTING)
	switch {
	case flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		mode = syscall.CREATE_NEW
	case flag&os.O_CREATE != 0:
		mode = syscall.OPEN_ALWAYS
	}
	share := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)
	h, err := syscall.CreateFile(p, access, share, nil, mode, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// renameFile is os.Rename, retried briefly on sharing violations: a virus
// scanner or the search indexer can hold a freshly written file for a few
// milliseconds on Windows.
func renameFile(from, to string) error {
	var err error
	for i := 0; i < 50; i++ {
		if err = os.Rename(from, to); err == nil || !transient(err) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

func transient(err error) bool {
	const errorSharingViolation = syscall.Errno(32)
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) || errors.Is(err, errorSharingViolation)
}
