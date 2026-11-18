//go:build !unix && !windows

package audit

import "os"

// On platforms without flock or LockFileEx, appends from one process are
// still serialized by FileSink's mutex; run one writer per log there.
func lockFile(*os.File) error   { return nil }
func unlockFile(*os.File) error { return nil }

func openShared(path string, flag int) (*os.File, error) { return os.OpenFile(path, flag, 0o600) }

func renameFile(from, to string) error { return os.Rename(from, to) }
