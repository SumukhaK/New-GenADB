//go:build !unix

package audit

import "os"

// On platforms without flock, appends from one process are still serialized
// by FileSink's mutex; run one writer per log there.
func lockFile(*os.File) error   { return nil }
func unlockFile(*os.File) error { return nil }
