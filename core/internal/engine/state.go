package engine

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// PairedDevices lists the device ids this desktop state directory has pinned.
func PairedDevices(state string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(state, "peers"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(e.Name())
		if err != nil {
			continue
		}
		if _, err := loadPeer(state, string(b)); err == nil {
			ids = append(ids, string(b))
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// ForgetDevice removes the pin for a paired device.
func ForgetDevice(state, id string) error {
	err := os.Remove(peerPath(state, id))
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotPaired
	}
	return err
}

// HasIdentity reports whether state already holds an identity key.
func HasIdentity(state string) bool {
	_, err := os.Stat(filepath.Join(state, "identity.key"))
	return err == nil
}
