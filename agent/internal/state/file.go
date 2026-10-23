package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type FileState struct {
	Path       string    `json:"path"`
	Exists     bool      `json:"exists"`
	Mode       uint32    `json:"mode"`
	ContentSHA string    `json:"content_sha256"`
	Content    []byte    `json:"content,omitempty"`
	CapturedAt time.Time `json:"captured_at"`
}

func CaptureFile(path string) (FileState, error) {
	state := FileState{
		Path:       path,
		CapturedAt: time.Now().UTC(),
	}

	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return FileState{}, err
	}
	if !info.Mode().IsRegular() {
		return FileState{}, fmt.Errorf("recovery target is not a regular file: %s", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return FileState{}, err
	}

	hash := sha256.Sum256(content)

	state.Exists = true
	state.Mode = uint32(info.Mode().Perm())
	state.ContentSHA = hex.EncodeToString(hash[:])
	state.Content = content

	return state, nil
}

func RestoreFile(state FileState) error {
	if err := validateFileState(state); err != nil {
		return err
	}

	if !state.Exists {
		err := os.Remove(state.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return syncDirectory(filepath.Dir(state.Path))
	}

	dir := filepath.Dir(state.Path)

	temp, err := os.CreateTemp(dir, ".hardening-restore-*")
	if err != nil {
		return err
	}

	tempPath := temp.Name()

	defer func() {
		_ = os.Remove(tempPath)
	}()

	if err := temp.Chmod(os.FileMode(state.Mode)); err != nil {
		_ = temp.Close()
		return err
	}

	if _, err := temp.Write(state.Content); err != nil {
		_ = temp.Close()
		return err
	}

	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}

	if err := temp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tempPath, state.Path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func validateFileState(state FileState) error {
	if !state.Exists {
		if len(state.Content) != 0 || state.ContentSHA != "" {
			return fmt.Errorf("absent-file state contains content or a digest")
		}
		return nil
	}
	if state.Mode&^uint32(0777) != 0 {
		return fmt.Errorf("invalid file mode %#o", state.Mode)
	}
	digest := sha256.Sum256(state.Content)
	if state.ContentSHA != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("file content SHA-256 does not match recorded digest")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
