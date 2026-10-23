package privhelper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const replaySchema = "agent-helper-replay/v1"

var ErrReplayStorage = errors.New("durable replay storage unavailable")

// FileReplayStore is a small local reservation primitive. Its directory must
// be provisioned by trusted configuration; production deployment must place
// it in a root-owned 0700 directory inaccessible to the unprivileged agent.
// A corrupt or partial reservation is never removed or treated as unused.
type FileReplayStore struct {
	directory string
}

type replayRecord struct {
	Schema        string `json:"schema"`
	JTI           string `json:"jti"`
	RequestDigest string `json:"request_digest"`
	State         string `json:"state"`
}

func NewFileReplayStore(directory string) (*FileReplayStore, error) {
	if directory == "" || !filepath.IsAbs(directory) {
		return nil, errors.New("replay directory must be an absolute configured path")
	}
	return &FileReplayStore{directory: filepath.Clean(directory)}, nil
}

func (s *FileReplayStore) Reserve(jti, requestDigest string) error {
	if s == nil || !validRequestID(jti) || !validDigest(requestDigest) {
		return fmt.Errorf("%w: invalid reservation fields", ErrReplayStorage)
	}
	if err := s.ensureDirectory(); err != nil {
		return fmt.Errorf("%w: %v", ErrReplayStorage, err)
	}
	key := sha256.Sum256([]byte(jti))
	path := filepath.Join(s.directory, hex.EncodeToString(key[:])+".json")
	data, err := json.Marshal(replayRecord{
		Schema: replaySchema, JTI: jti, RequestDigest: requestDigest, State: "reserved",
	})
	if err != nil {
		return fmt.Errorf("%w: encode reservation", ErrReplayStorage)
	}
	file, err := os.CreateTemp(s.directory, ".pending-replay-*")
	if err != nil {
		return fmt.Errorf("%w: create reservation staging file", ErrReplayStorage)
	}
	stagingPath := file.Name()
	defer func() { _ = os.Remove(stagingPath) }()
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("%w: restrict reservation staging file", ErrReplayStorage)
	}
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = errors.New("short replay record write")
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("%w: persist reservation", ErrReplayStorage)
	}
	if err := os.Link(stagingPath, path); errors.Is(err, os.ErrExist) {
		return s.existingReservation(path, jti, requestDigest)
	} else if err != nil {
		return fmt.Errorf("%w: publish reservation", ErrReplayStorage)
	}
	if err := syncReplayDirectory(s.directory); err != nil {
		return fmt.Errorf("%w: sync reservation directory", ErrReplayStorage)
	}
	return nil
}

func (s *FileReplayStore) ensureDirectory() error {
	if err := os.MkdirAll(s.directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(s.directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("replay directory must be a non-symlink private directory")
	}
	return nil
}

func (s *FileReplayStore) existingReservation(path, expectedJTI, expectedDigest string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2048 {
		return fmt.Errorf("%w: existing reservation is unreadable or unsafe", ErrReplayStorage)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: read existing reservation", ErrReplayStorage)
	}
	var record replayRecord
	if err := decodeStrict(data, &record); err != nil || record.Schema != replaySchema || record.JTI != expectedJTI || record.State != "reserved" || !validDigest(record.RequestDigest) {
		return fmt.Errorf("%w: existing reservation is corrupt", ErrReplayStorage)
	}
	if record.RequestDigest != expectedDigest {
		return ErrReplayConflict
	}
	return ErrReplay
}

func syncReplayDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value[len("sha256:"):]
}
