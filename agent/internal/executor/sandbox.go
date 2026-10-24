package executor

// This file provides a process/filesystem-only fixture for exercising the
// reviewed SSH executor. It never opens a listener or touches host SSH files.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/state"
)

type SSHFixtureScenario string

const (
	SSHFixtureNonCompliant       SSHFixtureScenario = "noncompliant"
	SSHFixtureCompliant          SSHFixtureScenario = "compliant"
	SSHFixturePrecedenceConflict SSHFixtureScenario = "precedence-conflict"
)

// TemporarySSHConfigSandbox owns one randomly created directory. There is no
// caller-controlled target, path, command, or service name in this API.
type TemporarySSHConfigSandbox struct {
	dir       string
	config    string
	dropIn    string
	statePath string
	closed    bool
}

func NewTemporarySSHConfigSandbox(scenario SSHFixtureScenario) (*TemporarySSHConfigSandbox, error) {
	if scenario != SSHFixtureNonCompliant && scenario != SSHFixtureCompliant && scenario != SSHFixturePrecedenceConflict {
		return nil, errors.New("unsupported SSH fixture scenario")
	}
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		return nil, errors.New("OpenSSH server binary /usr/sbin/sshd is required for the local sandbox")
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return nil, errors.New("ssh-keygen is required for the local sandbox")
	}
	dir, err := os.MkdirTemp("", "aha-ssh-fixture-")
	if err != nil {
		return nil, fmt.Errorf("create temporary SSH fixture: %w", err)
	}
	sandbox := &TemporarySSHConfigSandbox{dir: dir}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(dir)
		}
	}()
	configDir := filepath.Join(dir, "sshd_config.d")
	if err := os.Mkdir(configDir, 0700); err != nil {
		return nil, err
	}
	hostKey := filepath.Join(dir, "ssh_host_ed25519_key")
	if output, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", hostKey).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("generate temporary OpenSSH host key: %s: %w", strings.TrimSpace(string(output)), err)
	}
	sandbox.config = filepath.Join(dir, "sshd_config")
	sandbox.dropIn = filepath.Join(configDir, "99-autonomous-hardening-agent.conf")
	sandbox.statePath = filepath.Join(dir, "state", ActionSSHRootLogin+".json")
	config := fmt.Sprintf("Port 22222\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nInclude %s/*.conf\nPermitEmptyPasswords no\nPermitUserEnvironment no\nUsePAM yes\n", hostKey, filepath.Join(dir, "sshd.pid"), configDir)
	if scenario == SSHFixtureCompliant {
		config = strings.Replace(config, "UsePAM yes\n", "UsePAM yes\nPermitRootLogin no\n", 1)
	}
	if err := os.WriteFile(sandbox.config, []byte(config), 0600); err != nil {
		return nil, err
	}
	if scenario == SSHFixturePrecedenceConflict {
		if err := os.WriteFile(filepath.Join(configDir, "00-site-policy.conf"), []byte("PermitRootLogin yes\n"), 0600); err != nil {
			return nil, err
		}
	}
	if err := validateSSHConfigWithConfig(sandbox.config); err != nil {
		return nil, fmt.Errorf("temporary SSH fixture is invalid: %w", err)
	}
	cleanup = false
	return sandbox, nil
}

func (s *TemporarySSHConfigSandbox) EffectiveConfig() (string, error) {
	if s == nil || s.closed {
		return "", errors.New("SSH sandbox is closed")
	}
	output, err := exec.Command("/usr/sbin/sshd", "-T", "-f", s.config).Output()
	if err != nil {
		return "", fmt.Errorf("read temporary effective SSH configuration: %w", err)
	}
	return string(output), nil
}

func (s *TemporarySSHConfigSandbox) EffectivePermitRootLogin() (string, error) {
	if s == nil || s.closed {
		return "", errors.New("SSH sandbox is closed")
	}
	return effectivePermitRootLoginWithConfig(s.config)
}

func (s *TemporarySSHConfigSandbox) Apply() (ExecutionResult, error) {
	ops, err := s.operations()
	if err != nil {
		return ExecutionResult{}, err
	}
	return applySSHRootLoginDisable(ops)
}

func (s *TemporarySSHConfigSandbox) Rollback() (ExecutionResult, error) {
	ops, err := s.operations()
	if err != nil {
		return ExecutionResult{}, err
	}
	return rollbackSSHRootLogin(ops)
}

func (s *TemporarySSHConfigSandbox) RecoveryState() (ExecutionState, error) {
	if s == nil || s.closed {
		return ExecutionState{}, errors.New("SSH sandbox is closed")
	}
	return loadExecutionState(s.statePath)
}

func (s *TemporarySSHConfigSandbox) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	return os.RemoveAll(s.dir)
}

func (s *TemporarySSHConfigSandbox) operations() (sshOperations, error) {
	if s == nil || s.closed {
		return sshOperations{}, errors.New("SSH sandbox is closed")
	}
	return sshOperations{
		statePath: s.statePath, dropInPath: s.dropIn,
		requireRoot:              func() error { return nil },
		effectivePermitRootLogin: func() (string, error) { return effectivePermitRootLoginWithConfig(s.config) },
		captureFile:              state.CaptureFile, saveState: saveExecutionState, loadState: loadExecutionState,
		writeDropIn:       func(content string) error { return writeDropInAt(s.dropIn, content) },
		validateSSHConfig: func() error { return validateSSHConfigWithConfig(s.config) },
		reloadSSH:         func() error { return nil },
		restoreFile:       state.RestoreFile, verifyRestoredFile: verifyRestoredFile,
	}, nil
}
