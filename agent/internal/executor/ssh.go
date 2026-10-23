package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/state"
)

const (
	ActionSSHRootLogin = "ACT-SSH-5.1.20"

	SSHDropInPath = "/etc/ssh/sshd_config.d/99-autonomous-hardening-agent.conf"

	StateDirectory = "/var/lib/autonomous-hardening-agent/state"
)

type ExecutionState struct {
	ActionID               string          `json:"action_id"`
	File                   state.FileState `json:"file"`
	PreviousEffectiveValue string          `json:"previous_effective_value"`
	CapturedAt             time.Time       `json:"captured_at"`
}

type ExecutionResult struct {
	ActionID  string `json:"action_id"`
	Status    string `json:"status"`
	Before    string `json:"before"`
	After     string `json:"after"`
	StatePath string `json:"state_path"`
	Message   string `json:"message"`
}

type sshOperations struct {
	statePath                string
	dropInPath               string
	requireRoot              func() error
	effectivePermitRootLogin func() (string, error)
	captureFile              func(string) (state.FileState, error)
	saveState                func(string, ExecutionState) error
	loadState                func(string) (ExecutionState, error)
	writeDropIn              func(string) error
	validateSSHConfig        func() error
	reloadSSH                func() error
	restoreFile              func(state.FileState) error
	verifyRestoredFile       func(state.FileState) error
}

func ApplySSHRootLoginDisable() (ExecutionResult, error) {
	return applySSHRootLoginDisable(systemSSHOperations())
}

func applySSHRootLoginDisable(ops sshOperations) (ExecutionResult, error) {
	if err := ops.requireRoot(); err != nil {
		return ExecutionResult{}, err
	}

	previous, err := ops.effectivePermitRootLogin()
	if err != nil {
		return ExecutionResult{}, err
	}
	if previous == "no" {
		return ExecutionResult{
			ActionID:  ActionSSHRootLogin,
			Status:    "ALREADY_COMPLIANT",
			Before:    previous,
			After:     previous,
			StatePath: ops.statePath,
			Message:   "SSH root login is already disabled; no changes made",
		}, nil
	}

	fileState, err := ops.captureFile(ops.dropInPath)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("failed to capture SSH drop-in recovery state: %w", err)
	}

	executionState := ExecutionState{
		ActionID:               ActionSSHRootLogin,
		File:                   fileState,
		PreviousEffectiveValue: previous,
		CapturedAt:             time.Now().UTC(),
	}
	if err := validateExecutionState(executionState, ops.dropInPath); err != nil {
		return ExecutionResult{}, fmt.Errorf("captured recovery state is invalid; refusing execution: %w", err)
	}
	if err := ops.saveState(ops.statePath, executionState); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ExecutionResult{}, fmt.Errorf("recovery snapshot already exists; refusing to overwrite it or re-execute action: %w", err)
		}
		return ExecutionResult{}, fmt.Errorf("state capture persistence failed; refusing execution: %w", err)
	}

	if err := ops.writeDropIn("PermitRootLogin no\n"); err != nil {
		return ExecutionResult{}, executionFailureWithRecovery("writing SSH hardening drop-in", err, executionState, ops)
	}

	if err := ops.validateSSHConfig(); err != nil {
		return ExecutionResult{}, executionFailureWithRecovery("SSH configuration validation", err, executionState, ops)
	}

	if err := ops.reloadSSH(); err != nil {
		return ExecutionResult{}, executionFailureWithRecovery("SSH service reload", err, executionState, ops)
	}

	current, err := ops.effectivePermitRootLogin()
	if err != nil {
		return ExecutionResult{}, executionFailureWithRecovery("reading effective SSH configuration for verification", err, executionState, ops)
	}
	if current != "no" {
		verificationErr := fmt.Errorf("expected permitrootlogin=no, got %s", current)
		return ExecutionResult{}, executionFailureWithRecovery("SSH configuration verification", verificationErr, executionState, ops)
	}

	return ExecutionResult{
		ActionID:  ActionSSHRootLogin,
		Status:    "VERIFIED",
		Before:    previous,
		After:     current,
		StatePath: ops.statePath,
		Message:   "SSH root login hardening applied and verified",
	}, nil
}

func RollbackSSHRootLogin() (ExecutionResult, error) {
	return rollbackSSHRootLogin(systemSSHOperations())
}

func rollbackSSHRootLogin(ops sshOperations) (ExecutionResult, error) {
	if err := ops.requireRoot(); err != nil {
		return ExecutionResult{}, err
	}

	executionState, err := ops.loadState(ops.statePath)
	if err != nil {
		return ExecutionResult{}, err
	}
	if err := rollbackFromState(executionState, ops); err != nil {
		return ExecutionResult{}, err
	}

	current, err := ops.effectivePermitRootLogin()
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("rollback completed but effective SSH configuration verification failed: %w", err)
	}
	expected := executionState.PreviousEffectiveValue
	if current != expected {
		return ExecutionResult{}, fmt.Errorf(
			"rollback verification failed: expected effective PermitRootLogin=%s, got %s",
			expected,
			current,
		)
	}

	return ExecutionResult{
		ActionID:  ActionSSHRootLogin,
		Status:    "ROLLED_BACK",
		Before:    "no",
		After:     current,
		StatePath: ops.statePath,
		Message:   "SSH root login change rolled back and verified",
	}, nil
}

func rollbackFromState(executionState ExecutionState, ops sshOperations) error {
	if err := validateExecutionState(executionState, ops.dropInPath); err != nil {
		return fmt.Errorf("recovery state validation failed: %w", err)
	}
	if err := ops.restoreFile(executionState.File); err != nil {
		return fmt.Errorf("state restoration failed: %w", err)
	}
	if err := ops.verifyRestoredFile(executionState.File); err != nil {
		return fmt.Errorf("restored file verification failed: %w", err)
	}
	if err := ops.validateSSHConfig(); err != nil {
		return fmt.Errorf("restored SSH configuration is invalid: %w", err)
	}
	if err := ops.reloadSSH(); err != nil {
		return fmt.Errorf("SSH reload after rollback failed: %w", err)
	}
	return nil
}

func executionFailureWithRecovery(operation string, originalErr error, executionState ExecutionState, ops sshOperations) error {
	recoveryErr := rollbackFromState(executionState, ops)
	if recoveryErr != nil {
		return errors.Join(
			fmt.Errorf("%s failed: %w", operation, originalErr),
			fmt.Errorf("automatic rollback failed: %w", recoveryErr),
		)
	}

	recoveredValue, err := ops.effectivePermitRootLogin()
	if err != nil {
		return errors.Join(
			fmt.Errorf("%s failed: %w", operation, originalErr),
			fmt.Errorf("automatic recovery verification failed: could not read effective PermitRootLogin: %w", err),
		)
	}
	if recoveredValue != executionState.PreviousEffectiveValue {
		return errors.Join(
			fmt.Errorf("%s failed: %w", operation, originalErr),
			fmt.Errorf(
				"automatic recovery verification failed: expected effective PermitRootLogin=%s, got %s",
				executionState.PreviousEffectiveValue,
				recoveredValue,
			),
		)
	}
	return fmt.Errorf("%s failed; automatic rollback succeeded and effective state was verified: %w", operation, originalErr)
}

func validateExecutionState(executionState ExecutionState, expectedPath string) error {
	if executionState.ActionID != ActionSSHRootLogin {
		return fmt.Errorf("unexpected action ID %q", executionState.ActionID)
	}
	if executionState.File.Path != expectedPath {
		return fmt.Errorf("unexpected recovery file path %q", executionState.File.Path)
	}
	if !executionState.File.Exists {
		if len(executionState.File.Content) != 0 || executionState.File.ContentSHA != "" {
			return fmt.Errorf("absent-file recovery state contains content or a content digest")
		}
		return nil
	}
	if executionState.File.Mode&^uint32(0777) != 0 {
		return fmt.Errorf("invalid recovery file mode %#o", executionState.File.Mode)
	}
	if digest := contentSHA256(executionState.File.Content); digest != executionState.File.ContentSHA {
		return fmt.Errorf("recovery content SHA-256 mismatch: recorded %q, computed %q", executionState.File.ContentSHA, digest)
	}
	return nil
}

func writeDropIn(content string) error {
	return writeDropInAt(SSHDropInPath, content)
}

func writeDropInAt(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	temp, err := os.CreateTemp(dir, ".hardening-agent-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if err := temp.Chmod(0644); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.WriteString(content); err != nil {
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
	return os.Rename(tempPath, path)
}

func effectivePermitRootLogin() (string, error) {
	return effectivePermitRootLoginWithConfig("")
}

func effectivePermitRootLoginWithConfig(configPath string) (string, error) {
	args := []string{"-T"}
	if configPath != "" {
		args = append(args, "-f", configPath)
	}
	output, err := exec.Command("/usr/sbin/sshd", args...).Output()
	if err != nil {
		return "", fmt.Errorf("failed to read effective SSH configuration: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "permitrootlogin") {
			return strings.ToLower(fields[1]), nil
		}
	}
	return "", fmt.Errorf("effective PermitRootLogin value not found")
}

func validateSSHConfig() error {
	return validateSSHConfigWithConfig("")
}

func validateSSHConfigWithConfig(configPath string) error {
	args := []string{"-t"}
	if configPath != "" {
		args = append(args, "-f", configPath)
	}
	command := exec.Command("/usr/sbin/sshd", args...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func reloadSSH() error {
	command := exec.Command("systemctl", "reload", "ssh.service")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func saveExecutionState(path string, executionState ExecutionState) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(executionState, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, ".state-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
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

	// A hard link publishes the fully written snapshot atomically and fails if
	// the destination already exists, unlike rename which would replace it.
	if err := os.Link(tempPath, path); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return nil
}

func loadExecutionState(path string) (ExecutionState, error) {
	directory := filepath.Dir(path)
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		return ExecutionState{}, err
	}
	if directoryInfo.Mode().Perm()&0077 != 0 {
		return ExecutionState{}, fmt.Errorf("state directory permissions are not restrictive: %04o", directoryInfo.Mode().Perm())
	}

	info, err := os.Lstat(path)
	if err != nil {
		return ExecutionState{}, err
	}
	if !info.Mode().IsRegular() {
		return ExecutionState{}, fmt.Errorf("state file is not a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return ExecutionState{}, fmt.Errorf("state file permissions are not restrictive: %04o", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ExecutionState{}, err
	}
	var executionState ExecutionState
	if err := json.Unmarshal(data, &executionState); err != nil {
		return ExecutionState{}, err
	}
	return executionState, nil
}

func systemSSHOperations() sshOperations {
	return sshOperations{
		statePath:                filepath.Join(StateDirectory, ActionSSHRootLogin+".json"),
		dropInPath:               SSHDropInPath,
		requireRoot:              requireRoot,
		effectivePermitRootLogin: effectivePermitRootLogin,
		captureFile:              state.CaptureFile,
		saveState:                saveExecutionState,
		loadState:                loadExecutionState,
		writeDropIn:              writeDropIn,
		validateSSHConfig:        validateSSHConfig,
		reloadSSH:                reloadSSH,
		restoreFile:              state.RestoreFile,
		verifyRestoredFile:       verifyRestoredFile,
	}
}

func verifyRestoredFile(expected state.FileState) error {
	actual, err := state.CaptureFile(expected.Path)
	if err != nil {
		return err
	}
	if actual.Exists != expected.Exists {
		return fmt.Errorf("file existence mismatch: expected %t, got %t", expected.Exists, actual.Exists)
	}
	if !expected.Exists {
		return nil
	}
	if actual.ContentSHA != expected.ContentSHA {
		return fmt.Errorf("file digest mismatch: expected %s, got %s", expected.ContentSHA, actual.ContentSHA)
	}
	if string(actual.Content) != string(expected.Content) {
		return fmt.Errorf("file content does not match the captured recovery snapshot")
	}
	if actual.Mode != expected.Mode {
		return fmt.Errorf("file mode mismatch: expected %#o, got %#o", expected.Mode, actual.Mode)
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

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("agent executor requires root privileges")
	}
	return nil
}

func contentSHA256(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}
