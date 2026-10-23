package executor

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/state"
)

func TestDuplicateExecutionCannotOverwriteInitialSnapshot(t *testing.T) {
	ops, dropInPath, statePath := testOperations(t, []byte("PermitRootLogin yes\n"), 0640)
	effectiveValues := []string{"yes", "no", "yes"}
	effectiveCalls := 0
	ops.effectivePermitRootLogin = func() (string, error) {
		value := effectiveValues[effectiveCalls]
		effectiveCalls++
		return value, nil
	}

	first, err := applySSHRootLoginDisable(ops)
	if err != nil {
		t.Fatalf("first execution: %v", err)
	}
	if first.Status != "VERIFIED" {
		t.Fatalf("first execution status = %q, want VERIFIED", first.Status)
	}

	snapshotBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read initial snapshot: %v", err)
	}
	writeCalls := 1
	ops.writeDropIn = func(content string) error {
		writeCalls++
		return os.WriteFile(dropInPath, []byte(content), 0644)
	}

	if _, err := applySSHRootLoginDisable(ops); err == nil || !strings.Contains(err.Error(), "snapshot already exists") {
		t.Fatalf("second execution error = %v, want existing snapshot rejection", err)
	}
	if writeCalls != 1 {
		t.Errorf("write called %d times, want only the first execution", writeCalls)
	}
	snapshotAfter, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read snapshot after second execution: %v", err)
	}
	if string(snapshotAfter) != string(snapshotBefore) {
		t.Error("second execution changed the original recovery snapshot")
	}
	current, err := os.ReadFile(dropInPath)
	if err != nil {
		t.Fatalf("read drop-in after second execution: %v", err)
	}
	if string(current) != "PermitRootLogin no\n" {
		t.Errorf("drop-in after rejected execution = %q, want the first execution's content", current)
	}
}

func TestAlreadyCompliantStateDoesNotOverwriteSavedSnapshot(t *testing.T) {
	ops, _, statePath := testOperations(t, []byte("PermitRootLogin no\n"), 0644)
	fileState, err := state.CaptureFile(ops.dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	prior := ExecutionState{ActionID: ActionSSHRootLogin, File: fileState, PreviousEffectiveValue: "yes"}
	if err := saveExecutionState(statePath, prior); err != nil {
		t.Fatalf("save existing snapshot: %v", err)
	}
	snapshotBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	saveCalls := 0
	ops.saveState = func(string, ExecutionState) error {
		saveCalls++
		return errors.New("must not save")
	}
	ops.effectivePermitRootLogin = func() (string, error) { return "no", nil }

	result, err := applySSHRootLoginDisable(ops)
	if err != nil {
		t.Fatalf("already-compliant execution: %v", err)
	}
	if result.Status != "ALREADY_COMPLIANT" {
		t.Errorf("status = %q, want ALREADY_COMPLIANT", result.Status)
	}
	if saveCalls != 0 {
		t.Errorf("save called %d times, want 0", saveCalls)
	}
	snapshotAfter, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshotAfter) != string(snapshotBefore) {
		t.Error("already-compliant execution changed the saved snapshot")
	}
}

func TestCorruptedSnapshotContentIsRejected(t *testing.T) {
	ops, _, _ := testOperations(t, []byte("original\n"), 0600)
	fileState, err := state.CaptureFile(ops.dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	fileState.Content = []byte("corrupted\n")
	restored := false
	ops.restoreFile = func(state.FileState) error {
		restored = true
		return nil
	}

	err = rollbackFromState(ExecutionState{ActionID: ActionSSHRootLogin, File: fileState}, ops)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("rollback error = %v, want snapshot digest rejection", err)
	}
	if restored {
		t.Error("corrupted snapshot was passed to the restore operation")
	}
}

func TestUnexpectedSavedFilePathIsRejected(t *testing.T) {
	ops, _, _ := testOperations(t, []byte("original\n"), 0600)
	fileState, err := state.CaptureFile(ops.dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	fileState.Path = filepath.Join(t.TempDir(), "unexpected.conf")
	restored := false
	ops.restoreFile = func(state.FileState) error {
		restored = true
		return nil
	}

	err = rollbackFromState(ExecutionState{ActionID: ActionSSHRootLogin, File: fileState}, ops)
	if err == nil || !strings.Contains(err.Error(), "unexpected recovery file path") {
		t.Fatalf("rollback error = %v, want path rejection", err)
	}
	if restored {
		t.Error("unexpected file path was passed to the restore operation")
	}
}

func TestUnexpectedSavedActionIDIsRejected(t *testing.T) {
	ops, _, _ := testOperations(t, []byte("original\n"), 0600)
	fileState, err := state.CaptureFile(ops.dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	restored := false
	ops.restoreFile = func(state.FileState) error {
		restored = true
		return nil
	}

	err = rollbackFromState(ExecutionState{ActionID: "ACT-UNEXPECTED", File: fileState}, ops)
	if err == nil || !strings.Contains(err.Error(), "unexpected action ID") {
		t.Fatalf("rollback error = %v, want action ID rejection", err)
	}
	if restored {
		t.Error("unexpected action ID was passed to the restore operation")
	}
}

func TestFailedExecutionAndFailedAutomaticRollbackExposeBothErrors(t *testing.T) {
	ops, _, _ := testOperations(t, []byte("PermitRootLogin yes\n"), 0644)
	ops.effectivePermitRootLogin = func() (string, error) { return "yes", nil }
	ops.writeDropIn = func(string) error { return errors.New("write operation failed") }
	ops.restoreFile = func(state.FileState) error { return errors.New("restore operation failed") }

	result, err := applySSHRootLoginDisable(ops)
	if err == nil {
		t.Fatal("apply returned no error after execution and automatic rollback failed")
	}
	if result.Status == "VERIFIED" || result.Status == "ROLLED_BACK" {
		t.Errorf("failed apply reported status %q", result.Status)
	}
	for _, message := range []string{"write operation failed", "automatic rollback failed", "restore operation failed"} {
		if !strings.Contains(err.Error(), message) {
			t.Errorf("error %q does not contain %q", err, message)
		}
	}
}

func TestAutomaticRecoveryEffectiveStateQueryFailureExposesBothErrors(t *testing.T) {
	ops, _, executionState := testExecutionState(t)
	originalErr := errors.New("original reload failure")
	verificationErr := errors.New("effective-state query failed")
	ops.effectivePermitRootLogin = func() (string, error) { return "", verificationErr }

	err := executionFailureWithRecovery("SSH service reload", originalErr, executionState, ops)
	if !errors.Is(err, originalErr) {
		t.Errorf("error %v does not retain original execution failure", err)
	}
	if !errors.Is(err, verificationErr) {
		t.Errorf("error %v does not retain recovery verification failure", err)
	}
	for _, message := range []string{"original reload failure", "automatic recovery verification failed", "effective-state query failed"} {
		if !strings.Contains(err.Error(), message) {
			t.Errorf("error %q does not contain %q", err, message)
		}
	}
	if strings.Contains(err.Error(), "automatic rollback succeeded") {
		t.Errorf("error incorrectly reports successful automatic recovery: %v", err)
	}
}

func TestAutomaticRecoveryEffectiveStateMismatchExposesBothErrors(t *testing.T) {
	ops, _, executionState := testExecutionState(t)
	originalErr := errors.New("original verification failure")
	ops.effectivePermitRootLogin = func() (string, error) { return "no", nil }

	err := executionFailureWithRecovery("SSH configuration verification", originalErr, executionState, ops)
	if !errors.Is(err, originalErr) {
		t.Errorf("error %v does not retain original execution failure", err)
	}
	for _, message := range []string{"original verification failure", "automatic recovery verification failed", "expected effective PermitRootLogin=yes, got no"} {
		if !strings.Contains(err.Error(), message) {
			t.Errorf("error %q does not contain %q", err, message)
		}
	}
	if strings.Contains(err.Error(), "automatic rollback succeeded") {
		t.Errorf("error incorrectly reports successful automatic recovery: %v", err)
	}
}

func TestAutomaticRecoveryEffectiveStateMatchReportsVerifiedRecovery(t *testing.T) {
	ops, _, executionState := testExecutionState(t)
	originalErr := errors.New("original SSH reload failure")
	ops.effectivePermitRootLogin = func() (string, error) {
		return executionState.PreviousEffectiveValue, nil
	}

	err := executionFailureWithRecovery("SSH service reload", originalErr, executionState, ops)
	if !errors.Is(err, originalErr) {
		t.Errorf("error %v does not retain original execution failure", err)
	}
	if !strings.Contains(err.Error(), "automatic rollback succeeded and effective state was verified") {
		t.Errorf("error %q does not report verified recovery", err)
	}
}

func TestRestoreOrVerificationFailureNeverReportsSuccessfulRollback(t *testing.T) {
	tests := []struct {
		name             string
		restoreErr       error
		verificationErr  error
		wantErrorMessage string
	}{
		{name: "restore failure", restoreErr: errors.New("restore failed"), wantErrorMessage: "state restoration failed"},
		{name: "verification failure", verificationErr: errors.New("content mismatch"), wantErrorMessage: "restored file verification failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, _, _ := testOperations(t, []byte("original\n"), 0600)
			fileState, err := state.CaptureFile(ops.dropInPath)
			if err != nil {
				t.Fatal(err)
			}
			ops.loadState = func(string) (ExecutionState, error) {
				return ExecutionState{ActionID: ActionSSHRootLogin, File: fileState, PreviousEffectiveValue: "yes"}, nil
			}
			ops.restoreFile = func(state.FileState) error { return tt.restoreErr }
			ops.verifyRestoredFile = func(state.FileState) error { return tt.verificationErr }

			result, err := rollbackSSHRootLogin(ops)
			if err == nil || !strings.Contains(err.Error(), tt.wantErrorMessage) {
				t.Fatalf("rollback error = %v, want %q", err, tt.wantErrorMessage)
			}
			if result.Status == "ROLLED_BACK" {
				t.Error("failed restore or verification reported ROLLED_BACK")
			}
		})
	}
}

func TestSuccessfulRestorationVerifiesPriorContentAndExistence(t *testing.T) {
	ops, dropInPath, _ := testOperations(t, []byte("PermitRootLogin yes\n"), 0640)
	fileState, err := state.CaptureFile(dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropInPath, []byte("PermitRootLogin no\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ops.loadState = func(string) (ExecutionState, error) {
		return ExecutionState{ActionID: ActionSSHRootLogin, File: fileState, PreviousEffectiveValue: "yes"}, nil
	}
	ops.effectivePermitRootLogin = func() (string, error) { return "yes", nil }

	result, err := rollbackSSHRootLogin(ops)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if result.Status != "ROLLED_BACK" {
		t.Fatalf("status = %q, want ROLLED_BACK", result.Status)
	}
	info, err := os.Stat(dropInPath)
	if err != nil {
		t.Fatalf("restored file does not exist: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("restored target is not a regular file: %s", info.Mode())
	}
	content, err := os.ReadFile(dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "PermitRootLogin yes\n" {
		t.Errorf("restored content = %q, want prior content", content)
	}
	if got := contentSHA256(content); got != fileState.ContentSHA {
		t.Errorf("restored digest = %s, want %s", got, fileState.ContentSHA)
	}
	if got := info.Mode().Perm(); got != os.FileMode(fileState.Mode) {
		t.Errorf("restored mode = %04o, want %04o", got, fileState.Mode)
	}
}

func TestApplyUsesRealSSHDValidationAndEffectiveConfigurationInTemporaryTree(t *testing.T) {
	fixture := newSSHDConfigFixture(t, nil)
	ops, dropInPath, _ := testOperations(t, []byte("old contents\n"), 0640)
	if err := os.Remove(dropInPath); err != nil {
		t.Fatal(err)
	}
	ops.dropInPath = fixture.dropInPath
	ops.statePath = filepath.Join(t.TempDir(), "state", "execution.json")
	ops.effectivePermitRootLogin = func() (string, error) {
		return effectivePermitRootLoginWithConfig(fixture.configPath)
	}
	ops.writeDropIn = func(content string) error { return writeDropInAt(fixture.dropInPath, content) }
	ops.validateSSHConfig = func() error { return validateSSHConfigWithConfig(fixture.configPath) }
	ops.reloadSSH = func() error { return nil }
	ops.captureFile = state.CaptureFile
	ops.saveState = saveExecutionState
	ops.verifyRestoredFile = verifyRestoredFile

	result, err := applySSHRootLoginDisable(ops)
	if err != nil {
		t.Fatalf("apply with temporary sshd config: %v", err)
	}
	if result.Status != "VERIFIED" || result.After != "no" {
		t.Fatalf("result = %+v, want verified effective PermitRootLogin no", result)
	}
	if err := validateSSHConfigWithConfig(fixture.configPath); err != nil {
		t.Fatalf("sshd -t rejected resulting temporary configuration: %v", err)
	}
	effective, err := effectivePermitRootLoginWithConfig(fixture.configPath)
	if err != nil || effective != "no" {
		t.Fatalf("sshd -T effective PermitRootLogin = %q, %v; want no", effective, err)
	}
}

func TestEarlierSSHDDirectiveWinsAndExecutorRecoversInsteadOfReportingSuccess(t *testing.T) {
	fixture := newSSHDConfigFixture(t, map[string]string{"00-site-policy.conf": "PermitRootLogin yes\n"})
	ops, originalDropIn, _ := testOperations(t, []byte("old contents\n"), 0640)
	if err := os.Remove(originalDropIn); err != nil {
		t.Fatal(err)
	}
	ops.dropInPath = fixture.dropInPath
	ops.statePath = filepath.Join(t.TempDir(), "state", "execution.json")
	ops.effectivePermitRootLogin = func() (string, error) {
		return effectivePermitRootLoginWithConfig(fixture.configPath)
	}
	ops.writeDropIn = func(content string) error { return writeDropInAt(fixture.dropInPath, content) }
	ops.validateSSHConfig = func() error { return validateSSHConfigWithConfig(fixture.configPath) }
	ops.reloadSSH = func() error { return nil }
	ops.captureFile = state.CaptureFile
	ops.saveState = saveExecutionState
	ops.restoreFile = state.RestoreFile
	ops.verifyRestoredFile = verifyRestoredFile

	before, err := effectivePermitRootLoginWithConfig(fixture.configPath)
	if err != nil || before != "yes" {
		t.Fatalf("fixture effective PermitRootLogin = %q, %v; want earlier yes", before, err)
	}
	result, err := applySSHRootLoginDisable(ops)
	if err == nil || !strings.Contains(err.Error(), "expected permitrootlogin=no, got yes") {
		t.Fatalf("apply error = %v, want explicit effective-value mismatch", err)
	}
	if result.Status == "VERIFIED" {
		t.Fatal("precedence conflict was reported as verified")
	}
	if !strings.Contains(err.Error(), "automatic rollback succeeded and effective state was verified") {
		t.Fatalf("failure did not report verified recovery: %v", err)
	}
	if _, statErr := os.Stat(fixture.dropInPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("agent drop-in remains after failed verification/recovery: stat error %v", statErr)
	}
	after, err := effectivePermitRootLoginWithConfig(fixture.configPath)
	if err != nil || after != "yes" {
		t.Fatalf("recovered effective PermitRootLogin = %q, %v; want yes", after, err)
	}
}

func TestApplyFailuresAttemptAndVerifyRecovery(t *testing.T) {
	tests := []struct {
		name      string
		inject    func(*testing.T, *sshOperations, string) error
		wantError string
	}{
		{
			name: "partial file write",
			inject: func(t *testing.T, ops *sshOperations, path string) error {
				ops.writeDropIn = func(string) error {
					if err := os.WriteFile(path, []byte("partial write\n"), 0600); err != nil {
						return err
					}
					return errors.New("injected file write failure")
				}
				return nil
			},
			wantError: "injected file write failure",
		},
		{
			name: "configuration validation",
			inject: func(t *testing.T, ops *sshOperations, _ string) error {
				calls := 0
				ops.validateSSHConfig = func() error {
					calls++
					if calls == 1 {
						return errors.New("injected sshd validation failure")
					}
					return nil
				}
				return nil
			},
			wantError: "injected sshd validation failure",
		},
		{
			name: "service reload",
			inject: func(t *testing.T, ops *sshOperations, _ string) error {
				calls := 0
				ops.reloadSSH = func() error {
					calls++
					if calls == 1 {
						return errors.New("injected ssh reload failure")
					}
					return nil
				}
				return nil
			},
			wantError: "injected ssh reload failure",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := []byte("PermitRootLogin yes\n")
			ops, path, _ := testOperations(t, original, 0640)
			if err := tt.inject(t, &ops, path); err != nil {
				t.Fatal(err)
			}
			result, err := applySSHRootLoginDisable(ops)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("apply error = %v, want %q", err, tt.wantError)
			}
			if result.Status == "VERIFIED" || !strings.Contains(err.Error(), "automatic rollback succeeded and effective state was verified") {
				t.Fatalf("failed apply/recovery result = %+v, error %v", result, err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || string(got) != string(original) {
				t.Fatalf("drop-in after automatic recovery = %q, %v; want original", got, readErr)
			}
			info, statErr := os.Stat(path)
			if statErr != nil || info.Mode().Perm() != 0640 {
				t.Fatalf("drop-in mode after automatic recovery = %v, %v; want 0640", info, statErr)
			}
		})
	}
}

type sshdConfigFixture struct {
	configPath string
	dropInPath string
}

func newSSHDConfigFixture(t *testing.T, earlierFiles map[string]string) sshdConfigFixture {
	t.Helper()
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skipf("/usr/sbin/sshd unavailable: %v", err)
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skipf("ssh-keygen unavailable: %v", err)
	}
	root := t.TempDir()
	confDir := filepath.Join(root, "sshd_config.d")
	if err := os.Mkdir(confDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range earlierFiles {
		if err := os.WriteFile(filepath.Join(confDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(root, "host_key")
	if output, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("generate temporary sshd host key: %s: %v", output, err)
	}
	dropInPath := filepath.Join(confDir, "99-autonomous-hardening-agent.conf")
	configPath := filepath.Join(root, "sshd_config")
	config := "Port 22222\nListenAddress 127.0.0.1\nHostKey " + keyPath + "\nPidFile " + filepath.Join(root, "sshd.pid") + "\nInclude " + filepath.Join(confDir, "*.conf") + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateSSHConfigWithConfig(configPath); err != nil {
		t.Fatalf("sshd -t rejected temporary fixture: %v", err)
	}
	return sshdConfigFixture{configPath: configPath, dropInPath: dropInPath}
}

func testOperations(t *testing.T, initialContent []byte, mode os.FileMode) (sshOperations, string, string) {
	t.Helper()
	root := t.TempDir()
	dropInPath := filepath.Join(root, "99-autonomous-hardening-agent.conf")
	statePath := filepath.Join(root, "state", ActionSSHRootLogin+".json")
	if err := os.WriteFile(dropInPath, initialContent, mode); err != nil {
		t.Fatal(err)
	}
	ops := sshOperations{
		statePath:                statePath,
		dropInPath:               dropInPath,
		requireRoot:              func() error { return nil },
		effectivePermitRootLogin: func() (string, error) { return "yes", nil },
		captureFile:              state.CaptureFile,
		saveState:                saveExecutionState,
		loadState:                loadExecutionState,
		writeDropIn: func(content string) error {
			return os.WriteFile(dropInPath, []byte(content), 0644)
		},
		validateSSHConfig:  func() error { return nil },
		reloadSSH:          func() error { return nil },
		restoreFile:        state.RestoreFile,
		verifyRestoredFile: verifyRestoredFile,
	}
	return ops, dropInPath, statePath
}

func testExecutionState(t *testing.T) (sshOperations, string, ExecutionState) {
	t.Helper()
	ops, dropInPath, _ := testOperations(t, []byte("PermitRootLogin yes\n"), 0640)
	fileState, err := state.CaptureFile(dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	return ops, dropInPath, ExecutionState{
		ActionID:               ActionSSHRootLogin,
		File:                   fileState,
		PreviousEffectiveValue: "yes",
	}
}
