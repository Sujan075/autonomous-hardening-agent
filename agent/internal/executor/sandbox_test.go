package executor

import (
	"os"
	"testing"
)

func TestTemporarySSHFixtureOwnsOnlyTemporaryTreeAndCleansIt(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skip("OpenSSH server binary unavailable")
	}
	sandbox, err := NewTemporarySSHConfigSandbox(SSHFixtureNonCompliant)
	if err != nil {
		t.Skipf("local OpenSSH fixture unavailable: %v", err)
	}
	directory := sandbox.dir
	if _, err := os.Stat(sandbox.config); err != nil {
		t.Fatalf("fixture config missing: %v", err)
	}
	if err := sandbox.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if err := sandbox.Close(); err != nil {
		t.Fatalf("second Close(): %v", err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("temporary fixture remains after cleanup: stat error=%v", err)
	}
	if _, err := sandbox.EffectiveConfig(); err == nil {
		t.Fatal("closed fixture was still usable")
	}
}

func TestTemporarySSHFixtureRejectsUnknownScenario(t *testing.T) {
	if _, err := NewTemporarySSHConfigSandbox(SSHFixtureScenario("arbitrary")); err == nil {
		t.Fatal("unknown fixture scenario accepted")
	}
}
