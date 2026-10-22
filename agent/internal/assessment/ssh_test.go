package assessment

import (
	"errors"
	"strings"
	"testing"
)

const compliantSSHDOutput = `permitemptyPasswords no
permitrootlogin no
permituserenvironment no
usepam yes
`

func TestParseEffectiveSSHConfigFourDirectives(t *testing.T) {
	config, err := parseEffectiveSSHConfig([]byte(compliantSSHDOutput))
	if err != nil {
		t.Fatalf("parse effective SSH config: %v", err)
	}

	want := map[string]string{
		"permitemptypasswords":  "no",
		"permitrootlogin":       "no",
		"permituserenvironment": "no",
		"usepam":                "yes",
	}
	for directive, expected := range want {
		if got := config[directive]; got != expected {
			t.Errorf("%s = %q, want %q", directive, got, expected)
		}
	}
}

func TestAssessSSHControlsCompliantConfiguration(t *testing.T) {
	findings := assessSSHControls(fakeSSHConfigRunner(
		[]byte(compliantSSHDOutput),
		[]byte("diagnostic text on stderr must not be parsed as configuration"),
		nil,
	))

	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4", len(findings))
	}
	want := []struct {
		controlID string
		value     string
	}{
		{controlID: "5.1.19", value: "no"},
		{controlID: "5.1.20", value: "no"},
		{controlID: "5.1.21", value: "no"},
		{controlID: "5.1.22", value: "yes"},
	}
	for i, expected := range want {
		finding := findings[i]
		if finding.ControlID != expected.controlID {
			t.Errorf("finding %d control ID = %q, want %q", i, finding.ControlID, expected.controlID)
		}
		if finding.Status != StatusPass {
			t.Errorf("finding %s status = %q, want %q", finding.ControlID, finding.Status, StatusPass)
		}
		if finding.ExpectedValue != expected.value || finding.CurrentValue != expected.value {
			t.Errorf("finding %s values = current %q, expected %q; want both %q", finding.ControlID, finding.CurrentValue, finding.ExpectedValue, expected.value)
		}
	}
}

func TestAssessSSHControlsNoncompliantValues(t *testing.T) {
	output := `permitemptypasswords yes
permitrootlogin yes
permituserenvironment yes
usepam no
`
	findings := assessSSHControls(fakeSSHConfigRunner([]byte(output), nil, nil))

	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4", len(findings))
	}
	for _, finding := range findings {
		if finding.Status != StatusFail {
			t.Errorf("finding %s status = %q, want %q", finding.ControlID, finding.Status, StatusFail)
		}
	}
}

func TestAssessSSHControlsMissingOrMalformedOutputReturnsError(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "missing directive",
			output: "permitrootlogin no\npermituserenvironment no\nusepam yes\n",
			want:   "missing required directives",
		},
		{
			name:   "malformed directive",
			output: "permitemptypasswords no extra\npermitrootlogin no\npermituserenvironment no\nusepam yes\n",
			want:   "malformed permitemptypasswords directive",
		},
		{
			name:   "empty output",
			output: "",
			want:   "missing required directives",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := assessSSHControls(fakeSSHConfigRunner([]byte(tt.output), nil, nil))
			assertAssessmentError(t, findings, tt.want)
		})
	}
}

func TestAssessSSHControlsCommandInvocationFailureReturnsError(t *testing.T) {
	findings := assessSSHControls(fakeSSHConfigRunner(
		nil,
		[]byte("/etc/ssh/sshd_config.d/50-cloud-init.conf: Permission denied"),
		errors.New("exit status 1"),
	))

	assertAssessmentError(t, findings, "Permission denied")
}

func TestAssessSSHControlsDeniedNoninteractiveSudoReturnsError(t *testing.T) {
	findings := assessSSHControls(fakeSSHConfigRunner(
		nil,
		[]byte("sudo: a password is required"),
		errors.New("exit status 1"),
	))

	assertAssessmentError(t, findings, "sudo: a password is required")
}

func TestEvaluatorFailureNeverProducesPassingFindings(t *testing.T) {
	findings := assessSSHControls(fakeSSHConfigRunner(nil, []byte("not permitted"), errors.New("exit status 1")))

	if len(findings) == 0 {
		t.Fatal("got no findings, want an assessment error")
	}
	for _, finding := range findings {
		if finding.Status == StatusPass {
			t.Errorf("evaluator failure produced passing finding %s", finding.ControlID)
		}
	}
	assertAssessmentError(t, findings, "not permitted")
}

func fakeSSHConfigRunner(stdout, stderr []byte, err error) sshConfigRunner {
	return func() ([]byte, []byte, error) {
		return stdout, stderr, err
	}
}

func assertAssessmentError(t *testing.T, findings []Finding, diagnostic string) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly one assessment error", len(findings))
	}
	if findings[0].Status != StatusError {
		t.Errorf("status = %q, want %q", findings[0].Status, StatusError)
	}
	if findings[0].ControlID != "SSH-ASSESS-ERROR" {
		t.Errorf("control ID = %q, want %q", findings[0].ControlID, "SSH-ASSESS-ERROR")
	}
	if !strings.Contains(findings[0].Message, diagnostic) {
		t.Errorf("message = %q, want diagnostic %q", findings[0].Message, diagnostic)
	}
}
