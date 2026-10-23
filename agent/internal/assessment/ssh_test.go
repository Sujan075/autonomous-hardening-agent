package assessment

import (
	"errors"
	"strings"
	"testing"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/catalog"
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
		definition := catalog.Controls(catalog.PlatformUbuntu)[i]
		if finding.ControlID != expected.controlID {
			t.Errorf("finding %d control ID = %q, want %q", i, finding.ControlID, expected.controlID)
		}
		if finding.Status != StatusPass {
			t.Errorf("finding %s status = %q, want %q", finding.ControlID, finding.Status, StatusPass)
		}
		if finding.ExpectedValue != expected.value || finding.CurrentValue != expected.value {
			t.Errorf("finding %s values = current %q, expected %q; want both %q", finding.ControlID, finding.CurrentValue, finding.ExpectedValue, expected.value)
		}
		if finding.Title != definition.Title || finding.Severity != definition.Severity || finding.ExpectedValue != definition.ExpectedValue {
			t.Errorf("finding %s does not reflect catalog definition: %#v", finding.ControlID, finding)
		}
		if finding.Applicability != ApplicabilityApplicable || finding.Source != definition.Evidence[0].Source || len(finding.Evidence) != len(definition.Evidence) {
			t.Errorf("finding %s does not include catalog applicability/evidence metadata: %#v", finding.ControlID, finding)
		}
		if len(finding.Evidence) > 0 && (finding.Evidence[0].Name != definition.Evidence[0].SettingKey || finding.Evidence[0].Source != definition.Evidence[0].Source || finding.Evidence[0].Value != expected.value) {
			t.Errorf("finding %s evidence differs from catalog: %#v", finding.ControlID, finding.Evidence)
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

func TestEachCataloguedControlPassesAndFailsIndependently(t *testing.T) {
	tests := []struct {
		controlID string
		key       string
		good      string
		bad       string
	}{
		{controlID: "5.1.19", key: "permitemptypasswords", good: "no", bad: "yes"},
		{controlID: "5.1.20", key: "permitrootlogin", good: "no", bad: "yes"},
		{controlID: "5.1.21", key: "permituserenvironment", good: "no", bad: "yes"},
		{controlID: "5.1.22", key: "usepam", good: "yes", bad: "no"},
	}
	for _, test := range tests {
		t.Run(test.controlID, func(t *testing.T) {
			for _, state := range []struct {
				name, value string
				want        Status
			}{{"compliant", test.good, StatusPass}, {"noncompliant", test.bad, StatusFail}} {
				t.Run(state.name, func(t *testing.T) {
					output := strings.Replace(strings.ToLower(compliantSSHDOutput), test.key+" "+test.good, test.key+" "+state.value, 1)
					findings := assessSSHControls(fakeSSHConfigRunner([]byte(output), nil, nil))
					var selected *Finding
					for i := range findings {
						if findings[i].ControlID == test.controlID {
							selected = &findings[i]
							break
						}
					}
					if selected == nil {
						t.Fatalf("missing finding for %s: %#v", test.controlID, findings)
					}
					if selected.Status != state.want || selected.CurrentValue != state.value || selected.ExpectedValue != test.good {
						t.Fatalf("finding = %#v, want status=%s current=%s expected=%s", selected, state.want, state.value, test.good)
					}
					definition, ok := catalog.Lookup(catalog.PlatformUbuntu, test.controlID)
					if !ok || selected.Title != definition.Title || selected.Severity != definition.Severity || selected.Applicability != ApplicabilityApplicable || len(selected.Evidence) != 1 {
						t.Fatalf("finding metadata does not match catalog: %#v definition=%#v", selected, definition)
					}
					evidence := selected.Evidence[0]
					if selected.Source != definition.Evidence[0].Source || evidence.Name != definition.Evidence[0].SettingKey || evidence.Value != state.value || evidence.Source != selected.Source {
						t.Fatalf("evidence metadata does not identify the evaluated directive: %#v", selected)
					}
				})
			}
		})
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
			name:   "duplicate directive",
			output: "permitemptypasswords no\npermitemptypasswords yes\npermitrootlogin no\npermituserenvironment no\nusepam yes\n",
			want:   "duplicate permitemptypasswords directive",
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
	for _, test := range []struct {
		name       string
		stderr     string
		diagnostic string
	}{
		{name: "sshd command failure", stderr: "/etc/ssh/sshd_config.d/50-cloud-init.conf: Permission denied", diagnostic: "Permission denied"},
		{name: "noninteractive sudo denied", stderr: "sudo: a password is required", diagnostic: "sudo: a password is required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			findings := assessSSHControls(fakeSSHConfigRunner(nil, []byte(test.stderr), errors.New("exit status 1")))
			assertAssessmentError(t, findings, test.diagnostic)
			assertNoPassingFindings(t, findings)
		})
	}
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
	assertNoPassingFindings(t, findings)
}

func assertNoPassingFindings(t *testing.T, findings []Finding) {
	t.Helper()
	for _, finding := range findings {
		if finding.Status == StatusPass {
			t.Errorf("failed assessment produced PASS for %s", finding.ControlID)
		}
	}
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
