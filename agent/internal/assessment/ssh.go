package assessment

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/catalog"
)

const (
	PlatformUbuntu       = string(catalog.PlatformUbuntu)
	PlatformCentOSStream = string(catalog.PlatformCentOSStream)
	sshConfigSource      = catalog.EffectiveSSHConfigSource
	sudoBinary           = "/usr/bin/sudo"
	sshdBinary           = "/usr/sbin/sshd"
)

type sshConfigRunner func() (stdout, stderr []byte, err error)

func AssessSSHControls() []Finding {
	return assessSSHControls(runEffectiveSSHConfig)
}

func assessSSHControls(runner sshConfigRunner) []Finding {
	return assessSSHControlsForPlatform(catalog.PlatformUbuntu, runner)
}

func assessSSHControlsForPlatform(platform catalog.Platform, runner sshConfigRunner) []Finding {
	controls := catalog.Controls(platform)
	if err := catalog.Validate(controls); err != nil {
		return []Finding{sshAssessmentError(fmt.Errorf("invalid control catalog: %w", err))}
	}

	config, err := readEffectiveSSHConfigForControls(runner, controls)
	if err != nil {
		return []Finding{sshAssessmentError(err)}
	}

	findings := make([]Finding, 0, len(controls))
	for _, control := range controls {
		findings = append(findings, checkSSHDirective(config, control))
	}
	return findings
}

func runEffectiveSSHConfig() ([]byte, []byte, error) {
	command := exec.Command(sudoBinary, "-n", sshdBinary, "-T")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.Output()
	return stdout, stderr.Bytes(), err
}

func readEffectiveSSHConfig(runner sshConfigRunner) (map[string]string, error) {
	return readEffectiveSSHConfigForControls(runner, catalog.Controls(catalog.PlatformUbuntu))
}

func readEffectiveSSHConfigForControls(runner sshConfigRunner, controls []catalog.Control) (map[string]string, error) {
	stdout, stderr, err := runner()
	if err != nil {
		diagnostic := sanitizeDiagnostic(stderr)
		if diagnostic == "" {
			return nil, fmt.Errorf("failed to evaluate effective SSH configuration: %w", err)
		}
		return nil, fmt.Errorf("failed to evaluate effective SSH configuration: %w (stderr: %s)", err, diagnostic)
	}

	config, err := parseEffectiveSSHConfigForControls(stdout, controls)
	if err != nil {
		return nil, fmt.Errorf("failed to parse effective SSH configuration: %w", err)
	}
	return config, nil
}

func parseEffectiveSSHConfig(output []byte) (map[string]string, error) {
	return parseEffectiveSSHConfigForControls(output, catalog.Controls(catalog.PlatformUbuntu))
}

func parseEffectiveSSHConfigForControls(output []byte, controls []catalog.Control) (map[string]string, error) {
	if err := catalog.Validate(controls); err != nil {
		return nil, fmt.Errorf("invalid control catalog: %w", err)
	}
	requiredDirectives := make(map[string]struct{}, len(controls))
	for _, control := range controls {
		requiredDirectives[strings.ToLower(control.EffectiveSettingKey)] = struct{}{}
	}

	values := make(map[string]string)
	for lineNumber, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		key := strings.ToLower(fields[0])
		if _, required := requiredDirectives[key]; !required {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed %s directive on line %d", fields[0], lineNumber+1)
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("duplicate %s directive", fields[0])
		}
		values[key] = strings.ToLower(fields[1])
	}

	missing := make([]string, 0)
	for _, control := range controls {
		directive := strings.ToLower(control.EffectiveSettingKey)
		if _, exists := values[directive]; !exists {
			missing = append(missing, directive)
		}
	}
	if len(missing) != 0 {
		return nil, fmt.Errorf("missing required directives: %s", strings.Join(missing, ", "))
	}

	return values, nil
}

func sanitizeDiagnostic(stderr []byte) string {
	text := strings.ToValidUTF8(string(stderr), "�")
	diagnostic := strings.Join(strings.Fields(text), " ")
	const maxDiagnosticRunes = 1024
	runes := []rune(diagnostic)
	if len(runes) > maxDiagnosticRunes {
		return string(runes[:maxDiagnosticRunes]) + "…"
	}
	return diagnostic
}

func sshAssessmentError(err error) Finding {
	return Finding{
		ControlID:     "SSH-ASSESS-ERROR",
		Title:         "Read effective SSH configuration",
		Status:        StatusError,
		Applicability: ApplicabilityApplicable,
		Severity:      "HIGH",
		CurrentValue:  "",
		ExpectedValue: "Effective SSH configuration is readable",
		Message:       err.Error(),
		Source:        sshConfigSource,
		Error: &NormalizedError{
			Code:    "ASSESSMENT_EVALUATION_FAILED",
			Message: err.Error(),
			Source:  sshConfigSource,
		},
	}
}

func checkSSHDirective(
	config map[string]string,
	control catalog.Control,
) Finding {
	directive := control.EffectiveSettingKey
	current, exists := config[strings.ToLower(directive)]

	if !exists {
		current = "unknown"
	}

	status := StatusFail

	if strings.EqualFold(current, control.ExpectedValue) {
		status = StatusPass
	}

	message := "Effective configuration does not match expected value"

	if status == StatusPass {
		message = "Effective configuration matches expected value"
	}

	evidence := make([]Evidence, 0, len(control.Evidence))
	for _, expectation := range control.Evidence {
		evidence = append(evidence, Evidence{
			Name:   expectation.SettingKey,
			Value:  config[strings.ToLower(expectation.SettingKey)],
			Source: expectation.Source,
		})
	}
	source := sshConfigSource
	if len(control.Evidence) > 0 {
		source = control.Evidence[0].Source
	}

	return Finding{
		ControlID:     control.ID,
		Title:         control.Title,
		Status:        status,
		Applicability: ApplicabilityApplicable,
		Severity:      control.Severity,
		CurrentValue:  current,
		ExpectedValue: control.ExpectedValue,
		Message:       message,
		Source:        source,
		Evidence:      evidence,
	}
}
