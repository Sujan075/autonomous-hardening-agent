package assessment

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const (
	sudoBinary = "/usr/bin/sudo"
	sshdBinary = "/usr/sbin/sshd"
)

type sshConfigRunner func() (stdout, stderr []byte, err error)

var requiredSSHDirectives = []string{
	"permitemptypasswords",
	"permitrootlogin",
	"permituserenvironment",
	"usepam",
}

func AssessSSHControls() []Finding {
	return assessSSHControls(runEffectiveSSHConfig)
}

func assessSSHControls(runner sshConfigRunner) []Finding {
	config, err := readEffectiveSSHConfig(runner)
	if err != nil {
		return []Finding{sshAssessmentError(err)}
	}

	return []Finding{
		checkSSHDirective(
			config,
			"5.1.19",
			"Disable SSH empty passwords",
			"PermitEmptyPasswords",
			"no",
			"MEDIUM",
		),
		checkSSHDirective(
			config,
			"5.1.20",
			"Disable SSH root login",
			"PermitRootLogin",
			"no",
			"HIGH",
		),
		checkSSHDirective(
			config,
			"5.1.21",
			"Disable SSH user environment",
			"PermitUserEnvironment",
			"no",
			"MEDIUM",
		),
		checkSSHDirective(
			config,
			"5.1.22",
			"Enable SSH PAM",
			"UsePAM",
			"yes",
			"MEDIUM",
		),
	}
}

func runEffectiveSSHConfig() ([]byte, []byte, error) {
	command := exec.Command(sudoBinary, "-n", sshdBinary, "-T")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.Output()
	return stdout, stderr.Bytes(), err
}

func readEffectiveSSHConfig(runner sshConfigRunner) (map[string]string, error) {
	stdout, stderr, err := runner()
	if err != nil {
		diagnostic := sanitizeDiagnostic(stderr)
		if diagnostic == "" {
			return nil, fmt.Errorf("failed to evaluate effective SSH configuration: %w", err)
		}
		return nil, fmt.Errorf("failed to evaluate effective SSH configuration: %w (stderr: %s)", err, diagnostic)
	}

	config, err := parseEffectiveSSHConfig(stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse effective SSH configuration: %w", err)
	}
	return config, nil
}

func parseEffectiveSSHConfig(output []byte) (map[string]string, error) {
	values := make(map[string]string)
	for lineNumber, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		key := strings.ToLower(fields[0])
		if !isRequiredSSHDirective(key) {
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
	for _, directive := range requiredSSHDirectives {
		if _, exists := values[directive]; !exists {
			missing = append(missing, directive)
		}
	}
	if len(missing) != 0 {
		return nil, fmt.Errorf("missing required directives: %s", strings.Join(missing, ", "))
	}

	return values, nil
}

func isRequiredSSHDirective(key string) bool {
	for _, directive := range requiredSSHDirectives {
		if key == directive {
			return true
		}
	}
	return false
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
		Severity:      "HIGH",
		CurrentValue:  "",
		ExpectedValue: "Effective SSH configuration is readable",
		Message:       err.Error(),
	}
}

func checkSSHDirective(
	config map[string]string,
	controlID string,
	title string,
	directive string,
	expected string,
	severity string,
) Finding {
	current, exists := config[strings.ToLower(directive)]

	if !exists {
		current = "unknown"
	}

	status := StatusFail

	if strings.EqualFold(current, expected) {
		status = StatusPass
	}

	message := "Effective configuration does not match expected value"

	if status == StatusPass {
		message = "Effective configuration matches expected value"
	}

	return Finding{
		ControlID:     controlID,
		Title:         title,
		Status:        status,
		Severity:      severity,
		CurrentValue:  current,
		ExpectedValue: expected,
		Message:       message,
	}
}
