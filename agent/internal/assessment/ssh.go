package assessment

import (
	"fmt"
	"os/exec"
	"strings"
)

const sshdBinary = "/usr/sbin/sshd"

func AssessSSHControls() []Finding {
	config, err := readEffectiveSSHConfig()
	if err != nil {
		return []Finding{
			{
				ControlID:     "SSH-ASSESS-ERROR",
				Title:         "Read effective SSH configuration",
				Status:        StatusError,
				Severity:      "HIGH",
				CurrentValue:  "",
				ExpectedValue: "Effective SSH configuration is readable",
				Message:       err.Error(),
			},
		}
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

func readEffectiveSSHConfig() (map[string]string, error) {
	output, err := exec.Command(sshdBinary, "-T").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate effective SSH configuration: %w", err)
	}

	values := make(map[string]string)

	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)

		if len(fields) < 2 {
			continue
		}

		key := strings.ToLower(fields[0])
		value := strings.ToLower(fields[1])

		values[key] = value
	}

	return values, nil
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
