package assessment

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const platformDispatchSource = "platform.dispatch"

// AssessCurrentHost selects an evaluator from the local OS identity. Unknown
// platforms and versions are returned as UNKNOWN rather than evaluated using
// the Ubuntu control set.
func AssessCurrentHost() Assessment {
	data, err := readOSRelease()
	return assessHost(runtime.GOOS, data, err, runEffectiveSSHConfig)
}

func readOSRelease() ([]byte, error) {
	return os.ReadFile("/etc/os-release")
}

func assessHost(goos string, releaseData []byte, releaseErr error, runner sshConfigRunner) Assessment {
	if goos != "linux" {
		return unsupportedPlatformAssessment(goos, "", "this operating system has no registered assessment adapter")
	}
	if releaseErr != nil {
		return unsupportedPlatformAssessment("linux", "", fmt.Sprintf("cannot identify Linux distribution: %v", releaseErr))
	}
	release := parseOSRelease(releaseData)
	id := release["ID"]
	version := release["VERSION_ID"]
	prettyName := release["PRETTY_NAME"]

	if id == "ubuntu" && ubuntuCatalogVersion(version, prettyName) {
		return Assessment{Platform: PlatformUbuntu, Findings: assessSSHControls(runner)}
	}
	if id == "centos" && release["NAME"] == "CentOS Stream" {
		return unsupportedPlatformAssessment("centos-stream", version, "CentOS Stream is detected, but no verified CentOS Stream control set or assessment adapter is registered")
	}
	platform := id
	if platform == "" {
		platform = "linux"
	}
	return unsupportedPlatformAssessment(platform, version, "no assessment adapter is registered for this operating system and version")
}

func ubuntuCatalogVersion(version, prettyName string) bool {
	if version != "24.04" {
		return false
	}
	fields := strings.Fields(prettyName)
	return len(fields) >= 2 && fields[0] == "Ubuntu" && fields[1] == "24.04.5"
}

func parseOSRelease(data []byte) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if decoded, err := strconv.Unquote(value); err == nil {
			value = decoded
		} else {
			value = strings.Trim(value, "'")
		}
		values[key] = value
	}
	return values
}

func unsupportedPlatformAssessment(platform, version, reason string) Assessment {
	message := reason
	if version != "" {
		message = fmt.Sprintf("%s (version %s)", reason, version)
	}
	return Assessment{
		Platform: platform,
		Findings: []Finding{{
			ControlID: "PLATFORM-ASSESSMENT-UNSUPPORTED",
			Title:     "Platform assessment is unsupported",
			Status:    StatusUnknown,
			Severity:  "INFO",
			Message:   message,
			Source:    platformDispatchSource,
			Error: &NormalizedError{
				Code:    "PLATFORM_OR_CONTROL_SET_UNSUPPORTED",
				Message: message,
				Source:  platformDispatchSource,
			},
		}},
	}
}
