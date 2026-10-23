package assessment

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

const platformDispatchSource = "platform.dispatch"

// AssessCurrentHost selects an evaluator from the local OS identity. Unknown
// platforms and versions are returned as UNKNOWN rather than evaluated using
// the Ubuntu control set.
func AssessCurrentHost() Assessment {
	data, err := readOSRelease()
	return assessHost(runtime.GOOS, runtime.GOARCH, data, err, runEffectiveSSHConfig)
}

func readOSRelease() ([]byte, error) {
	return os.ReadFile("/etc/os-release")
}

func assessHost(goos, goarch string, releaseData []byte, releaseErr error, runner sshConfigRunner) Assessment {
	if goos != "linux" {
		return unsupportedPlatformAssessment(goos, "", "this operating system has no registered assessment adapter")
	}
	if releaseErr != nil {
		return unsupportedPlatformAssessment("linux", "", fmt.Sprintf("cannot identify Linux distribution: %v", releaseErr))
	}
	release, err := parseOSRelease(releaseData)
	if err != nil {
		return unsupportedPlatformAssessment("linux", "", fmt.Sprintf("cannot parse Linux distribution identity: %v", err))
	}
	id := release["ID"]
	version := release["VERSION_ID"]
	prettyName := release["PRETTY_NAME"]
	if id == "" || version == "" {
		return unsupportedPlatformAssessment("linux", version, "Linux distribution identity is incomplete: ID and VERSION_ID are required")
	}

	if id == "ubuntu" {
		if !ubuntuCatalogVersion(version, prettyName) {
			return unsupportedPlatformAssessment("ubuntu", version, "Ubuntu release identity is incomplete or outside the supported 24.04.5 catalog scope")
		}
		if goarch != "arm64" {
			return unsupportedPlatformAssessment("ubuntu", version, fmt.Sprintf("Ubuntu 24.04.5 architecture %q is not in the supported catalog scope", goarch))
		}
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

func parseOSRelease(data []byte) (map[string]string, error) {
	values := make(map[string]string)
	for lineNumber, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.TrimSpace(key) != key || !validOSReleaseKey(key) {
			return nil, fmt.Errorf("malformed os-release assignment on line %d", lineNumber+1)
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("duplicate os-release key %s", key)
		}
		parsedValue, err := parseOSReleaseValue(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("malformed os-release value for %s on line %d: %w", key, lineNumber+1, err)
		}
		values[key] = parsedValue
	}
	return values, nil
}

// parseOSReleaseValue parses one os-release assignment value without invoking
// a shell. It implements the quoting and backslash rules needed for literal
// values; variable expansion and concatenated quoted fragments are rejected.
func parseOSReleaseValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	quote := raw[0]
	if quote == '\'' || quote == '"' {
		var value strings.Builder
		closed := false
		for i := 1; i < len(raw); i++ {
			character := raw[i]
			if character == quote {
				if strings.TrimSpace(raw[i+1:]) != "" {
					return "", fmt.Errorf("characters follow closing quote")
				}
				closed = true
				break
			}
			if character == '\\' && quote == '"' {
				if i+1 == len(raw) {
					return "", fmt.Errorf("trailing escape")
				}
				i++
				escaped := raw[i]
				if strings.ContainsRune("$\"\\`", rune(escaped)) {
					value.WriteByte(escaped)
				} else {
					value.WriteByte('\\')
					value.WriteByte(escaped)
				}
				continue
			}
			value.WriteByte(character)
		}
		if !closed {
			return "", fmt.Errorf("unterminated quoted value")
		}
		return validateOSReleaseString(value.String())
	}

	var value strings.Builder
	for i := 0; i < len(raw); i++ {
		character := raw[i]
		if character == '\'' || character == '"' || character == ' ' || character == '\t' || character == '\r' || character == '\n' {
			return "", fmt.Errorf("unquoted special character")
		}
		if character == '\\' {
			if i+1 == len(raw) {
				return "", fmt.Errorf("trailing escape")
			}
			i++
			character = raw[i]
		}
		value.WriteByte(character)
	}
	return validateOSReleaseString(value.String())
}

func validateOSReleaseString(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("value is not valid UTF-8")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("value contains a non-printable character")
		}
	}
	return value, nil
}

func validOSReleaseKey(key string) bool {
	for i, character := range key {
		letter := (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
		if i == 0 && !letter && character != '_' {
			return false
		}
		if !letter && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
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
