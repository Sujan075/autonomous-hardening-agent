package assessment

import (
	"errors"
	"testing"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/catalog"
)

func TestParseOSReleaseSupportsQuotedValuesAndShellStyleEscapes(t *testing.T) {
	tests := []struct {
		name, input, key, want string
	}{
		{name: "single quoted identity", input: "ID='ubuntu'\n", key: "ID", want: "ubuntu"},
		{name: "single quoted spaces", input: "PRETTY_NAME='Ubuntu 24.04.5 LTS'\n", key: "PRETTY_NAME", want: "Ubuntu 24.04.5 LTS"},
		{name: "double quoted spaces", input: `PRETTY_NAME="Ubuntu 24.04.5 LTS"` + "\n", key: "PRETTY_NAME", want: "Ubuntu 24.04.5 LTS"},
		{name: "double quoted escaped shell characters", input: "VALUE=\"dollar \\$HOME quote \\\" slash \\\\ backtick \\`\"\n", key: "VALUE", want: "dollar $HOME quote \" slash \\ backtick `"},
		{name: "variable text stays literal", input: `VALUE="$ID"` + "\n", key: "VALUE", want: "$ID"},
		{name: "single quoted backslash stays literal", input: `VALUE='path\segment'` + "\n", key: "VALUE", want: `path\segment`},
		{name: "escaped unquoted space", input: `VALUE=two\ words` + "\n", key: "VALUE", want: "two words"},
		{name: "unknown double quote escape preserves backslash", input: `VALUE="keep\q"` + "\n", key: "VALUE", want: `keep\q`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values, err := parseOSRelease([]byte(test.input))
			if err != nil {
				t.Fatalf("parseOSRelease() error = %v", err)
			}
			if values[test.key] != test.want {
				t.Fatalf("%s = %q, want %q", test.key, values[test.key], test.want)
			}
		})
	}
}

func TestParseOSReleaseRejectsMalformedValuesAndAssignments(t *testing.T) {
	tests := []struct {
		name, input string
	}{
		{name: "unterminated single quote", input: "VALUE='unterminated\n"},
		{name: "unterminated double quote", input: `VALUE="unterminated`},
		{name: "trailing quoted escape", input: "VALUE=\"trailing\\"},
		{name: "text after closing quote", input: `VALUE="valid"suffix`},
		{name: "concatenated quoted fragments", input: `VALUE="first""second"`},
		{name: "malformed assignment", input: "ID=ubuntu\nnot-an-assignment\n"},
		{name: "invalid assignment key", input: "1ID=ubuntu\n"},
		{name: "duplicate key", input: "ID=ubuntu\nID=other\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if values, err := parseOSRelease([]byte(test.input)); err == nil {
				t.Fatalf("parseOSRelease() = %#v, want error", values)
			}
		})
	}
}

func TestAssessHostDispatchesSingleQuotedUbuntuIdentity(t *testing.T) {
	called := false
	result := assessHost("linux", "arm64", []byte("ID='ubuntu'\nVERSION_ID='24.04'\nPRETTY_NAME='Ubuntu 24.04.5 LTS'\n"), nil,
		func() ([]byte, []byte, error) {
			called = true
			return []byte(compliantSSHDOutput), nil, nil
		})
	if !called || result.Platform != PlatformUbuntu || len(result.Findings) != 4 {
		t.Fatalf("single-quoted identity did not dispatch supported assessment: called=%v assessment=%#v", called, result)
	}
}

func TestAssessHostDispatchesOnlySupportedUbuntuCatalog(t *testing.T) {
	called := false
	result := assessHost("linux", "arm64", []byte("ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"), nil,
		func() ([]byte, []byte, error) {
			called = true
			return []byte("permitemptyPasswords no\npermitrootlogin no\npermituserenvironment no\nusepam yes\n"), nil, nil
		})

	if !called {
		t.Fatal("supported Ubuntu dispatch did not run the SSH evaluator")
	}
	if result.Platform != PlatformUbuntu || len(result.Findings) != 4 {
		t.Fatalf("assessment = %#v, want four Ubuntu findings", result)
	}
	for _, finding := range result.Findings {
		if finding.Status != StatusPass || finding.Source != sshConfigSource || len(finding.Evidence) == 0 {
			t.Errorf("Ubuntu finding lacks passing evidence: %#v", finding)
		}
	}
}

func TestAssessHostDoesNotDispatchUbuntuControlsToCentOSStream(t *testing.T) {
	called := false
	result := assessHost("linux", "arm64", []byte("NAME=\"CentOS Stream\"\nID=centos\nVERSION_ID=\"9\"\n"), nil,
		func() ([]byte, []byte, error) {
			called = true
			return nil, nil, nil
		})

	if called {
		t.Fatal("CentOS Stream unexpectedly ran the Ubuntu SSH evaluator")
	}
	if result.Platform != "centos-stream" || len(result.Findings) != 1 {
		t.Fatalf("assessment = %#v, want one explicit CentOS Stream unsupported finding", result)
	}
	finding := result.Findings[0]
	if finding.Status != StatusUnknown || finding.Error == nil || finding.Error.Code != "PLATFORM_OR_CONTROL_SET_UNSUPPORTED" {
		t.Fatalf("unsupported CentOS state was not explicit and fail-closed: %#v", finding)
	}
	if finding.Applicability == ApplicabilityNotApplicable || finding.Status == StatusPass {
		t.Fatalf("unsupported CentOS was incorrectly marked compliant or not applicable: %#v", finding)
	}
}

func TestAssessHostDispatchesExactCentOSStream9ARM64Identity(t *testing.T) {
	called := false
	result := assessHost("linux", "arm64", []byte("ID=centos\nNAME=\"CentOS Stream\"\nVERSION_ID=9\nPRETTY_NAME=\"CentOS Stream 9\"\n"), nil, func() ([]byte, []byte, error) {
		called = true
		return []byte(compliantSSHDOutput), nil, nil
	})
	if !called || result.Platform != PlatformCentOSStream || len(result.Findings) != 4 {
		t.Fatalf("dispatch result called=%v assessment=%#v", called, result)
	}
	for i, finding := range result.Findings {
		control := catalog.Controls(catalog.PlatformCentOSStream)[i]
		if finding.ControlID != control.ID || finding.Status != StatusPass || finding.ExpectedValue != control.ExpectedValue || finding.Source != sshConfigSource || len(finding.Evidence) != 1 || finding.Evidence[0].Value != control.ExpectedValue {
			t.Errorf("finding[%d]=%#v control=%#v", i, finding, control)
		}
	}
}

func TestAssessHostRejectsCentOSIdentityOutsideExactScope(t *testing.T) {
	tests := []struct{ name, goos, arch, release string }{
		{"wrong distribution", "linux", "arm64", "ID=rocky\nNAME=\"CentOS Stream\"\nVERSION_ID=9\nPRETTY_NAME=\"CentOS Stream 9\"\n"},
		{"wrong version", "linux", "arm64", "ID=centos\nNAME=\"CentOS Stream\"\nVERSION_ID=10\nPRETTY_NAME=\"CentOS Stream 10\"\n"},
		{"wrong architecture", "linux", "amd64", "ID=centos\nNAME=\"CentOS Stream\"\nVERSION_ID=9\nPRETTY_NAME=\"CentOS Stream 9\"\n"},
		{"missing name", "linux", "arm64", "ID=centos\nVERSION_ID=9\nPRETTY_NAME=\"CentOS Stream 9\"\n"},
		{"inconsistent pretty name", "linux", "arm64", "ID=centos\nNAME=\"CentOS Stream\"\nVERSION_ID=9\nPRETTY_NAME=\"CentOS Linux 9\"\n"},
		{"malformed identity", "linux", "arm64", "ID=centos\nNAME=\"CentOS Stream\nVERSION_ID=9\n"},
		{"wrong OS", "freebsd", "arm64", "ID=centos\nNAME=\"CentOS Stream\"\nVERSION_ID=9\nPRETTY_NAME=\"CentOS Stream 9\"\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			result := assessHost(test.goos, test.arch, []byte(test.release), nil, func() ([]byte, []byte, error) { called = true; return []byte(compliantSSHDOutput), nil, nil })
			if called {
				t.Fatal("unsupported identity invoked SSH evaluator")
			}
			if len(result.Findings) != 1 || result.Findings[0].Status != StatusUnknown || result.Findings[0].Error == nil {
				t.Fatalf("result=%#v, want UNKNOWN", result)
			}
		})
	}
}

func TestAssessHostRejectsUnsupportedUbuntuReleaseBeforeCommands(t *testing.T) {
	called := false
	result := assessHost("linux", "arm64", []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"), nil,
		func() ([]byte, []byte, error) {
			called = true
			return nil, nil, nil
		})
	if called {
		t.Fatal("unsupported Ubuntu release unexpectedly ran the evaluator")
	}
	if result.Platform != "ubuntu" || result.Findings[0].Status != StatusUnknown || result.Findings[0].Error == nil {
		t.Fatalf("unsupported Ubuntu release assessment = %#v", result)
	}
}

func TestAssessHostRejectsUnsupportedOrIncompleteIdentityBeforeCommands(t *testing.T) {
	tests := []struct {
		name    string
		goarch  string
		release string
	}{
		{name: "unsupported Ubuntu point release", goarch: "arm64", release: "ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.6 LTS\"\n"},
		{name: "older Ubuntu release", goarch: "arm64", release: "ID=ubuntu\nVERSION_ID=22.04\nPRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\n"},
		{name: "other distribution", goarch: "arm64", release: "ID=debian\nVERSION_ID=12\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n"},
		{name: "unsupported architecture", goarch: "amd64", release: "ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"},
		{name: "missing ID", goarch: "arm64", release: "VERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"},
		{name: "missing version", goarch: "arm64", release: "ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"},
		{name: "missing pretty name", goarch: "arm64", release: "ID=ubuntu\nVERSION_ID=24.04\n"},
		{name: "malformed quoted identity", goarch: "arm64", release: "ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\n"},
		{name: "duplicate identity key", goarch: "arm64", release: "ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"},
		{name: "malformed os-release line", goarch: "arm64", release: "ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nBROKEN\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			result := assessHost("linux", test.goarch, []byte(test.release), nil, func() ([]byte, []byte, error) {
				called = true
				return []byte(compliantSSHDOutput), nil, nil
			})
			if called {
				t.Fatal("unsupported or incomplete identity dispatched the Ubuntu evaluator")
			}
			if len(result.Findings) != 1 || result.Findings[0].Status != StatusUnknown || result.Findings[0].Error == nil {
				t.Fatalf("identity result = %#v, want explicit UNKNOWN", result)
			}
		})
	}
}

func TestAssessHostUnknownOSAndDetectionFailureFailClosed(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		goarch       string
		release      []byte
		releaseError error
	}{
		{name: "non Linux", goos: "windows", goarch: "arm64"},
		{name: "release unavailable", goos: "linux", goarch: "arm64", releaseError: errors.New("read denied")},
		{name: "unknown Linux distribution", goos: "linux", goarch: "arm64", release: []byte("ID=fedora\nVERSION_ID=42\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			result := assessHost(test.goos, test.goarch, test.release, test.releaseError, func() ([]byte, []byte, error) {
				called = true
				return nil, nil, nil
			})
			if called {
				t.Fatal("unknown platform unexpectedly ran the Ubuntu evaluator")
			}
			if len(result.Findings) != 1 || result.Findings[0].Status != StatusUnknown || result.Findings[0].Error == nil {
				t.Fatalf("unsupported assessment = %#v", result)
			}
		})
	}
}

func TestAssessHostRetainsNormalizedUbuntuCommandFailure(t *testing.T) {
	result := assessHost("linux", "arm64", []byte("ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"), nil,
		func() ([]byte, []byte, error) {
			return nil, []byte("sshd unavailable"), errors.New("exit status 1")
		})
	if len(result.Findings) != 1 || result.Findings[0].Status != StatusError || result.Findings[0].Error == nil {
		t.Fatalf("command failure did not remain an assessment error: %#v", result)
	}
}
