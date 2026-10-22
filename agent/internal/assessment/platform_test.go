package assessment

import (
	"errors"
	"testing"
)

func TestAssessHostDispatchesOnlySupportedUbuntuCatalog(t *testing.T) {
	called := false
	result := assessHost("linux", []byte("ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"), nil,
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
	result := assessHost("linux", []byte("NAME=\"CentOS Stream\"\nID=centos\nVERSION_ID=\"9\"\n"), nil,
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

func TestAssessHostRejectsUnsupportedUbuntuReleaseBeforeCommands(t *testing.T) {
	called := false
	result := assessHost("linux", []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"), nil,
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

func TestAssessHostUnknownOSAndDetectionFailureFailClosed(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		release      []byte
		releaseError error
	}{
		{name: "non Linux", goos: "windows"},
		{name: "release unavailable", goos: "linux", releaseError: errors.New("read denied")},
		{name: "unknown Linux distribution", goos: "linux", release: []byte("ID=fedora\nVERSION_ID=42\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			result := assessHost(test.goos, test.release, test.releaseError, func() ([]byte, []byte, error) {
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
	result := assessHost("linux", []byte("ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"), nil,
		func() ([]byte, []byte, error) {
			return nil, []byte("sshd unavailable"), errors.New("exit status 1")
		})
	if len(result.Findings) != 1 || result.Findings[0].Status != StatusError || result.Findings[0].Error == nil {
		t.Fatalf("command failure did not remain an assessment error: %#v", result)
	}
}
