package assessment

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAssessmentContractSerializationAndLegacyCompatibility(t *testing.T) {
	legacyJSON := `{"platform":"ubuntu","findings":[{"control_id":"5.1.20","title":"Disable SSH root login","status":"PASS","severity":"HIGH","current_value":"no","expected_value":"no","message":"Effective configuration matches expected value"}]}`

	var result Assessment
	if err := json.Unmarshal([]byte(legacyJSON), &result); err != nil {
		t.Fatalf("unmarshal legacy assessment: %v", err)
	}
	if result.Platform != PlatformUbuntu || len(result.Findings) != 1 {
		t.Fatalf("legacy response was not preserved: %#v", result)
	}
	if got := result.Findings[0].ControlID; got != "5.1.20" {
		t.Fatalf("control ID = %q, want 5.1.20", got)
	}

	result.Findings[0].Applicability = ApplicabilityApplicable
	result.Findings[0].Source = sshConfigSource
	result.Findings[0].Evidence = []Evidence{{
		Name: "PermitRootLogin", Value: "no", Source: sshConfigSource,
	}}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal assessment contract: %v", err)
	}

	var roundTrip Assessment
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal assessment contract: %v", err)
	}
	finding := roundTrip.Findings[0]
	if roundTrip.Platform != PlatformUbuntu || finding.Applicability != ApplicabilityApplicable {
		t.Fatalf("platform/applicability did not round-trip: %#v", roundTrip)
	}
	if finding.Source != sshConfigSource || len(finding.Evidence) != 1 || finding.Evidence[0].Value != "no" {
		t.Fatalf("source/evidence did not round-trip: %#v", finding)
	}
}

func TestUnknownControlAndStatusArePreserved(t *testing.T) {
	finding := Finding{
		ControlID: "future.control.id",
		Status:    StatusUnknown,
		Severity:  "INFO",
	}
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal unknown control finding: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal unknown control finding: %v", err)
	}
	if decoded.ControlID != finding.ControlID || decoded.Status != StatusUnknown {
		t.Fatalf("unknown control/status changed: %#v", decoded)
	}
}

func TestNotApplicableFindingSerialization(t *testing.T) {
	finding := NotApplicableFinding(
		"5.1.20", "Disable SSH root login", "HIGH", "SSH server is not installed", sshConfigSource,
	)
	if finding.Status != StatusNotApplicable || finding.Applicability != ApplicabilityNotApplicable {
		t.Fatalf("not-applicable finding has incorrect state: %#v", finding)
	}

	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal not-applicable finding: %v", err)
	}
	if !strings.Contains(string(encoded), `"status":"NOT_APPLICABLE"`) ||
		!strings.Contains(string(encoded), `"applicability":"NOT_APPLICABLE"`) {
		t.Fatalf("serialized finding does not state non-applicability: %s", encoded)
	}
}

func TestNormalizedAssessmentErrorSerialization(t *testing.T) {
	finding := sshAssessmentError(assertionError("permission denied"))
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal normalized assessment error: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal normalized assessment error: %v", err)
	}
	if decoded.Status != StatusError || decoded.Error == nil {
		t.Fatalf("normalized error missing: %#v", decoded)
	}
	if decoded.Error.Code != "ASSESSMENT_EVALUATION_FAILED" || decoded.Error.Source != sshConfigSource {
		t.Fatalf("unexpected normalized error: %#v", decoded.Error)
	}
	if decoded.Error.Message != "permission denied" || decoded.Message != decoded.Error.Message {
		t.Fatalf("legacy and normalized error messages differ: %#v", decoded)
	}
}

type assertionError string

func (err assertionError) Error() string { return string(err) }
