package catalog

import (
	"strings"
	"testing"
)

func TestUbuntuSSHControlsAreUniqueAndValid(t *testing.T) {
	controls := Controls(PlatformUbuntu)
	if len(controls) != 4 {
		t.Fatalf("got %d Ubuntu controls, want 4", len(controls))
	}
	if err := Validate(controls); err != nil {
		t.Fatalf("validate catalog: %v", err)
	}

	seen := make(map[string]struct{}, len(controls))
	for _, control := range controls {
		if _, exists := seen[control.ID]; exists {
			t.Fatalf("duplicate control ID %q", control.ID)
		}
		seen[control.ID] = struct{}{}
	}
}

func TestCatalogDefinitionsPreserveUbuntuSSHControlsAndValues(t *testing.T) {
	want := map[string]struct {
		title    string
		key      string
		value    string
		severity string
	}{
		"5.1.19": {"Disable SSH empty passwords", "PermitEmptyPasswords", "no", "MEDIUM"},
		"5.1.20": {"Disable SSH root login", "PermitRootLogin", "no", "HIGH"},
		"5.1.21": {"Disable SSH user environment", "PermitUserEnvironment", "no", "MEDIUM"},
		"5.1.22": {"Enable SSH PAM", "UsePAM", "yes", "MEDIUM"},
	}
	for _, control := range Controls(PlatformUbuntu) {
		expected, exists := want[control.ID]
		if !exists {
			t.Errorf("unexpected control ID %q", control.ID)
			continue
		}
		if control.Title != expected.title || control.EffectiveSettingKey != expected.key || control.ExpectedValue != expected.value || control.Severity != expected.severity {
			t.Errorf("control %s definition = %#v, want title/key/value/severity %q/%q/%q/%q", control.ID, control, expected.title, expected.key, expected.value, expected.severity)
		}
		if control.Scope.Platform != PlatformUbuntu || control.Scope.OSFamily != "Ubuntu" || len(control.Scope.ValidatedOSVersions) != 1 || control.Scope.ValidatedOSVersions[0] != "24.04.5" || len(control.Scope.ValidatedArchitectures) != 1 || control.Scope.ValidatedArchitectures[0] != "arm64" {
			t.Errorf("control %s has unexpected applicability scope: %#v", control.ID, control.Scope)
		}
		if !strings.Contains(control.Scope.Limitations, "other Ubuntu releases") {
			t.Errorf("control %s does not state its version limitation: %q", control.ID, control.Scope.Limitations)
		}
		if len(control.Evidence) != 1 || control.Evidence[0].SettingKey != expected.key || control.Evidence[0].Source != EffectiveSSHConfigSource || control.Evidence[0].Method != EffectiveSSHConfigMethod {
			t.Errorf("control %s has incomplete evidence expectation: %#v", control.ID, control.Evidence)
		}
		if control.Verification.EffectiveSettingKey != expected.key || control.Verification.ExpectedValue != expected.value || control.Verification.Source != EffectiveSSHConfigSource {
			t.Errorf("control %s has inconsistent verification expectation: %#v", control.ID, control.Verification)
		}
	}
}

func TestBenchmarkProvenanceIsCompleteAndAccuratelyQualified(t *testing.T) {
	wantRecommendations := map[string]string{
		"5.1.19": "Ensure sshd PermitEmptyPasswords is disabled",
		"5.1.20": "Ensure sshd PermitRootLogin is disabled",
		"5.1.21": "Ensure sshd PermitUserEnvironment is disabled",
		"5.1.22": "Ensure sshd UsePAM is enabled",
	}
	for _, control := range Controls(PlatformUbuntu) {
		benchmark := control.Provenance.Benchmark
		if benchmark.Title != "CIS Ubuntu Linux 24.04 LTS Benchmark" || benchmark.Version != "2.0.0" {
			t.Errorf("control %s benchmark identity = %q v%s", control.ID, benchmark.Title, benchmark.Version)
		}
		if benchmark.ControlReference != control.ID || benchmark.RecommendationTitle != wantRecommendations[control.ID] {
			t.Errorf("control %s benchmark mapping = reference %q, recommendation %q", control.ID, benchmark.ControlReference, benchmark.RecommendationTitle)
		}
		if benchmark.OfficialBenchmarkPageURL != OfficialBenchmarkPageURL || benchmark.OfficialReleaseUpdateURL != OfficialReleaseUpdateURL || benchmark.SecondaryRenderingURL != SecondaryRenderingURL {
			t.Errorf("control %s provenance source URLs are incomplete or unexpected: %#v", control.ID, benchmark)
		}
		if benchmark.MappingStatus != MappingCorroboratedSecondary || benchmark.PrimaryPDFReviewStatus != ReviewNotInspected || benchmark.TargetApplicabilityStatus != ApplicabilityUnconfirmed {
			t.Errorf("control %s overstates benchmark verification: %#v", control.ID, benchmark)
		}
		if !strings.Contains(benchmark.Notes, "public CIS-based secondary rendering") || !strings.Contains(benchmark.Notes, "official benchmark PDF was not directly inspected") || !strings.Contains(benchmark.Notes, "ARM64 target remains unconfirmed") {
			t.Errorf("control %s does not state provenance limitations: %q", control.ID, benchmark.Notes)
		}
	}
}

func TestOnlyExistingRootLoginControlHasApprovalRemediation(t *testing.T) {
	for _, control := range Controls(PlatformUbuntu) {
		if control.ID == "5.1.20" {
			remediation := control.Remediation
			if !remediation.Supported || !remediation.RequiresApproval || remediation.ActionID != "ACT-SSH-5.1.20" || remediation.ActionType != "SET_SSH_DIRECTIVE" || remediation.DesiredValue != "no" {
				t.Fatalf("5.1.20 remediation = %#v", remediation)
			}
			continue
		}
		if control.Remediation.Supported || control.Remediation.RequiresApproval || control.Remediation.ActionID != "" || control.Remediation.ActionType != "" || control.Remediation.DesiredValue != "" {
			t.Errorf("control %s unexpectedly supports remediation: %#v", control.ID, control.Remediation)
		}
	}
}

func TestUnsupportedPlatformsHaveNoCatalogEntries(t *testing.T) {
	for _, platform := range []Platform{"centos", "windows", "docker", "aws", "edge"} {
		if controls := Controls(platform); len(controls) != 0 {
			t.Errorf("platform %q unexpectedly has catalog entries: %#v", platform, controls)
		}
	}
}

func TestCentOSStream9CatalogIsProjectDefinedAndAssessmentOnly(t *testing.T) {
	controls := Controls(PlatformCentOSStream)
	if len(controls) != 4 {
		t.Fatalf("got %d CentOS controls, want 4", len(controls))
	}
	if err := Validate(controls); err != nil {
		t.Fatalf("validate CentOS catalog: %v", err)
	}
	want := []struct{ id, key, value string }{
		{"CSTS9-SSH-001", "PermitEmptyPasswords", "no"},
		{"CSTS9-SSH-002", "PermitRootLogin", "no"},
		{"CSTS9-SSH-003", "PermitUserEnvironment", "no"},
		{"CSTS9-SSH-004", "UsePAM", "yes"},
	}
	for i, control := range controls {
		expected := want[i]
		if control.ID != expected.id || control.EffectiveSettingKey != expected.key || control.ExpectedValue != expected.value {
			t.Errorf("control[%d]=%#v, want %#v", i, control, expected)
		}
		if control.Scope.Platform != PlatformCentOSStream || control.Scope.OSFamily != "CentOS Stream" || len(control.Scope.ValidatedOSVersions) != 1 || control.Scope.ValidatedOSVersions[0] != "9" || len(control.Scope.ValidatedArchitectures) != 1 || control.Scope.ValidatedArchitectures[0] != "arm64" {
			t.Errorf("scope=%#v", control.Scope)
		}
		if control.Provenance.Classification != ProvenanceProjectDefined || control.Provenance.DefinitionSource != ProjectSSHBaselineName || control.Provenance.Benchmark != (BenchmarkProvenance{}) {
			t.Errorf("provenance=%#v", control.Provenance)
		}
		if control.Remediation != (Remediation{}) {
			t.Errorf("CentOS remediation must be empty: %#v", control.Remediation)
		}
		if len(control.Evidence) != 1 || control.Evidence[0].SettingKey != expected.key || control.Evidence[0].Source != EffectiveSSHConfigSource || control.Verification.ExpectedValue != expected.value {
			t.Errorf("evidence/verification mismatch: %#v", control)
		}
	}
}

func TestProjectDefinedProvenanceCannotBeUsedToWeakenUbuntuValidation(t *testing.T) {
	controls := Controls(PlatformUbuntu)
	controls[0].Provenance.Classification = ProvenanceProjectDefined
	if err := Validate(controls); err == nil {
		t.Fatal("Ubuntu accepted project-defined provenance classification")
	}
}

func TestValidateRejectsCentOSProjectBaselineBenchmarkClaimsAndRemediation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Control)
	}{
		{name: "benchmark title", mutate: func(c *Control) { c.Provenance.Benchmark.Title = "Unverified benchmark" }},
		{name: "benchmark reference", mutate: func(c *Control) { c.Provenance.Benchmark.ControlReference = "CIS-5.1.19" }},
		{name: "benchmark claim in notes", mutate: func(c *Control) { c.Provenance.Notes = "Verified against the CentOS CIS benchmark." }},
		{name: "remediation metadata", mutate: func(c *Control) { c.Remediation.ActionID = "ACT-CSTS9-SSH-002" }},
		{name: "supported remediation", mutate: func(c *Control) {
			c.Remediation = Remediation{Supported: true, ActionID: "ACT-CSTS9-SSH-002", ActionTitle: "Change SSH setting", ActionType: "SET_SSH_DIRECTIVE", DesiredValue: "no", RiskScore: 1, RequiresApproval: true}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controls := Controls(PlatformCentOSStream)
			test.mutate(&controls[0])
			if err := Validate(controls); err == nil {
				t.Fatal("Validate accepted CentOS project baseline with unsupported metadata")
			}
		})
	}
}

func TestValidateRejectsDuplicateAndIncompleteDefinitions(t *testing.T) {
	valid := Controls(PlatformUbuntu)
	if err := Validate(nil); err == nil || !strings.Contains(err.Error(), "at least one control") {
		t.Errorf("Validate empty catalog error = %v, want empty catalog error", err)
	}

	duplicate := append(append([]Control(nil), valid...), valid[0])
	if err := Validate(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate control ID") {
		t.Errorf("Validate duplicate controls error = %v, want duplicate ID error", err)
	}

	invalid := Controls(PlatformUbuntu)
	invalid[0].Scope.ValidatedOSVersions = nil
	if err := Validate(invalid); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Errorf("Validate incomplete scope error = %v, want scope error", err)
	}

	invalid = Controls(PlatformUbuntu)
	invalid[0].Evidence = nil
	if err := Validate(invalid); err == nil || !strings.Contains(err.Error(), "evidence expectation") {
		t.Errorf("Validate missing evidence error = %v, want evidence error", err)
	}

	invalid = Controls(PlatformUbuntu)
	invalid[1].Remediation.DesiredValue = "yes"
	if err := Validate(invalid); err == nil || !strings.Contains(err.Error(), "does not match expected value") {
		t.Errorf("Validate inconsistent remediation error = %v, want remediation mismatch", err)
	}

	invalid = Controls(PlatformUbuntu)
	invalid[0].Provenance.Benchmark.MappingStatus = ""
	if err := Validate(invalid); err == nil || !strings.Contains(err.Error(), "secondary corroboration") {
		t.Errorf("Validate missing provenance status error = %v, want qualified mapping status error", err)
	}

	invalid = Controls(PlatformUbuntu)
	invalid[0].Provenance.Benchmark.ControlReference = "different-control"
	if err := Validate(invalid); err == nil || !strings.Contains(err.Error(), "matching reference") {
		t.Errorf("Validate mismatched benchmark reference error = %v, want matching-reference error", err)
	}

	invalid = Controls(PlatformUbuntu)
	invalid[0].Provenance.Benchmark.SecondaryRenderingURL = "http://example.invalid/rendering"
	if err := Validate(invalid); err == nil || !strings.Contains(err.Error(), "absolute HTTPS") {
		t.Errorf("Validate invalid provenance URL error = %v, want HTTPS URL error", err)
	}
}

func TestControlsReturnsCopies(t *testing.T) {
	controls := Controls(PlatformUbuntu)
	controls[0].ID = "mutated"
	controls[0].Scope.ValidatedOSVersions[0] = "0.0"
	controls[0].Scope.ValidatedArchitectures[0] = "mutated"
	controls[0].Evidence[0].Source = "mutated"

	original, ok := Lookup(PlatformUbuntu, "5.1.19")
	if !ok || original.ID != "5.1.19" || original.Scope.ValidatedOSVersions[0] != "24.04.5" || original.Scope.ValidatedArchitectures[0] != "arm64" || original.Evidence[0].Source != EffectiveSSHConfigSource {
		t.Fatalf("caller mutation changed catalog definition: %#v", original)
	}
}
