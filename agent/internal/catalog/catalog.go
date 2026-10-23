// Package catalog contains the current, explicit hardening-control definitions.
// It intentionally has no dependencies on assessment or planning packages.
package catalog

import (
	"fmt"
	"math"
	"net/url"
	"strings"
)

type Platform string

const (
	PlatformUbuntu       Platform = "ubuntu"
	PlatformCentOSStream Platform = "centos-stream"
)

type Control struct {
	ID                  string
	Title               string
	Scope               PlatformScope
	ExpectedValue       string
	EffectiveSettingKey string
	Severity            string
	Evidence            []EvidenceExpectation
	Remediation         Remediation
	Verification        VerificationExpectation
	Provenance          Provenance
}

type PlatformScope struct {
	Platform               Platform
	OSFamily               string
	ValidatedOSVersions    []string
	ValidatedArchitectures []string
	Limitations            string
}

type EvidenceExpectation struct {
	SettingKey string
	Source     string
	Method     string
}

type Remediation struct {
	Supported        bool
	ActionID         string
	ActionTitle      string
	ActionType       string
	DesiredValue     string
	RiskScore        float64
	RequiresApproval bool
}

type VerificationExpectation struct {
	Method              string
	EffectiveSettingKey string
	ExpectedValue       string
	Source              string
}

type Provenance struct {
	Classification   ProvenanceClassification
	DefinitionSource string
	Benchmark        BenchmarkProvenance
	Notes            string
}

type ProvenanceClassification string

const (
	ProvenanceBenchmarkReferenced ProvenanceClassification = "BENCHMARK_REFERENCED"
	ProvenanceProjectDefined      ProvenanceClassification = "PROJECT_DEFINED_BASELINE"
)

type BenchmarkProvenance struct {
	Title                     string
	Version                   string
	ControlReference          string
	RecommendationTitle       string
	OfficialBenchmarkPageURL  string
	OfficialReleaseUpdateURL  string
	SecondaryRenderingURL     string
	MappingStatus             string
	PrimaryPDFReviewStatus    string
	TargetApplicabilityStatus string
	Notes                     string
}

const (
	MappingCorroboratedSecondary = "CORROBORATED_BY_SECONDARY_SOURCE"
	ReviewNotInspected           = "NOT_INSPECTED"
	ApplicabilityUnconfirmed     = "UNCONFIRMED"

	OfficialBenchmarkTitle   = "CIS Ubuntu Linux 24.04 LTS Benchmark"
	OfficialBenchmarkVersion = "2.0.0"
	OfficialBenchmarkPageURL = "https://www.cisecurity.org/benchmark/ubuntu_linux"
	OfficialReleaseUpdateURL = "https://www.cisecurity.org/insights/blog/cis-benchmarks-june-2026-update"
	SecondaryRenderingURL    = "https://complianceascode.github.io/content-pages/rendered-policies/ubuntu2404/cis_ubuntu2404.html"

	EffectiveSSHConfigSource = "ssh.effective_config"
	EffectiveSSHConfigMethod = "sshd -T effective configuration"
)

const ProjectSSHBaselineName = "Project-defined SSH baseline"
const ProjectSSHBaselineProvenanceNotes = "Project-defined SSH baseline; authoritative CentOS benchmark mapping has not been verified."

var ubuntuSSHControls = []Control{
	{
		ID:                  "5.1.19",
		Title:               "Disable SSH empty passwords",
		Scope:               ubuntuSSHScope(),
		ExpectedValue:       "no",
		EffectiveSettingKey: "PermitEmptyPasswords",
		Severity:            "MEDIUM",
		Evidence: []EvidenceExpectation{{
			SettingKey: "PermitEmptyPasswords",
			Source:     EffectiveSSHConfigSource,
			Method:     EffectiveSSHConfigMethod,
		}},
		Verification: sshVerification("PermitEmptyPasswords", "no"),
		Provenance:   existingImplementationProvenance("5.1.19", "Ensure sshd PermitEmptyPasswords is disabled"),
	},
	{
		ID:                  "5.1.20",
		Title:               "Disable SSH root login",
		Scope:               ubuntuSSHScope(),
		ExpectedValue:       "no",
		EffectiveSettingKey: "PermitRootLogin",
		Severity:            "HIGH",
		Evidence: []EvidenceExpectation{{
			SettingKey: "PermitRootLogin",
			Source:     EffectiveSSHConfigSource,
			Method:     EffectiveSSHConfigMethod,
		}},
		Remediation: Remediation{
			Supported:        true,
			ActionID:         "ACT-SSH-5.1.20",
			ActionTitle:      "Disable SSH root login",
			ActionType:       "SET_SSH_DIRECTIVE",
			DesiredValue:     "no",
			RiskScore:        3.8,
			RequiresApproval: true,
		},
		Verification: sshVerification("PermitRootLogin", "no"),
		Provenance:   existingImplementationProvenance("5.1.20", "Ensure sshd PermitRootLogin is disabled"),
	},
	{
		ID:                  "5.1.21",
		Title:               "Disable SSH user environment",
		Scope:               ubuntuSSHScope(),
		ExpectedValue:       "no",
		EffectiveSettingKey: "PermitUserEnvironment",
		Severity:            "MEDIUM",
		Evidence: []EvidenceExpectation{{
			SettingKey: "PermitUserEnvironment",
			Source:     EffectiveSSHConfigSource,
			Method:     EffectiveSSHConfigMethod,
		}},
		Verification: sshVerification("PermitUserEnvironment", "no"),
		Provenance:   existingImplementationProvenance("5.1.21", "Ensure sshd PermitUserEnvironment is disabled"),
	},
	{
		ID:                  "5.1.22",
		Title:               "Enable SSH PAM",
		Scope:               ubuntuSSHScope(),
		ExpectedValue:       "yes",
		EffectiveSettingKey: "UsePAM",
		Severity:            "MEDIUM",
		Evidence: []EvidenceExpectation{{
			SettingKey: "UsePAM",
			Source:     EffectiveSSHConfigSource,
			Method:     EffectiveSSHConfigMethod,
		}},
		Verification: sshVerification("UsePAM", "yes"),
		Provenance:   existingImplementationProvenance("5.1.22", "Ensure sshd UsePAM is enabled"),
	},
}

var centOSStream9SSHControls = []Control{
	centOSStream9SSHControl("CSTS9-SSH-001", "Disable SSH empty passwords", "PermitEmptyPasswords", "no", "MEDIUM"),
	centOSStream9SSHControl("CSTS9-SSH-002", "Disable SSH root login", "PermitRootLogin", "no", "HIGH"),
	centOSStream9SSHControl("CSTS9-SSH-003", "Disable SSH user environment", "PermitUserEnvironment", "no", "MEDIUM"),
	centOSStream9SSHControl("CSTS9-SSH-004", "Enable SSH PAM", "UsePAM", "yes", "MEDIUM"),
}

func centOSStream9SSHControl(id, title, key, expected, severity string) Control {
	return Control{
		ID: id, Title: title,
		Scope:         PlatformScope{Platform: PlatformCentOSStream, OSFamily: "CentOS Stream", ValidatedOSVersions: []string{"9"}, ValidatedArchitectures: []string{"arm64"}, Limitations: "Project-defined baseline scoped to CentOS Stream 9 ARM64; no authoritative benchmark mapping or live target verification is claimed."},
		ExpectedValue: expected, EffectiveSettingKey: key, Severity: severity,
		Evidence:     []EvidenceExpectation{{SettingKey: key, Source: EffectiveSSHConfigSource, Method: EffectiveSSHConfigMethod}},
		Verification: sshVerification(key, expected),
		Provenance:   Provenance{Classification: ProvenanceProjectDefined, DefinitionSource: ProjectSSHBaselineName, Notes: ProjectSSHBaselineProvenanceNotes},
	}
}

func ubuntuSSHScope() PlatformScope {
	return PlatformScope{
		Platform:               PlatformUbuntu,
		OSFamily:               "Ubuntu",
		ValidatedOSVersions:    []string{"24.04.5"},
		ValidatedArchitectures: []string{"arm64"},
		Limitations:            "Validated on Ubuntu 24.04.5 ARM64 only; other Ubuntu releases and architectures are not established by this catalog.",
	}
}

func sshVerification(key, expected string) VerificationExpectation {
	return VerificationExpectation{
		Method:              "Re-read effective SSH configuration",
		EffectiveSettingKey: key,
		ExpectedValue:       expected,
		Source:              EffectiveSSHConfigSource,
	}
}

func existingImplementationProvenance(controlReference, recommendationTitle string) Provenance {
	return Provenance{
		Classification:   ProvenanceBenchmarkReferenced,
		DefinitionSource: "Existing Ubuntu SSH assessment implementation",
		Benchmark: BenchmarkProvenance{
			Title:                     OfficialBenchmarkTitle,
			Version:                   OfficialBenchmarkVersion,
			ControlReference:          controlReference,
			RecommendationTitle:       recommendationTitle,
			OfficialBenchmarkPageURL:  OfficialBenchmarkPageURL,
			OfficialReleaseUpdateURL:  OfficialReleaseUpdateURL,
			SecondaryRenderingURL:     SecondaryRenderingURL,
			MappingStatus:             MappingCorroboratedSecondary,
			PrimaryPDFReviewStatus:    ReviewNotInspected,
			TargetApplicabilityStatus: ApplicabilityUnconfirmed,
			Notes:                     "Control ID and recommendation title are corroborated by the public CIS-based secondary rendering. The official benchmark PDF was not directly inspected; applicability to the project's Ubuntu 24.04.5 ARM64 target remains unconfirmed.",
		},
		Notes: "Stable user-facing control ID retained from the existing implementation; mapping is corroborated by a secondary source, not directly verified against the official benchmark PDF.",
	}
}

// Controls returns the catalog entries for a platform in stable order.
func Controls(platform Platform) []Control {
	switch {
	case strings.EqualFold(string(platform), string(PlatformUbuntu)):
		return cloneControls(ubuntuSSHControls)
	case strings.EqualFold(string(platform), string(PlatformCentOSStream)):
		return cloneControls(centOSStream9SSHControls)
	default:
		return nil
	}
}

// Lookup returns a copy of a control definition for the given platform and ID.
func Lookup(platform Platform, id string) (Control, bool) {
	for _, control := range Controls(platform) {
		if control.ID == id {
			return control, true
		}
	}
	return Control{}, false
}

func cloneControls(controls []Control) []Control {
	cloned := make([]Control, len(controls))
	for i, control := range controls {
		cloned[i] = control
		cloned[i].Scope.ValidatedOSVersions = append([]string(nil), control.Scope.ValidatedOSVersions...)
		cloned[i].Scope.ValidatedArchitectures = append([]string(nil), control.Scope.ValidatedArchitectures...)
		cloned[i].Evidence = append([]EvidenceExpectation(nil), control.Evidence...)
	}
	return cloned
}

// Validate checks catalog invariants and can also validate test or future candidate data.
func Validate(controls []Control) error {
	if len(controls) == 0 {
		return fmt.Errorf("catalog must define at least one control")
	}
	seen := make(map[string]struct{}, len(controls))
	for _, control := range controls {
		if strings.TrimSpace(control.ID) == "" || strings.TrimSpace(control.ID) != control.ID {
			return fmt.Errorf("control ID is required and must not have surrounding whitespace")
		}
		if _, exists := seen[control.ID]; exists {
			return fmt.Errorf("duplicate control ID %q", control.ID)
		}
		seen[control.ID] = struct{}{}
		if strings.TrimSpace(control.Title) == "" {
			return fmt.Errorf("control %q title is required", control.ID)
		}
		if control.Scope.Platform == "" || control.Scope.OSFamily == "" || len(control.Scope.ValidatedOSVersions) == 0 || len(control.Scope.ValidatedArchitectures) == 0 || strings.TrimSpace(control.Scope.Limitations) == "" {
			return fmt.Errorf("control %q platform scope and limitations must be explicit", control.ID)
		}
		for _, version := range control.Scope.ValidatedOSVersions {
			if strings.TrimSpace(version) == "" {
				return fmt.Errorf("control %q has an empty validated OS version", control.ID)
			}
		}
		for _, architecture := range control.Scope.ValidatedArchitectures {
			if strings.TrimSpace(architecture) == "" {
				return fmt.Errorf("control %q has an empty validated architecture", control.ID)
			}
		}
		if strings.TrimSpace(control.ExpectedValue) == "" || strings.TrimSpace(control.EffectiveSettingKey) == "" {
			return fmt.Errorf("control %q expected value and effective setting key are required", control.ID)
		}
		switch control.Severity {
		case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			return fmt.Errorf("control %q has invalid severity %q", control.ID, control.Severity)
		}
		if len(control.Evidence) == 0 {
			return fmt.Errorf("control %q requires an evidence expectation", control.ID)
		}
		hasEffectiveSettingEvidence := false
		for _, evidence := range control.Evidence {
			if evidence.SettingKey == "" || evidence.Source == "" || evidence.Method == "" {
				return fmt.Errorf("control %q has incomplete evidence metadata", control.ID)
			}
			if evidence.SettingKey == control.EffectiveSettingKey {
				hasEffectiveSettingEvidence = true
			}
		}
		if !hasEffectiveSettingEvidence {
			return fmt.Errorf("control %q evidence does not include its effective setting", control.ID)
		}
		if control.Verification.Method == "" || control.Verification.EffectiveSettingKey == "" || control.Verification.ExpectedValue == "" || control.Verification.Source == "" {
			return fmt.Errorf("control %q requires a complete verification expectation", control.ID)
		}
		if control.Verification.EffectiveSettingKey != control.EffectiveSettingKey || control.Verification.ExpectedValue != control.ExpectedValue {
			return fmt.Errorf("control %q verification does not match its assessment definition", control.ID)
		}
		if control.Provenance.DefinitionSource == "" || control.Provenance.Notes == "" {
			return fmt.Errorf("control %q provenance must be documented", control.ID)
		}
		if control.Provenance.Classification == ProvenanceProjectDefined {
			if control.Provenance.DefinitionSource != ProjectSSHBaselineName || control.Provenance.Notes != ProjectSSHBaselineProvenanceNotes || control.Scope.Platform != PlatformCentOSStream || control.Scope.OSFamily != "CentOS Stream" || len(control.Scope.ValidatedOSVersions) != 1 || control.Scope.ValidatedOSVersions[0] != "9" || len(control.Scope.ValidatedArchitectures) != 1 || control.Scope.ValidatedArchitectures[0] != "arm64" || control.Provenance.Benchmark != (BenchmarkProvenance{}) {
				return fmt.Errorf("control %q project-defined provenance must be explicit and cannot include benchmark claims", control.ID)
			}
			if control.Remediation.Supported || control.Remediation.ActionID != "" || control.Remediation.ActionTitle != "" || control.Remediation.ActionType != "" || control.Remediation.DesiredValue != "" || control.Remediation.RiskScore != 0 || control.Remediation.RequiresApproval {
				return fmt.Errorf("control %q project-defined baseline cannot declare remediation", control.ID)
			}
			continue
		}
		if control.Provenance.Classification != ProvenanceBenchmarkReferenced {
			return fmt.Errorf("control %q has an unsupported provenance classification", control.ID)
		}
		benchmark := control.Provenance.Benchmark
		if benchmark.Title == "" || benchmark.Version == "" || benchmark.ControlReference != control.ID || benchmark.RecommendationTitle == "" {
			return fmt.Errorf("control %q requires complete benchmark title, version, matching reference, and recommendation title", control.ID)
		}
		for _, sourceURL := range []string{benchmark.OfficialBenchmarkPageURL, benchmark.OfficialReleaseUpdateURL, benchmark.SecondaryRenderingURL} {
			if !isHTTPSURL(sourceURL) {
				return fmt.Errorf("control %q provenance source URLs must be absolute HTTPS URLs", control.ID)
			}
		}
		if benchmark.MappingStatus != MappingCorroboratedSecondary || benchmark.PrimaryPDFReviewStatus != ReviewNotInspected || benchmark.TargetApplicabilityStatus != ApplicabilityUnconfirmed {
			return fmt.Errorf("control %q benchmark provenance must distinguish secondary corroboration from uninspected PDF and unconfirmed applicability", control.ID)
		}
		if !strings.Contains(strings.ToLower(benchmark.Notes), "secondary") || !strings.Contains(strings.ToLower(benchmark.Notes), "not directly inspected") || !strings.Contains(strings.ToLower(benchmark.Notes), "remains unconfirmed") {
			return fmt.Errorf("control %q benchmark provenance limitations must be explained", control.ID)
		}
		remediation := control.Remediation
		if remediation.Supported {
			if remediation.ActionID == "" || remediation.ActionTitle == "" || remediation.ActionType == "" || remediation.DesiredValue == "" || remediation.RiskScore <= 0 || math.IsNaN(remediation.RiskScore) || math.IsInf(remediation.RiskScore, 0) {
				return fmt.Errorf("control %q has incomplete remediation metadata", control.ID)
			}
			if remediation.DesiredValue != control.ExpectedValue {
				return fmt.Errorf("control %q remediation value does not match expected value", control.ID)
			}
		} else if remediation.ActionID != "" || remediation.ActionTitle != "" || remediation.ActionType != "" || remediation.DesiredValue != "" || remediation.RiskScore != 0 || remediation.RequiresApproval {
			return fmt.Errorf("control %q has remediation metadata but remediation is unsupported", control.ID)
		}
	}
	return nil
}

func isHTTPSURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}
