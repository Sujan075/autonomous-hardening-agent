package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/executor"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/planner"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/state"
)

func TestPlanBindingMutationsChangeDigest(t *testing.T) {
	evidence := testEvidence()
	plan := testPlan()
	original, err := PlanBindingDigest("target-1", OperationExecute, "policy-v1", "catalog-v1", plan, evidence)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*planner.Plan, *EvidenceProvenance, *string, *string, *string){
		"target": func(_ *planner.Plan, e *EvidenceProvenance, target, _, _ *string) {
			*target = "target-2"
			e.TargetID = "target-2"
		},
		"ordered action": func(p *planner.Plan, _ *EvidenceProvenance, _, _, _ *string) {
			p.Actions[0], p.Actions[1] = p.Actions[1], p.Actions[0]
		},
		"action parameter": func(p *planner.Plan, _ *EvidenceProvenance, _, _, _ *string) { p.Actions[0].DesiredValue += "-changed" },
		"policy version":   func(_ *planner.Plan, _ *EvidenceProvenance, _, policy, _ *string) { *policy = "policy-v2" },
		"catalog version": func(_ *planner.Plan, evidence *EvidenceProvenance, _, _, catalog *string) {
			*catalog = "catalog-v2"
			evidence.CatalogVersion = "catalog-v2"
		},
		"evidence reference": func(_ *planner.Plan, e *EvidenceProvenance, _, _, _ *string) { e.AssessmentID = "assessment-2" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changedPlan, changedEvidence := testPlan(), testEvidence()
			target, policy, catalog := "target-1", "policy-v1", "catalog-v1"
			mutate(&changedPlan, &changedEvidence, &target, &policy, &catalog)
			got, err := PlanBindingDigest(target, OperationExecute, policy, catalog, changedPlan, changedEvidence)
			if err != nil {
				t.Fatal(err)
			}
			if got == original {
				t.Fatal("plan digest did not change after binding mutation")
			}
		})
	}
}

func TestEvidenceDigestBindsAssessmentPayloadAndProvenance(t *testing.T) {
	original, err := EvidenceDigest(testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*EvidenceProvenance){
		"source":          func(p *EvidenceProvenance) { p.Source = "other-source" },
		"collection time": func(p *EvidenceProvenance) { p.CollectedAt = p.CollectedAt.Add(time.Second) },
		"evidence value":  func(p *EvidenceProvenance) { p.Assessment.Findings[0].Evidence[0].Value = "changed" },
		"finding order": func(p *EvidenceProvenance) {
			p.Assessment.Findings[0], p.Assessment.Findings[1] = p.Assessment.Findings[1], p.Assessment.Findings[0]
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := testEvidence()
			mutate(&changed)
			got, err := EvidenceDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == original {
				t.Fatal("evidence digest did not change after mutation")
			}
		})
	}
}

func TestRecoveryManifestDigestBindsStateAndRejectsCorruption(t *testing.T) {
	manifest := testRecoveryManifest()
	original, err := RecoveryManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	changed := testRecoveryManifest()
	changed.TargetID = "target-2"
	assertDifferentRecoveryDigest(t, original, changed)

	changed = testRecoveryManifest()
	changed.ExecutionID = "execution-2"
	assertDifferentRecoveryDigest(t, original, changed)

	changed = testRecoveryManifest()
	changed.State.File.Content = []byte("different previous configuration\n")
	hash := sha256.Sum256(changed.State.File.Content)
	changed.State.File.ContentSHA = hex.EncodeToString(hash[:])
	assertDifferentRecoveryDigest(t, original, changed)

	corrupt := testRecoveryManifest()
	corrupt.State.File.ContentSHA = "00" + corrupt.State.File.ContentSHA[2:]
	if _, err := RecoveryManifestDigest(corrupt); err == nil {
		t.Fatal("RecoveryManifestDigest accepted recovery state with a corrupt content hash")
	}
}

func TestBindingContractsMatchSharedGoldenVectors(t *testing.T) {
	contents, err := os.ReadFile("testdata/approval_bindings_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Evidence struct {
			Version      string `json:"version"`
			CanonicalHex string `json:"canonical_hex"`
			SHA256       string `json:"sha256"`
		} `json:"evidence"`
		Plan struct {
			Version      string `json:"version"`
			CanonicalHex string `json:"canonical_hex"`
			SHA256       string `json:"sha256"`
		} `json:"plan"`
		Recovery struct {
			Version      string `json:"version"`
			CanonicalHex string `json:"canonical_hex"`
			SHA256       string `json:"sha256"`
		} `json:"recovery"`
	}
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Evidence.Version != EvidenceBindingVersion || vectors.Plan.Version != PlanBindingVersion || vectors.Recovery.Version != RecoveryBindingVersion {
		t.Fatal("shared binding vector version does not match implementation")
	}
	evidenceBytes, err := canonicalEvidenceBytes(testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	assertVector(t, evidenceBytes, vectors.Evidence.CanonicalHex, vectors.Evidence.SHA256)
	planBytes, err := canonicalPlanBindingBytes("target-1", OperationExecute, "policy-v1", "catalog-v1", testPlan(), testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	assertVector(t, planBytes, vectors.Plan.CanonicalHex, vectors.Plan.SHA256)
	recoveryBytes, err := canonicalRecoveryManifestBytes(testRecoveryManifest())
	if err != nil {
		t.Fatal(err)
	}
	assertVector(t, recoveryBytes, vectors.Recovery.CanonicalHex, vectors.Recovery.SHA256)
}

func assertVector(t *testing.T, canonical []byte, wantHex, wantDigest string) {
	t.Helper()
	if got := hex.EncodeToString(canonical); got != wantHex {
		t.Fatalf("canonical bytes = %s, want %s", got, wantHex)
	}
	if got := digestCanonical(canonical); got != "sha256:"+wantDigest {
		t.Fatalf("digest = %s, want sha256:%s", got, wantDigest)
	}
}

func assertDifferentRecoveryDigest(t *testing.T, original string, changed RecoveryManifest) {
	t.Helper()
	got, err := RecoveryManifestDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if got == original {
		t.Fatal("recovery manifest digest did not change after mutation")
	}
}

func testEvidence() EvidenceProvenance {
	return EvidenceProvenance{
		AssessmentID: "assessment-1", TargetID: "target-1", Source: "agent-assessment", CatalogVersion: "catalog-v1",
		CollectedAt: time.Date(2026, 10, 23, 12, 0, 0, 123456789, time.UTC),
		Assessment: assessment.Assessment{Platform: "ubuntu", Findings: []assessment.Finding{
			{ControlID: "SSH-1", Title: "SSH setting one", Status: assessment.StatusFail, Applicability: assessment.ApplicabilityApplicable, Severity: "HIGH", CurrentValue: "yes", ExpectedValue: "no", Message: "must be disabled", Source: "sshd", Evidence: []assessment.Evidence{{Name: "PermitRootLogin", Value: "yes", Source: "sshd -T"}}},
			{ControlID: "SSH-2", Title: "SSH setting two", Status: assessment.StatusPass, Applicability: assessment.ApplicabilityApplicable, Severity: "LOW", CurrentValue: "no", ExpectedValue: "no", Message: "compliant", Source: "sshd"},
		}},
	}
}

func testPlan() planner.Plan {
	action1 := testAction()
	action2 := testAction()
	action2.ActionID = "ACT-SSH-SECOND"
	action2.ControlID = "SSH-SECOND"
	return planner.Plan{Status: planner.PlanStatusReady, Platform: "ubuntu", Actions: []planner.Action{action1, action2}}
}

func testRecoveryManifest() RecoveryManifest {
	content := []byte("PermitRootLogin yes\n")
	hash := sha256.Sum256(content)
	stateTime := time.Date(2026, 10, 23, 12, 1, 0, 0, time.UTC)
	return RecoveryManifest{
		TargetID: "target-1", AgentID: "agent-1", BindingGeneration: "generation-1", ExecutionID: "execution-1", Action: testAction(),
		State: executor.ExecutionState{ActionID: testAction().ActionID, PreviousEffectiveValue: "yes", CapturedAt: stateTime,
			File: state.FileState{Path: "/etc/ssh/sshd_config.d/99-agent.conf", Exists: true, Mode: 0600, ContentSHA: hex.EncodeToString(hash[:]), Content: content, CapturedAt: stateTime}},
	}
}
