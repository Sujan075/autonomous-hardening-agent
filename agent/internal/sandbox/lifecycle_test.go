package sandbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/approval"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/catalog"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/executor"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/planner"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/privhelper"
)

func TestFixedSandboxScenariosExerciseRealOpenSSHAndRecovery(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skip("OpenSSH server binary unavailable")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	tests := []struct{ name, scenario, status string }{
		{"noncompliant execute independent verify and signed rollback", "roundtrip", string(RolledBack)},
		{"compliant no-op", "compliant", "COMPLIANT"},
		{"first-value precedence conflict and automatic recovery", "precedence-conflict", string(RolledBack)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Run(tc.scenario)
			if err != nil {
				t.Fatalf("Run(%q): %v", tc.scenario, err)
			}
			if result.Status != tc.status {
				t.Fatalf("status=%q, want %q (error=%s)", result.Status, tc.status, result.Error)
			}
			if !result.SandboxOnly || !result.TestOnlyTrust || result.LiveTargetModified {
				t.Fatalf("unsafe run metadata: %+v", result)
			}
			if len(result.Findings) != 4 {
				t.Fatalf("finding count=%d, want four: %+v", len(result.Findings), result.Findings)
			}
			if tc.scenario == "roundtrip" {
				if result.Verification == nil || result.Verification.Status != "VERIFIED" || result.Verification.Source != "independent sshd -T -f temporary-config" {
					t.Fatalf("missing independent verification: %+v", result.Verification)
				}
				if result.Recovery["status"] != "ROLLED_BACK" || result.Recovery["verified_independently"] != true {
					t.Fatalf("missing independent recovery: %+v", result.Recovery)
				}
				if len(result.AuditEvents) != 4 {
					t.Fatalf("audit event count=%d, want execute and rollback start/finish", len(result.AuditEvents))
				}
				if result.Approval["token_persisted"] != false {
					t.Fatal("test approval token must not be persisted")
				}
			}
			if tc.scenario == "compliant" && len(result.AuditEvents) != 0 {
				t.Fatalf("compliant no-op unexpectedly issued an action: %+v", result.AuditEvents)
			}
			if tc.scenario == "precedence-conflict" {
				if result.Verification == nil || result.Verification.Status != "FAILED_AS_EXPECTED" || result.Recovery["verified_independently"] != true {
					t.Fatalf("precedence failure did not recover: %+v", result)
				}
				if len(result.AuditEvents) != 2 {
					t.Fatalf("audit event count=%d, want start/finish with recovery-required outcome", len(result.AuditEvents))
				}
			}
		})
	}
}

func TestLifecycleMachineRejectsInvalidAndDuplicateTransitions(t *testing.T) {
	m := &machine{}
	if err := m.advance(Initialized, "start"); err != nil {
		t.Fatal(err)
	}
	if err := m.advance(Initialized, "duplicate"); err == nil {
		t.Fatal("duplicate initialization transition accepted")
	}
	if err := m.advance(Verified, "skip steps"); err == nil {
		t.Fatal("invalid transition accepted")
	}
	if err := m.advance(Discovered, "discover"); err != nil {
		t.Fatal(err)
	}
}

func TestComposedHelperRejectsMismatchedAndInvalidApprovalScenarios(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skip("OpenSSH server binary unavailable")
	}
	fixture, err := executor.NewTemporarySSHConfigSandbox(executor.SSHFixtureNonCompliant)
	if err != nil {
		t.Skipf("local OpenSSH fixture unavailable: %v", err)
	}
	defer fixture.Close()
	effective, err := fixture.EffectiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := findingsFromEffectiveConfig(effective)
	if err != nil {
		t.Fatal(err)
	}
	plan := planner.BuildAssessmentPlan(assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings})
	if plan.Status != planner.PlanStatusReady || len(plan.Actions) != 1 {
		t.Fatalf("fixture plan=%+v", plan)
	}
	targetID, runID := "sandbox-local-approval-test", "approval-matrix"
	evidence := approval.EvidenceProvenance{AssessmentID: "assessment-matrix", TargetID: targetID, Source: "temporary-sshd-fixture", CatalogVersion: testCatalog, CollectedAt: time.Now().UTC(), Assessment: assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}}
	action := plan.Actions[0]
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	audit := &fileAuditSink{path: t.TempDir() + "/audit.jsonl"}
	called := 0
	helper, err := newHelper(key, audit, t.TempDir(), func() (executor.ExecutionResult, error) { called++; return fixture.Apply() }, approval.OperationExecute, targetID, runID, action, plan, evidence, approval.RecoveryManifest{})
	if err != nil {
		t.Fatal(err)
	}
	type testCase struct {
		name            string
		mutate          func(map[string]any)
		requestMutation func(*privhelper.Request)
	}
	mutations := []testCase{
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() }, nil},
		{"not-yet-valid", func(c map[string]any) { c["nbf"] = time.Now().Add(time.Minute).Unix() }, nil},
		{"issuer-mismatch", func(c map[string]any) { c["iss"] = "other" }, nil},
		{"audience-mismatch", func(c map[string]any) { c["aud"] = "other" }, nil},
		{"agent-mismatch", func(c map[string]any) { c["agent_id"] = "other" }, nil},
		{"target-mismatch", func(c map[string]any) { c["target_id"] = "other" }, nil},
		{"binding-mismatch", func(c map[string]any) { c["binding_generation"] = "other" }, nil},
		{"operation-mismatch", func(c map[string]any) { c["operation"] = approval.OperationRollback }, nil},
		{"action-mismatch", func(c map[string]any) { c["action_id"] = "other" }, nil},
		{"action-digest-mismatch", func(c map[string]any) { c["action_digest"] = "sha256:" + strings.Repeat("1", 64) }, nil},
		{"plan-mismatch", func(c map[string]any) { c["plan_digest"] = "sha256:" + strings.Repeat("2", 64) }, nil},
		{"evidence-mismatch", func(c map[string]any) { c["evidence_digest"] = "sha256:" + strings.Repeat("3", 64) }, nil},
		{"policy-version-mismatch", func(c map[string]any) { c["policy_version"] = "other" }, nil},
		{"catalog-version-mismatch", func(c map[string]any) { c["catalog_version"] = "other" }, nil},
		{"missing-issuer", func(c map[string]any) { delete(c, "iss") }, nil},
		{"unknown-claim", func(c map[string]any) { c["admin"] = true }, nil},
		{"request-jti-mismatch", nil, func(r *privhelper.Request) { r.RequestID = "different-id" }},
		{"request-action-mismatch", nil, func(r *privhelper.Request) { r.ActionID = "other-action" }},
		{"request-operation-mismatch", nil, func(r *privhelper.Request) { r.Operation = approval.OperationRollback }},
		{"missing-token", nil, func(r *privhelper.Request) { r.ApprovalToken = "" }},
		{"malformed-token", nil, func(r *privhelper.Request) { r.ApprovalToken = "not-a-jwt" }},
		{"unknown-key-id", nil, func(r *privhelper.Request) {
			parts := strings.Split(r.ApprovalToken, ".")
			parts[0] = "eyJhbGciOiJFUzI1NiIsImtpZCI6Im90aGVyIiwidHlwIjoiYXBwbGljYXRpb24vYXBwcm92YWwrand0In0"
			r.ApprovalToken = strings.Join(parts, ".")
		}},
		{"bad-signature", nil, func(r *privhelper.Request) {
			parts := strings.Split(r.ApprovalToken, ".")
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			signature[0] ^= 0x01
			parts[2] = base64.RawURLEncoding.EncodeToString(signature)
			r.ApprovalToken = strings.Join(parts, ".")
		}},
	}
	for index, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			requestID := fmt.Sprintf("case-%02d", index)
			claims, err := approvalClaims(key, requestID, approval.OperationExecute, targetID, runID, action, plan, evidence, approval.RecoveryManifest{}, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			token, err := signClaims(key, claims)
			if err != nil {
				t.Fatal(err)
			}
			request := privhelper.Request{Schema: privhelper.RequestSchema, RequestID: requestID, Operation: approval.OperationExecute, ActionID: action.ActionID, ApprovalToken: token}
			if tc.requestMutation != nil {
				tc.requestMutation(&request)
			}
			raw, _ := json.Marshal(request)
			if _, err := helper.Process(raw); err == nil {
				t.Fatal("invalid approval was accepted")
			}
			if called != 0 {
				t.Fatalf("operation invoked %d times", called)
			}
		})
	}
	if value, err := fixture.EffectivePermitRootLogin(); err != nil || value == "no" {
		t.Fatalf("rejected approvals changed fixture: value=%q err=%v", value, err)
	}
	if len(audit.snapshot) != 0 {
		t.Fatalf("rejected approvals appended audit events: %+v", audit.snapshot)
	}
}

func TestSandboxHelperRejectsReplayBeforeSecondOperation(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skip("OpenSSH server binary unavailable")
	}
	fixture, err := executor.NewTemporarySSHConfigSandbox(executor.SSHFixtureNonCompliant)
	if err != nil {
		t.Skipf("local OpenSSH fixture unavailable: %v", err)
	}
	defer fixture.Close()
	effective, err := fixture.EffectiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := findingsFromEffectiveConfig(effective)
	if err != nil {
		t.Fatal(err)
	}
	plan := planner.BuildAssessmentPlan(assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings})
	action := plan.Actions[0]
	targetID, runID := "sandbox-replay", "replay-test"
	evidence := approval.EvidenceProvenance{AssessmentID: "assessment-replay", TargetID: targetID, Source: "temporary-sshd-fixture", CatalogVersion: testCatalog, CollectedAt: time.Now().UTC(), Assessment: assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	audit := &fileAuditSink{path: t.TempDir() + "/audit.jsonl"}
	helper, err := newHelper(key, audit, t.TempDir(), func() (executor.ExecutionResult, error) { calls++; return fixture.Apply() }, approval.OperationExecute, targetID, runID, action, plan, evidence, approval.RecoveryManifest{})
	if err != nil {
		t.Fatal(err)
	}
	requestID := "replay-one"
	claims, err := approvalClaims(key, requestID, approval.OperationExecute, targetID, runID, action, plan, evidence, approval.RecoveryManifest{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	token, err := signClaims(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(privhelper.Request{Schema: privhelper.RequestSchema, RequestID: requestID, Operation: approval.OperationExecute, ActionID: action.ActionID, ApprovalToken: token})
	if result, err := helper.Process(raw); err != nil || result.Status != "VERIFIED" {
		t.Fatalf("first request result=%+v err=%v", result, err)
	}
	if _, err := helper.Process(raw); !errors.Is(err, privhelper.ErrReplay) {
		t.Fatalf("replayed approval error=%v", err)
	}
	if calls != 1 {
		t.Fatalf("operation calls=%d, want one", calls)
	}
}

type rejectingAudit struct{}

func (rejectingAudit) Append(privhelper.AuditEvent) error {
	return errors.New("injected durable audit failure")
}

func TestComposedHelperPreAuditFailurePreventsFixtureMutation(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skip("OpenSSH server binary unavailable")
	}
	fixture, err := executor.NewTemporarySSHConfigSandbox(executor.SSHFixtureNonCompliant)
	if err != nil {
		t.Skipf("local OpenSSH fixture unavailable: %v", err)
	}
	defer fixture.Close()
	effective, err := fixture.EffectiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := findingsFromEffectiveConfig(effective)
	if err != nil {
		t.Fatal(err)
	}
	plan := planner.BuildAssessmentPlan(assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings})
	if plan.Status != planner.PlanStatusReady || len(plan.Actions) != 1 {
		t.Fatalf("fixture plan=%+v", plan)
	}
	targetID, runID := "sandbox-local-audit-failure", "audit-failure-test"
	evidence := approval.EvidenceProvenance{AssessmentID: "assessment-audit-failure", TargetID: targetID, Source: "temporary-sshd-fixture", CatalogVersion: testCatalog, CollectedAt: time.Now().UTC(), Assessment: assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	helper, err := newHelper(key, rejectingAudit{}, t.TempDir(), func() (executor.ExecutionResult, error) { calls++; return fixture.Apply() }, approval.OperationExecute, targetID, runID, plan.Actions[0], plan, evidence, approval.RecoveryManifest{})
	if err != nil {
		t.Fatal(err)
	}
	requestID := "audit-reject-one"
	claims, err := approvalClaims(key, requestID, approval.OperationExecute, targetID, runID, plan.Actions[0], plan, evidence, approval.RecoveryManifest{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	token, err := signClaims(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(privhelper.Request{Schema: privhelper.RequestSchema, RequestID: requestID, Operation: approval.OperationExecute, ActionID: plan.Actions[0].ActionID, ApprovalToken: token})
	if _, err := helper.Process(raw); !errors.Is(err, privhelper.ErrAuditBefore) {
		t.Fatalf("pre-operation audit error=%v", err)
	}
	if calls != 0 {
		t.Fatalf("operation called %d times after failed pre-audit", calls)
	}
	value, err := fixture.EffectivePermitRootLogin()
	if err != nil || value == "no" {
		t.Fatalf("pre-audit failure modified fixture: value=%q err=%v", value, err)
	}
}

func TestUncertainOrIncompleteSSHObservationBlocksPlan(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		t.Skip("OpenSSH server binary unavailable")
	}
	fixture, err := executor.NewTemporarySSHConfigSandbox(executor.SSHFixtureNonCompliant)
	if err != nil {
		t.Skipf("local OpenSSH fixture unavailable: %v", err)
	}
	defer fixture.Close()
	effective, err := fixture.EffectiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	base, err := findingsFromEffectiveConfig(effective)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func([]assessment.Finding)
	}{
		{"missing evidence", func(f []assessment.Finding) { f[1].Evidence = nil }},
		{"unknown finding", func(f []assessment.Finding) { f[1].Status = assessment.StatusUnknown }},
		{"error finding", func(f []assessment.Finding) {
			f[1].Status = assessment.StatusError
			f[1].Error = &assessment.NormalizedError{Code: "fixture_error", Message: "effective read unavailable", Source: catalog.EffectiveSSHConfigSource}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := append([]assessment.Finding(nil), base...)
			tc.change(findings)
			plan := planner.BuildAssessmentPlan(assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings})
			if plan.Status != planner.PlanStatusBlocked || len(plan.Actions) != 0 {
				t.Fatalf("plan=%+v", plan)
			}
		})
	}
}

func TestPlannerKeepsCentOSSandboxPlanBlocked(t *testing.T) {
	controls := catalog.Controls(catalog.PlatformCentOSStream)
	findings := make([]assessment.Finding, 0, len(controls))
	for _, control := range controls {
		findings = append(findings, assessment.Finding{ControlID: control.ID, Title: control.Title, Status: assessment.StatusFail, Applicability: assessment.ApplicabilityApplicable, Severity: control.Severity, CurrentValue: "yes", ExpectedValue: control.ExpectedValue, Message: "fixture", Source: catalog.EffectiveSSHConfigSource, Evidence: []assessment.Evidence{{Name: control.EffectiveSettingKey, Value: "yes", Source: catalog.EffectiveSSHConfigSource}}})
	}
	plan := planner.BuildAssessmentPlan(assessment.Assessment{Platform: assessment.PlatformCentOSStream, Findings: findings})
	if plan.Status != planner.PlanStatusBlocked || len(plan.Actions) != 0 {
		t.Fatalf("CentOS plan=%+v, want BLOCKED and no actions", plan)
	}
}
