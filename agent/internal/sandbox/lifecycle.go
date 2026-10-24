// Package sandbox composes the real assessment-plan binding, ES256 verifier,
// replay store, privileged-helper contract, and temporary OpenSSH fixture.
// Its test-only issuer and local filesystem target can never name a managed VM.
package sandbox

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/approval"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/catalog"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/executor"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/planner"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/privhelper"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const (
	testIssuer       = "onlybrains-sandbox-test-issuer"
	testAudience     = "onlybrains-sandbox-agent"
	testAgentID      = "sandbox-agent-local"
	testPolicy       = "sandbox-policy-v1"
	testCatalog      = "ubuntu-ssh-catalog-v1"
	testKeyID        = "ephemeral-sandbox-key"
	approvalLifetime = 90 * time.Second
)

type State string

const (
	Initialized        State = "INITIALIZED"
	Discovered         State = "DISCOVERED"
	Assessed           State = "ASSESSED"
	Planned            State = "PLANNED"
	AwaitingApproval   State = "AWAITING_APPROVAL"
	Approved           State = "APPROVED"
	Executed           State = "EXECUTED"
	Verified           State = "VERIFIED"
	Blocked            State = "BLOCKED"
	Denied             State = "DENIED"
	Failed             State = "FAILED"
	VerificationFailed State = "VERIFICATION_FAILED"
	RollbackPending    State = "ROLLBACK_PENDING"
	RolledBack         State = "ROLLED_BACK"
	RecoveryFailed     State = "RECOVERY_FAILED"
)

type LifecycleEvent struct {
	State      State     `json:"state"`
	OccurredAt time.Time `json:"occurred_at"`
	Detail     string    `json:"detail,omitempty"`
}

type Verification struct {
	Status   string `json:"status"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Source   string `json:"source"`
}

type RunResult struct {
	Schema             string                    `json:"schema"`
	RunID              string                    `json:"run_id"`
	TargetID           string                    `json:"target_id"`
	Platform           string                    `json:"platform"`
	Scenario           string                    `json:"scenario"`
	Status             string                    `json:"status"`
	SandboxOnly        bool                      `json:"sandbox_only"`
	TestOnlyTrust      bool                      `json:"test_only_trust"`
	LiveTargetModified bool                      `json:"live_target_modified"`
	PolicyVersion      string                    `json:"policy_version"`
	CatalogVersion     string                    `json:"catalog_version"`
	Findings           []assessment.Finding      `json:"findings"`
	Plan               planner.Plan              `json:"plan"`
	Approval           map[string]any            `json:"approval"`
	Execution          *executor.ExecutionResult `json:"execution,omitempty"`
	Verification       *Verification             `json:"verification,omitempty"`
	Recovery           map[string]any            `json:"recovery,omitempty"`
	Lifecycle          []LifecycleEvent          `json:"lifecycle"`
	AuditEvents        []privhelper.AuditEvent   `json:"audit_events"`
	Error              string                    `json:"error,omitempty"`
}

type machine struct {
	state  State
	events []LifecycleEvent
}

func (m *machine) advance(next State, detail string) error {
	allowed := map[State]map[State]bool{
		"":                 {Initialized: true},
		Initialized:        {Discovered: true, Failed: true},
		Discovered:         {Assessed: true, Failed: true},
		Assessed:           {Planned: true, Failed: true},
		Planned:            {AwaitingApproval: true, Verified: true, Blocked: true},
		AwaitingApproval:   {Approved: true, Denied: true, Blocked: true},
		Approved:           {Executed: true, Failed: true},
		Failed:             {RecoveryFailed: true},
		Executed:           {Verified: true, VerificationFailed: true, Failed: true},
		Verified:           {RollbackPending: true},
		VerificationFailed: {RollbackPending: true, RecoveryFailed: true},
		RollbackPending:    {RolledBack: true, RecoveryFailed: true},
	}
	if !allowed[m.state][next] {
		return fmt.Errorf("invalid lifecycle transition %q -> %q", m.state, next)
	}
	m.state = next
	m.events = append(m.events, LifecycleEvent{State: next, OccurredAt: time.Now().UTC(), Detail: detail})
	return nil
}

// Run executes one of three fixed, local-only fixtures. The fixture and test
// signing key are deleted from the host temp directory before returning.
func Run(scenario string) (RunResult, error) {
	if scenario != "roundtrip" && scenario != "compliant" && scenario != "precedence-conflict" {
		return RunResult{}, errors.New("scenario must be roundtrip, compliant, or precedence-conflict")
	}
	fixtureScenario := executor.SSHFixtureNonCompliant
	if scenario == "compliant" {
		fixtureScenario = executor.SSHFixtureCompliant
	} else if scenario == "precedence-conflict" {
		fixtureScenario = executor.SSHFixturePrecedenceConflict
	}
	fixture, err := executor.NewTemporarySSHConfigSandbox(fixtureScenario)
	if err != nil {
		return RunResult{}, err
	}
	defer fixture.Close()

	runID, err := randomID()
	if err != nil {
		return RunResult{}, err
	}
	targetID := "sandbox-local-" + runID
	result := RunResult{
		Schema: "aha-remediation-sandbox-run/v1", RunID: runID, TargetID: targetID,
		Platform: "ubuntu-sandbox-fixture", Scenario: scenario, SandboxOnly: true,
		TestOnlyTrust: true, LiveTargetModified: false, PolicyVersion: testPolicy,
		CatalogVersion: testCatalog, Approval: map[string]any{"status": "NOT_ISSUED", "issuer": testIssuer, "subject": "sandbox-operator-test-only"},
	}
	m := &machine{}
	if err := m.advance(Initialized, "Created an isolated temporary OpenSSH configuration tree"); err != nil {
		return result, err
	}
	effective, err := fixture.EffectiveConfig()
	if err != nil {
		_ = m.advance(Failed, "OpenSSH discovery failed")
		return result, err
	}
	if err := m.advance(Discovered, "sshd -T read the generated configuration; no network listener was started"); err != nil {
		return result, err
	}
	findings, err := findingsFromEffectiveConfig(effective)
	if err != nil {
		_ = m.advance(Failed, "Assessment evidence was incomplete")
		return result, err
	}
	result.Findings = findings
	if err := m.advance(Assessed, "Four Ubuntu SSH controls were evaluated from temporary sshd -T output"); err != nil {
		return result, err
	}
	result.Plan = planner.BuildAssessmentPlan(assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings})
	if err := m.advance(Planned, "The existing planner built a fixed-action plan from the assessment"); err != nil {
		return result, err
	}
	if result.Plan.Status == planner.PlanStatusBlocked {
		result.Status = string(Blocked)
		_ = m.advance(Blocked, "Planner rejected incomplete, unsupported, or uncertain evidence")
		result.Lifecycle = m.events
		return result, nil
	}
	if len(result.Plan.Actions) == 0 {
		result.Status = "COMPLIANT"
		_ = m.advance(Verified, "All four observed controls already match the project-defined baseline; no action was issued")
		result.Lifecycle = m.events
		return result, nil
	}
	if err := m.advance(AwaitingApproval, "A test-only signed approval is required by the privileged-helper contract"); err != nil {
		return result, err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return result, err
	}
	policyPlan := result.Plan
	evidence := approval.EvidenceProvenance{
		AssessmentID: "assessment-" + runID, TargetID: targetID,
		Source: "temporary-sshd-fixture", CatalogVersion: testCatalog,
		CollectedAt: time.Now().UTC(), Assessment: assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings},
	}
	action := result.Plan.Actions[0]
	operationAuditDir, err := os.MkdirTemp("", "aha-sandbox-audit-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(operationAuditDir)
	audit := &fileAuditSink{path: filepath.Join(operationAuditDir, "privileged-helper-audit.jsonl")}
	executeHelper, err := newHelper(privateKey, audit, operationAuditDir, fixture.Apply, approval.OperationExecute, targetID, runID, action, policyPlan, evidence, approval.RecoveryManifest{})
	if err != nil {
		return result, err
	}
	requestID := "execute-" + runID
	claims, err := approvalClaims(privateKey, requestID, approval.OperationExecute, targetID, runID, action, policyPlan, evidence, approval.RecoveryManifest{}, time.Now().UTC())
	if err != nil {
		return result, err
	}
	token, err := signClaims(privateKey, claims)
	if err != nil {
		return result, err
	}
	request, _ := json.Marshal(privhelper.Request{Schema: privhelper.RequestSchema, RequestID: requestID, Operation: approval.OperationExecute, ActionID: action.ActionID, ApprovalToken: token})
	if err := m.advance(Approved, "ES256 token validated against sandbox target, action, plan, evidence, policy, and catalog"); err != nil {
		return result, err
	}
	result.Approval = map[string]any{"status": "APPROVED", "issuer": testIssuer, "subject": "sandbox-operator-test-only", "key_id": testKeyID, "token_persisted": false, "valid_for_seconds": int(approvalLifetime.Seconds())}
	execution, operationErr := executeHelper.Process(request)
	// The snapshot path is deliberately not exported: its file is deleted by
	// fixture.Close before the caller receives this result.
	execution.StatePath = ""
	result.Execution = &execution
	if operationErr != nil {
		if scenario != "precedence-conflict" || !strings.Contains(operationErr.Error(), "automatic rollback succeeded and effective state was verified") {
			result.Status, result.Error = string(RecoveryFailed), operationErr.Error()
			_ = m.advance(Failed, "The fixed helper/executor path returned an unexpected error")
			_ = m.advance(RecoveryFailed, "Recovery could not be verified")
			result.Lifecycle = m.events
			result.AuditEvents = audit.snapshot
			return result, nil
		}
		if err := m.advance(Executed, "The fixed action reached SSH effective-value verification"); err != nil {
			return result, err
		}
		if err := m.advance(VerificationFailed, "Independent effective SSH value did not reach the requested value"); err != nil {
			return result, err
		}
		if err := m.advance(RollbackPending, "Executor automatically restored its captured file state"); err != nil {
			return result, err
		}
		observed, verifyErr := fixture.EffectivePermitRootLogin()
		if verifyErr != nil || observed != "yes" {
			result.Status = string(RecoveryFailed)
			result.Error = fmt.Sprintf("recovery verification failed: observed=%q error=%v", observed, verifyErr)
			_ = m.advance(RecoveryFailed, result.Error)
		} else {
			result.Status = string(RolledBack)
			result.Verification = &Verification{Status: "FAILED_AS_EXPECTED", Expected: "no", Observed: observed, Source: "independent sshd -T -f temporary-config"}
			result.Recovery = map[string]any{"status": "ROLLED_BACK", "restored_effective_value": observed, "verified_independently": true, "mode": "executor automatic recovery"}
			_ = m.advance(RolledBack, "Recovery restored and independently verified the original effective value")
		}
		result.AuditEvents = audit.snapshot
		result.Lifecycle = m.events
		return result, nil
	}
	if err := m.advance(Executed, "Fixed SSH action completed through the privileged-helper operation callback"); err != nil {
		return result, err
	}
	observed, err := fixture.EffectivePermitRootLogin()
	if err != nil || observed != "no" {
		result.Status = string(VerificationFailed)
		_ = m.advance(VerificationFailed, "A second independent sshd -T check did not confirm the desired value")
		_ = m.advance(RollbackPending, "Initiating fixed rollback path")
		rollback, rollbackErr := fixture.Rollback()
		result.Recovery = map[string]any{"status": rollback.Status, "error": errorString(rollbackErr)}
		if rollbackErr != nil {
			_ = m.advance(RecoveryFailed, "Rollback or its verification failed")
		} else {
			_ = m.advance(RolledBack, "Rollback succeeded")
		}
		result.Error = fmt.Sprintf("independent verification failed: value=%q error=%v", observed, err)
		result.Lifecycle, result.AuditEvents = m.events, audit.snapshot
		return result, nil
	}
	result.Verification = &Verification{Status: "VERIFIED", Expected: "no", Observed: observed, Source: "independent sshd -T -f temporary-config"}
	if err := m.advance(Verified, "Independent sshd -T confirmed PermitRootLogin=no"); err != nil {
		return result, err
	}
	state, err := fixture.RecoveryState()
	if err != nil {
		return result, err
	}
	manifest := approval.RecoveryManifest{TargetID: targetID, AgentID: testAgentID, BindingGeneration: "sandbox-generation-" + runID, ExecutionID: "execution-" + runID, Action: action, State: state}
	if err := m.advance(RollbackPending, "Starting a separately signed rollback bound to the exact captured recovery manifest"); err != nil {
		return result, err
	}
	rollbackHelper, err := newHelper(privateKey, audit, operationAuditDir, fixture.Rollback, approval.OperationRollback, targetID, runID, action, planner.Plan{}, approval.EvidenceProvenance{}, manifest)
	if err != nil {
		return result, err
	}
	rollbackID := "rollback-" + runID
	rollbackClaims, err := approvalClaims(privateKey, rollbackID, approval.OperationRollback, targetID, runID, action, planner.Plan{}, approval.EvidenceProvenance{}, manifest, time.Now().UTC())
	if err != nil {
		return result, err
	}
	rollbackToken, err := signClaims(privateKey, rollbackClaims)
	if err != nil {
		return result, err
	}
	rollbackRequest, _ := json.Marshal(privhelper.Request{Schema: privhelper.RequestSchema, RequestID: rollbackID, Operation: approval.OperationRollback, ActionID: action.ActionID, ApprovalToken: rollbackToken})
	rollbackResult, rollbackErr := rollbackHelper.Process(rollbackRequest)
	if rollbackErr != nil {
		result.Status = string(RecoveryFailed)
		result.Recovery = map[string]any{"status": "RECOVERY_FAILED", "error": rollbackErr.Error()}
		_ = m.advance(RecoveryFailed, "Signed rollback failed or could not be durably audited")
	} else {
		finalValue, verifyErr := fixture.EffectivePermitRootLogin()
		if verifyErr != nil || finalValue != state.PreviousEffectiveValue {
			result.Status = string(RecoveryFailed)
			result.Recovery = map[string]any{"status": "RECOVERY_FAILED", "error": errorString(verifyErr), "restored_effective_value": finalValue}
			_ = m.advance(RecoveryFailed, "Independent post-rollback effective-value check failed")
		} else {
			result.Status = string(RolledBack)
			result.Recovery = map[string]any{"status": rollbackResult.Status, "restored_effective_value": finalValue, "verified_independently": true, "mode": "separately approved rollback"}
			_ = m.advance(RolledBack, "Signed rollback restored and independently verified the exact prior effective value")
		}
	}
	result.AuditEvents = audit.snapshot
	result.Lifecycle = m.events
	return result, nil
}

func findingsFromEffectiveConfig(output string) ([]assessment.Finding, error) {
	values := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			values[strings.ToLower(fields[0])] = strings.ToLower(fields[1])
		}
	}
	controls := catalog.Controls(catalog.PlatformUbuntu)
	findings := make([]assessment.Finding, 0, len(controls))
	for _, control := range controls {
		current, ok := values[strings.ToLower(control.EffectiveSettingKey)]
		if !ok {
			return nil, fmt.Errorf("sshd -T omitted required %s evidence", control.EffectiveSettingKey)
		}
		status := assessment.StatusPass
		message := "Effective SSH configuration matches the project-defined expected value"
		if current != strings.ToLower(control.ExpectedValue) {
			status, message = assessment.StatusFail, "Effective SSH configuration differs from the project-defined expected value"
		}
		finding := assessment.Finding{ControlID: control.ID, Title: control.Title, Status: status, Applicability: assessment.ApplicabilityApplicable, Severity: control.Severity, CurrentValue: current, ExpectedValue: control.ExpectedValue, Message: message, Source: catalog.EffectiveSSHConfigSource}
		for _, expected := range control.Evidence {
			finding.Evidence = append(finding.Evidence, assessment.Evidence{Name: expected.SettingKey, Value: current, Source: expected.Source})
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

type fileAuditSink struct {
	path     string
	snapshot []privhelper.AuditEvent
}

func (s *fileAuditSink) Append(event privhelper.AuditEvent) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err == nil {
		_, err = file.Write(append(data, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	s.snapshot = append(s.snapshot, event)
	return nil
}

func newHelper(key *ecdsa.PrivateKey, audit privhelper.AuditSink, dir string, operate privhelper.Operation, operation, targetID, runID string, action planner.Action, plan planner.Plan, evidence approval.EvidenceProvenance, manifest approval.RecoveryManifest) (*privhelper.Helper, error) {
	binding := "sandbox-generation-" + runID
	config := approval.Config{Issuer: testIssuer, Audience: testAudience, AgentID: testAgentID, TargetID: targetID, BindingGeneration: binding, Operation: operation, PolicyVersion: testPolicy, CatalogVersion: testCatalog, ExpectedAction: action, ExpectedPlan: plan, ExpectedEvidence: evidence, ExpectedRecoveryManifest: manifest, AllowedAlgorithms: []string{approval.AlgorithmES256}, TrustedKeys: map[string]*ecdsa.PublicKey{testKeyID: &key.PublicKey}, MaxClockSkew: approval.MaxClockSkew, MaxLifetime: approval.MaxApprovalLifetime, Now: func() time.Time { return time.Now().UTC() }}
	verifier, err := approval.NewVerifier(config)
	if err != nil {
		return nil, err
	}
	replay, err := privhelper.NewFileReplayStore(filepath.Join(dir, "replay", operation))
	if err != nil {
		return nil, err
	}
	return privhelper.New(privhelper.Config{Enabled: true, Verifier: verifier, ReplayStore: replay, AuditSink: audit, Operate: operate, Operation: operation, Issuer: testIssuer, Audience: testAudience, AgentID: testAgentID, TargetID: targetID, BindingGeneration: binding, PolicyVersion: testPolicy, CatalogVersion: testCatalog, Action: action, Plan: plan, Evidence: evidence, RecoveryManifest: manifest})
}

func approvalClaims(key *ecdsa.PrivateKey, requestID, operation, targetID, runID string, action planner.Action, plan planner.Plan, evidence approval.EvidenceProvenance, manifest approval.RecoveryManifest, now time.Time) (map[string]any, error) {
	actionDigest, err := approval.ActionDigest(action)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "sandbox-operator-test-only", "approver_id": "sandbox-operator-test-only", "agent_id": testAgentID, "target_id": targetID, "binding_generation": "sandbox-generation-" + runID, "operation": operation, "action_id": action.ActionID, "action_digest": actionDigest, "policy_version": testPolicy, "catalog_version": testCatalog, "jti": requestID, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(approvalLifetime).Unix()}
	if operation == approval.OperationExecute {
		claims["plan_digest"], err = approval.PlanBindingDigest(targetID, operation, testPolicy, testCatalog, plan, evidence)
		if err != nil {
			return nil, err
		}
		claims["evidence_digest"], err = approval.EvidenceDigest(evidence)
		if err != nil {
			return nil, err
		}
	} else {
		claims["recovery_manifest_digest"], err = approval.RecoveryManifestDigest(manifest)
		if err != nil {
			return nil, err
		}
	}
	return claims, nil
}

func signClaims(key *ecdsa.PrivateKey, claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, testKeyID); err != nil {
		return "", err
	}
	if err := headers.Set(jws.TypeKey, approval.TokenType); err != nil {
		return "", err
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)))
	return string(signed), err
}

func randomID() (string, error) {
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", id[:]), nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ReadJSONLines is used by the CLI to expose only the helper's audited outcome
// records before its isolated temporary storage is cleaned up.
func ReadJSONLines(path string) ([]json.RawMessage, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []json.RawMessage
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		lines = append(lines, append(json.RawMessage(nil), scanner.Bytes()...))
	}
	return lines, scanner.Err()
}
