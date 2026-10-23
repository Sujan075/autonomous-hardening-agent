package privhelper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/approval"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/executor"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/planner"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/state"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const (
	testIssuer   = "https://approval.test.invalid"
	testAudience = "spiffe://test.invalid/agent/one"
	testKeyID    = "ephemeral-test-key"
)

type helperFixture struct {
	helper    *Helper
	key       *ecdsa.PrivateKey
	claims    map[string]any
	requestID string
	operation string
	plan      planner.Plan
	evidence  approval.EvidenceProvenance
	manifest  approval.RecoveryManifest
	now       time.Time
	called    atomic.Int32
	audit     *memoryAudit
}

type memoryAudit struct {
	mu     sync.Mutex
	events []AuditEvent
	failAt int
	calls  int
}

func (a *memoryAudit) Append(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.failAt == a.calls {
		return errors.New("injected durable audit failure")
	}
	a.events = append(a.events, event)
	return nil
}

func (a *memoryAudit) snapshot() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditEvent(nil), a.events...)
}

func newHelperFixture(t *testing.T, operation string) *helperFixture {
	t.Helper()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action := planner.Action{
		ActionID: SupportedAction, ControlID: "SSH-5.1.20", Title: "Disable SSH root login",
		ActionType: "set_sshd_option", CurrentValue: "yes", DesiredValue: "no",
		RiskScore: 3.5, ExecutionMode: planner.ExecutionApproval, Reason: "Root login is enabled.",
	}
	plan := planner.Plan{Status: planner.PlanStatusReady, Platform: "ubuntu-24.04.5-arm64", Actions: []planner.Action{action}}
	evidence := approval.EvidenceProvenance{
		AssessmentID: "assessment-1", TargetID: "target-1", Source: "controller-observation",
		CatalogVersion: "catalog-v1", CollectedAt: now,
		Assessment: assessment.Assessment{Platform: plan.Platform, Findings: []assessment.Finding{{
			ControlID: "SSH-5.1.20", Title: "Disable SSH root login", Status: assessment.StatusFail,
			Applicability: assessment.ApplicabilityApplicable, Severity: "high", CurrentValue: "yes",
			ExpectedValue: "no", Message: "root login enabled", Source: "test-fixture",
		}}},
	}
	manifest := approval.RecoveryManifest{
		TargetID: "target-1", AgentID: "agent-1", BindingGeneration: "generation-1", ExecutionID: "execution-1",
		Action: action,
		State: executor.ExecutionState{
			ActionID: action.ActionID, PreviousEffectiveValue: "yes", CapturedAt: now,
			File: state.FileState{Path: executor.SSHDropInPath, CapturedAt: now},
		},
	}
	verifier, err := approval.NewVerifier(approval.Config{
		Issuer: testIssuer, Audience: testAudience, AgentID: "agent-1", TargetID: "target-1",
		BindingGeneration: "generation-1", Operation: operation, PolicyVersion: "policy-v1", CatalogVersion: "catalog-v1",
		ExpectedAction: action, ExpectedPlan: plan, ExpectedEvidence: evidence, ExpectedRecoveryManifest: manifest,
		AllowedAlgorithms: []string{approval.AlgorithmES256}, TrustedKeys: map[string]*ecdsa.PublicKey{testKeyID: &key.PublicKey},
		MaxClockSkew: approval.MaxClockSkew, MaxLifetime: approval.MaxApprovalLifetime, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	audit := &memoryAudit{}
	fixture := &helperFixture{
		key: key, operation: operation, plan: plan, evidence: evidence, manifest: manifest,
		now: now, requestID: "request-1", audit: audit,
	}
	fixture.claims = fixture.makeClaims(t, verifier, action)
	store, err := NewFileReplayStore(t.TempDir() + "/replay")
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Enabled: true, Verifier: verifier, ReplayStore: store, AuditSink: audit, Operation: operation,
		Issuer: testIssuer, Audience: testAudience, AgentID: "agent-1", TargetID: "target-1",
		BindingGeneration: "generation-1", PolicyVersion: "policy-v1", CatalogVersion: "catalog-v1", Action: action,
		Plan: plan, Evidence: evidence, RecoveryManifest: manifest,
		Operate: func() (executor.ExecutionResult, error) {
			fixture.called.Add(1)
			status := "VERIFIED"
			before, after := "yes", "no"
			if operation == approval.OperationRollback {
				status = "ROLLED_BACK"
				before, after = "no", "yes"
			}
			return executor.ExecutionResult{ActionID: action.ActionID, Status: status, Before: before, After: after}, nil
		},
	}
	fixture.helper, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *helperFixture) makeClaims(t *testing.T, verifier *approval.Verifier, action planner.Action) map[string]any {
	t.Helper()
	actionDigest, err := approval.ActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": testIssuer, "aud": testAudience, "sub": "user:test-approver", "approver_id": "user:test-approver",
		"agent_id": "agent-1", "target_id": "target-1", "binding_generation": "generation-1",
		"operation": f.operation, "action_id": action.ActionID, "action_digest": actionDigest,
		"policy_version": "policy-v1", "catalog_version": "catalog-v1", "jti": f.requestID,
		"iat": f.now.Unix(), "nbf": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(),
	}
	if f.operation == approval.OperationExecute {
		planDigest, digestErr := approval.PlanBindingDigest("target-1", f.operation, "policy-v1", "catalog-v1", f.plan, f.evidence)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		evidenceDigest, digestErr := approval.EvidenceDigest(f.evidence)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		claims["plan_digest"], claims["evidence_digest"] = planDigest, evidenceDigest
	} else {
		recoveryDigest, digestErr := approval.RecoveryManifestDigest(f.manifest)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		claims["recovery_manifest_digest"] = recoveryDigest
	}
	_ = verifier // verifier is intentionally created before request signing and is trusted test configuration.
	return claims
}

func (f *helperFixture) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, testKeyID); err != nil {
		t.Fatal(err)
	}
	if err := headers.Set(jws.TypeKey, approval.TokenType); err != nil {
		t.Fatal(err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), f.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func (f *helperFixture) request(t *testing.T, token string, requestID, operation, actionID string) []byte {
	t.Helper()
	encoded, err := json.Marshal(Request{Schema: RequestSchema, RequestID: requestID, Operation: operation, ActionID: actionID, ApprovalToken: token})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (f *helperFixture) validRequest(t *testing.T) []byte {
	return f.request(t, f.sign(t, f.claims), f.requestID, f.operation, SupportedAction)
}

func TestHelperValidSignedRequestReachesOnlyInjectedFixedOperation(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	token := f.sign(t, f.claims)
	result, err := f.helper.Process(f.request(t, token, f.requestID, f.operation, SupportedAction))
	if err != nil {
		t.Fatalf("Process(): %v", err)
	}
	if result.Status != "VERIFIED" || f.called.Load() != 1 {
		t.Fatalf("result=%+v operations=%d", result, f.called.Load())
	}
	events := f.audit.snapshot()
	if len(events) != 2 || events[0].EventType != "action.started" || events[1].EventType != "action.finished" || !events[1].Verified {
		t.Fatalf("unexpected audit events: %+v", events)
	}
	for _, event := range events {
		if event.ApproverSubjectClaim != "user:test-approver" || event.TargetID != "target-1" || event.ActionID != SupportedAction || event.PolicyVersion != "policy-v1" || event.CatalogVersion != "catalog-v1" {
			t.Fatalf("audit event lacks expected safe identifiers: %+v", event)
		}
	}
	encodedAudit, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedAudit), token) {
		t.Fatal("audit event serialization exposed the approval token")
	}
	store, ok := f.helper.replay.(*FileReplayStore)
	if !ok {
		t.Fatal("fixture is not using the persistent replay store")
	}
	entries, err := os.ReadDir(store.directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("replay entries = %d, %v; want one reserved digest", len(entries), err)
	}
	record, err := os.ReadFile(store.directory + "/" + entries[0].Name())
	if err != nil || strings.Contains(string(record), token) {
		t.Fatalf("replay record read/exposure check failed: %v", err)
	}
}

func TestHelperDefaultsDisabled(t *testing.T) {
	helper, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := helper.Process([]byte(`{}`)); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled helper error = %v", err)
	}
}

func TestHelperRejectsMalformedOversizedDuplicateUnknownAndTrailingRequestsWithoutOperation(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	validToken := f.sign(t, f.claims)
	valid := f.validRequest(t)
	duplicate := strings.Replace(string(valid), `"request_id":"request-1"`, `"request_id":"request-1","request_id":"request-2"`, 1)
	if duplicate == string(valid) {
		t.Fatal("could not construct duplicate-member request fixture")
	}
	caseAliasDuplicate := strings.Replace(string(valid), `"request_id":"request-1"`, `"request_id":"request-1","Request_ID":"request-2"`, 1)
	if caseAliasDuplicate == string(valid) {
		t.Fatal("could not construct case-alias duplicate-member request fixture")
	}
	unknown := fmt.Sprintf(`{"schema":%q,"request_id":"request-1","operation":"execute","action_id":%q,"approval_token":%q,"command":"id"}`, RequestSchema, SupportedAction, validToken)
	malformed := []byte(`{"request_id":`)
	baseObject := map[string]any{
		"schema": RequestSchema, "request_id": "request-1", "operation": "execute",
		"action_id": SupportedAction, "approval_token": validToken,
	}
	tests := []struct {
		name string
		body []byte
	}{
		{name: "empty"}, {name: "malformed", body: malformed},
		{name: "oversized", body: []byte(strings.Repeat("x", MaxRequestBytes+1))},
		{name: "trailing value", body: append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{name: "unknown command", body: []byte(unknown)},
		{name: "duplicate member", body: []byte(duplicate)},
		{name: "case-insensitive duplicate member", body: []byte(caseAliasDuplicate)},
		{name: "missing fields", body: []byte(`{"request_id":"request-1"}`)},
		{name: "non-json", body: []byte("not json")},
	}
	for _, field := range []string{"executable", "target_path", "service_name", "public_key"} {
		object := make(map[string]any, len(baseObject)+1)
		for key, value := range baseObject {
			object[key] = value
		}
		object[field] = "untrusted"
		body, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, struct {
			name string
			body []byte
		}{name: "unknown " + field, body: body})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := f.helper.Process(tt.body); err == nil {
				t.Fatal("Process() accepted invalid request")
			}
			if f.called.Load() != 0 {
				t.Fatalf("rejected request invoked operation %d times", f.called.Load())
			}
		})
	}
}

func TestHelperRejectsInvalidSignaturesExpiredAndMismatchedClaimsBeforeOperation(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	mutations := map[string]func(map[string]any){
		"issuer":          func(c map[string]any) { c["iss"] = "https://other.test.invalid" },
		"audience":        func(c map[string]any) { c["aud"] = "spiffe://other/agent" },
		"agent":           func(c map[string]any) { c["agent_id"] = "agent-elsewhere" },
		"target":          func(c map[string]any) { c["target_id"] = "target-elsewhere" },
		"generation":      func(c map[string]any) { c["binding_generation"] = "generation-old" },
		"operation":       func(c map[string]any) { c["operation"] = approval.OperationRollback },
		"action":          func(c map[string]any) { c["action_id"] = "ACT-OTHER" },
		"action digest":   func(c map[string]any) { c["action_digest"] = "sha256:" + strings.Repeat("1", 64) },
		"plan digest":     func(c map[string]any) { c["plan_digest"] = "sha256:" + strings.Repeat("2", 64) },
		"evidence digest": func(c map[string]any) { c["evidence_digest"] = "sha256:" + strings.Repeat("3", 64) },
		"policy":          func(c map[string]any) { c["policy_version"] = "policy-v2" },
		"catalog":         func(c map[string]any) { c["catalog_version"] = "catalog-v2" },
		"expiry":          func(c map[string]any) { c["exp"] = f.now.Add(-time.Minute).Unix() },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			claims := cloneClaims(f.claims)
			mutate(claims)
			token := f.sign(t, claims)
			requestID := f.requestID
			if jti, ok := claims["jti"].(string); ok {
				requestID = jti
			}
			if _, err := f.helper.Process(f.request(t, token, requestID, f.operation, SupportedAction)); err == nil {
				t.Fatal("Process() accepted mismatched signed claims")
			}
		})
	}
	valid := f.sign(t, f.claims)
	parts := strings.Split(valid, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	if _, err := f.helper.Process(f.request(t, strings.Join(parts, "."), f.requestID, f.operation, SupportedAction)); err == nil {
		t.Fatal("Process() accepted altered signature")
	}
	if _, err := f.helper.Process(f.request(t, valid, f.requestID, approval.OperationRollback, SupportedAction)); err == nil {
		t.Fatal("Process() accepted request operation different from configured operation")
	}
	if _, err := f.helper.Process(f.request(t, valid, f.requestID, f.operation, "ACT-OTHER")); err == nil {
		t.Fatal("Process() accepted a different action ID")
	}
	if _, err := f.helper.Process(f.request(t, valid, "request-other", f.operation, SupportedAction)); err == nil {
		t.Fatal("Process() accepted request ID that does not equal signed JTI")
	}
	if f.called.Load() != 0 {
		t.Fatalf("rejected requests invoked operation %d times", f.called.Load())
	}
}

func TestHelperRecomputesBindingsFromConfiguredTypedContext(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	validToken := f.sign(t, f.claims)
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "action parameter",
			mutate: func(config *Config) {
				config.Action.CurrentValue = "unknown-value"
				config.Plan.Actions[0].CurrentValue = "unknown-value"
			},
		},
		{
			name: "ordered plan",
			mutate: func(config *Config) {
				other := config.Plan.Actions[0]
				other.ActionID = "ACT-OTHER"
				other.ControlID = "OTHER"
				config.Plan.Actions = append([]planner.Action{other}, config.Plan.Actions...)
			},
		},
		{
			name:   "evidence source",
			mutate: func(config *Config) { config.Evidence.Source = "replaced-source" },
		},
		{
			name: "catalog version",
			mutate: func(config *Config) {
				config.CatalogVersion = "catalog-v2"
				config.Evidence.CatalogVersion = "catalog-v2"
			},
		},
		{
			name:   "policy version",
			mutate: func(config *Config) { config.PolicyVersion = "policy-v2" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := f.plan.Actions[0]
			config := Config{
				Enabled: true, Verifier: f.helper.verifier, AuditSink: &memoryAudit{},
				Operation: approval.OperationExecute, Issuer: testIssuer, Audience: testAudience,
				AgentID: "agent-1", TargetID: "target-1", BindingGeneration: "generation-1",
				PolicyVersion: "policy-v1", CatalogVersion: "catalog-v1", Action: action,
				Plan: f.plan, Evidence: f.evidence,
				Operate: func() (executor.ExecutionResult, error) {
					f.called.Add(1)
					return executor.ExecutionResult{Status: "VERIFIED"}, nil
				},
			}
			store, err := NewFileReplayStore(t.TempDir() + "/replay")
			if err != nil {
				t.Fatal(err)
			}
			config.ReplayStore = store
			tt.mutate(&config)
			changed, err := New(config)
			if err != nil {
				t.Fatalf("New(changed trusted context): %v", err)
			}
			if _, err := changed.Process(f.request(t, validToken, f.requestID, f.operation, SupportedAction)); err == nil {
				t.Fatal("approval for different authoritative context was accepted")
			}
			if f.called.Load() != 0 {
				t.Fatal("context mismatch invoked operation")
			}
		})
	}
}

func TestHelperReplayIsAtomicAcrossConcurrencyAndStoreRecreation(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	token := f.sign(t, f.claims)
	request := f.request(t, token, f.requestID, f.operation, SupportedAction)
	const attempts = 16
	var wg sync.WaitGroup
	var success atomic.Int32
	var replay atomic.Int32
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.helper.Process(request)
			switch {
			case err == nil:
				success.Add(1)
			case errors.Is(err, ErrReplay):
				replay.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 || replay.Load() != attempts-1 || f.called.Load() != 1 {
		t.Fatalf("success=%d replay=%d operations=%d", success.Load(), replay.Load(), f.called.Load())
	}
	conflictingClaims := cloneClaims(f.claims)
	conflictingClaims["sub"] = "user:another-claimed-approver"
	conflictingClaims["approver_id"] = "user:another-claimed-approver"
	conflicting := f.request(t, f.sign(t, conflictingClaims), f.requestID, f.operation, SupportedAction)
	if _, err := f.helper.Process(conflicting); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("same JTI with different signed bytes error = %v", err)
	}
	if f.called.Load() != 1 {
		t.Fatal("conflicting retry invoked operation")
	}
}

func TestFileReplayStoreRejectsReplayConflictAndPersistsReservation(t *testing.T) {
	directory := t.TempDir() + "/journal"
	first, err := NewFileReplayStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	digest1 := "sha256:" + strings.Repeat("a", 64)
	digest2 := "sha256:" + strings.Repeat("b", 64)
	if err := first.Reserve("request-1", digest1); err != nil {
		t.Fatalf("initial reserve: %v", err)
	}
	second, err := NewFileReplayStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Reserve("request-1", digest1); !errors.Is(err, ErrReplay) {
		t.Fatalf("recreated store replay error = %v", err)
	}
	if err := second.Reserve("request-1", digest2); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("conflicting request error = %v", err)
	}
}

func TestReplayPersistenceFailureAndPreOperationAuditFailurePreventMutation(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	request := f.validRequest(t)
	file := t.TempDir() + "/not-a-directory"
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	failedStore, err := NewFileReplayStore(file + "/journal")
	if err != nil {
		t.Fatal(err)
	}
	f.helper.replay = failedStore
	if _, err := f.helper.Process(request); !errors.Is(err, ErrReplayStorage) {
		t.Fatalf("storage failure = %v", err)
	}
	if f.called.Load() != 0 {
		t.Fatal("replay persistence failure invoked operation")
	}

	f = newHelperFixture(t, approval.OperationExecute)
	f.audit.failAt = 1
	request = f.validRequest(t)
	if _, err := f.helper.Process(request); !errors.Is(err, ErrAuditBefore) {
		t.Fatalf("pre-operation audit error = %v", err)
	}
	if f.called.Load() != 0 {
		t.Fatal("pre-operation audit failure invoked operation")
	}
	if _, err := f.helper.Process(request); !errors.Is(err, ErrReplay) {
		t.Fatalf("request was not durably spent after audit failure: %v", err)
	}
}

func TestPostOperationAuditFailureIsExplicitlyIncompleteAndCannotBeRetried(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	f.audit.failAt = 2
	request := f.validRequest(t)
	result, err := f.helper.Process(request)
	if !errors.Is(err, ErrAuditAfter) || result.Status != "AUDIT_INCOMPLETE" || f.called.Load() != 1 {
		t.Fatalf("result=%+v err=%v operations=%d", result, err, f.called.Load())
	}
	if _, err := f.helper.Process(request); !errors.Is(err, ErrReplay) {
		t.Fatalf("ambiguous audited outcome was retryable: %v", err)
	}
}

func TestOperationFailureNeverReturnsSuccessAndRetainsRecoveryRequiredStatus(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	f.helper.operate = func() (executor.ExecutionResult, error) {
		f.called.Add(1)
		return executor.ExecutionResult{}, errors.New("injected verification and recovery failure")
	}
	result, err := f.helper.Process(f.validRequest(t))
	if err == nil || !errors.Is(err, ErrIncomplete) && !strings.Contains(err.Error(), "recovery status requires reconciliation") || result.Status != "RECOVERY_REQUIRED" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if events := f.audit.snapshot(); len(events) != 2 || events[1].Verified || events[1].Outcome != "recovery_required" {
		t.Fatalf("failed operation audit outcome = %+v", events)
	}
}

func TestHelperDoesNotAcceptSuccessWithoutExpectedEffectiveValue(t *testing.T) {
	f := newHelperFixture(t, approval.OperationExecute)
	f.helper.operate = func() (executor.ExecutionResult, error) {
		f.called.Add(1)
		return executor.ExecutionResult{ActionID: SupportedAction, Status: "VERIFIED", Before: "yes", After: "yes"}, nil
	}
	result, err := f.helper.Process(f.validRequest(t))
	if !errors.Is(err, ErrIncomplete) || result.Status != "INCOMPLETE" {
		t.Fatalf("result=%+v error=%v; want incomplete denial", result, err)
	}
	if events := f.audit.snapshot(); len(events) != 2 || events[1].Verified || events[1].Outcome != "incomplete" {
		t.Fatalf("unexpected audit outcome: %+v", events)
	}
}

func TestRollbackRequiresAndBindsExpectedRecoveryManifest(t *testing.T) {
	f := newHelperFixture(t, approval.OperationRollback)
	if result, err := f.helper.Process(f.validRequest(t)); err != nil || result.Status != "ROLLED_BACK" || f.called.Load() != 1 {
		t.Fatalf("valid rollback-bound test request result=%+v err=%v calls=%d", result, err, f.called.Load())
	}
	f = newHelperFixture(t, approval.OperationRollback)
	claims := cloneClaims(f.claims)
	claims["recovery_manifest_digest"] = "sha256:" + strings.Repeat("f", 64)
	if _, err := f.helper.Process(f.request(t, f.sign(t, claims), f.requestID, f.operation, SupportedAction)); err == nil {
		t.Fatal("Process() accepted changed recovery-manifest digest")
	}
	if f.called.Load() != 0 {
		t.Fatal("invalid recovery binding invoked operation")
	}
	changed := f.manifest
	changed.ExecutionID = "execution-other"
	config := Config{
		Enabled: true, Verifier: f.helper.verifier, ReplayStore: f.helper.replay, AuditSink: f.audit,
		Operate:   func() (executor.ExecutionResult, error) { return executor.ExecutionResult{}, nil },
		Operation: approval.OperationRollback, Issuer: testIssuer, Audience: testAudience,
		AgentID: "agent-1", TargetID: "target-1", BindingGeneration: "generation-1",
		PolicyVersion: "policy-v1", CatalogVersion: "catalog-v1", Action: f.manifest.Action, RecoveryManifest: changed,
	}
	changedHelper, err := New(config)
	if err != nil {
		t.Fatalf("New(changed authoritative recovery context): %v", err)
	}
	if _, err := changedHelper.Process(f.validRequest(t)); err == nil {
		t.Fatal("helper accepted approval bound to a different original execution reference")
	}
	if f.called.Load() != 0 {
		t.Fatal("approval for stale recovery context invoked operation")
	}
}

func cloneClaims(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
