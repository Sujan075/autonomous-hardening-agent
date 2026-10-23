package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/planner"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const testKeyID = "ephemeral-test-key"

func TestVerifyAcceptsValidEnvelope(t *testing.T) {
	fixture := newApprovalFixture(t)
	token := fixture.sign(t, fixture.claims())

	got, err := fixture.verifier.Verify(token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got.ApproverID != "user:approver-1" || got.JTI != "request-1" || got.TargetID != "target-1" {
		t.Fatalf("Verify() returned unexpected claims: %+v", got)
	}
}

func TestVerifyRejectsMalformedAndInvalidSignatures(t *testing.T) {
	fixture := newApprovalFixture(t)
	valid := fixture.sign(t, fixture.claims())
	malformedSignedJSON := fixture.signRaw(t, []byte(`{"iss":`))
	parts := strings.Split(valid, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	invalidSignature := strings.Join(parts, ".")
	oversized := strings.Repeat("x", MaxTokenBytes+1)

	for name, token := range map[string]string{
		"empty":                 "",
		"malformed":             "not-a-jwt",
		"extra compact segment": valid + ".extra",
		"empty segments":        "..",
		"invalid base64url":     "@@@@.@@@@.@@@@",
		"malformed signed JSON": malformedSignedJSON,
		"invalid signature":     invalidSignature,
		"oversized":             oversized,
		"surrounding space":     " " + valid,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.verifier.Verify(token); err == nil {
				t.Fatal("Verify() accepted invalid input")
			}
		})
	}
}

func TestVerifyRejectsUnknownKeyAndDisallowedAlgorithm(t *testing.T) {
	fixture := newApprovalFixture(t)
	unknownKey := fixture.signWith(t, fixture.privateKey, "not-trusted", mustJSON(t, fixture.claims()))
	if _, err := fixture.verifier.Verify(unknownKey); err == nil {
		t.Fatal("Verify() accepted an unknown kid")
	}

	for _, headerName := range []string{"jwk", "jku", "x5u"} {
		t.Run("untrusted key header "+headerName, func(t *testing.T) {
			headers := jws.NewHeaders()
			_ = headers.Set(jws.KeyIDKey, testKeyID)
			_ = headers.Set(jws.TypeKey, TokenType)
			switch headerName {
			case "jwk":
				publicJWK, err := jwk.Import[jwk.Key](&fixture.privateKey.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := headers.Set(headerName, publicJWK); err != nil {
					t.Fatal(err)
				}
			case "jku", "x5u":
				_ = headers.Set(headerName, "https://attacker.invalid/key-material")
			}
			payload := mustJSON(t, fixture.claims())
			signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), fixture.privateKey, jws.WithProtectedHeaders(headers)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.verifier.Verify(string(signed)); err == nil {
				t.Fatalf("Verify() accepted untrusted %s header", headerName)
			}
		})
	}

	claims, err := json.Marshal(fixture.claims())
	if err != nil {
		t.Fatal(err)
	}
	protected := jws.NewHeaders()
	_ = protected.Set(jws.KeyIDKey, testKeyID)
	_ = protected.Set(jws.TypeKey, TokenType)
	hs256, err := jws.Sign(claims, jws.WithKey(jwa.HS256(), []byte("ephemeral-only"), jws.WithProtectedHeaders(protected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.verifier.Verify(string(hs256)); err == nil {
		t.Fatal("Verify() accepted a disallowed algorithm")
	}

	// A compact JWS with an explicit alg=none header and empty signature must
	// also be rejected before any claims can be treated as trusted.
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"none","kid":%q,"typ":%q}`, testKeyID, TokenType)))
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	if _, err := fixture.verifier.Verify(encodedHeader + "." + encodedClaims + "."); err == nil {
		t.Fatal("Verify() accepted alg=none")
	}
}

func TestVerifyRejectsMissingConflictingAndNonStringClaims(t *testing.T) {
	fixture := newApprovalFixture(t)
	base := fixture.claims()
	for _, claim := range []string{"iss", "aud", "sub", "approver_id", "agent_id", "target_id", "binding_generation", "operation", "action_id", "action_digest", "plan_digest", "evidence_digest", "policy_version", "catalog_version", "jti", "iat", "nbf", "exp"} {
		t.Run("missing "+claim, func(t *testing.T) {
			claims := cloneClaims(base)
			delete(claims, claim)
			if _, err := fixture.verifier.Verify(fixture.sign(t, claims)); err == nil {
				t.Fatalf("Verify() accepted missing %q", claim)
			}
		})
	}

	duplicate := strings.Replace(string(mustJSON(t, base)), `"iss":"trusted-issuer"`, `"iss":"trusted-issuer","iss":"attacker"`, 1)
	if _, err := fixture.verifier.Verify(fixture.signRaw(t, []byte(duplicate))); err == nil {
		t.Fatal("Verify() accepted conflicting duplicate claims")
	}

	wrongType := cloneClaims(base)
	wrongType["approver_id"] = 42
	if _, err := fixture.verifier.Verify(fixture.sign(t, wrongType)); err == nil {
		t.Fatal("Verify() accepted a non-string approver identity")
	}

	conflictingSubject := cloneClaims(base)
	conflictingSubject["sub"] = "user:someone-else"
	if _, err := fixture.verifier.Verify(fixture.sign(t, conflictingSubject)); err == nil {
		t.Fatal("Verify() accepted conflicting subject and approver identity")
	}

	unexpectedClaim := cloneClaims(base)
	unexpectedClaim["admin"] = true
	if _, err := fixture.verifier.Verify(fixture.sign(t, unexpectedClaim)); err == nil {
		t.Fatal("Verify() accepted an unrecognized private claim")
	}

	wrongAudienceShape := cloneClaims(base)
	wrongAudienceShape["aud"] = []string{"agent-audience", "other-audience"}
	if _, err := fixture.verifier.Verify(fixture.sign(t, wrongAudienceShape)); err == nil {
		t.Fatal("Verify() accepted a conflicting audience list")
	}
}

func TestVerifyRejectsContextMismatches(t *testing.T) {
	fixture := newApprovalFixture(t)
	mutations := map[string]func(map[string]any){
		"issuer":          func(c map[string]any) { c["iss"] = "other-issuer" },
		"audience":        func(c map[string]any) { c["aud"] = "other-audience" },
		"agent":           func(c map[string]any) { c["agent_id"] = "other-agent" },
		"target":          func(c map[string]any) { c["target_id"] = "other-target" },
		"binding":         func(c map[string]any) { c["binding_generation"] = "generation-2" },
		"operation":       func(c map[string]any) { c["operation"] = OperationRollback },
		"action":          func(c map[string]any) { c["action_id"] = "other-action" },
		"action digest":   func(c map[string]any) { c["action_digest"] = "sha256:wrong" },
		"plan digest":     func(c map[string]any) { c["plan_digest"] = "sha256:" + strings.Repeat("3", 64) },
		"evidence digest": func(c map[string]any) { c["evidence_digest"] = "sha256:" + strings.Repeat("4", 64) },
		"policy version":  func(c map[string]any) { c["policy_version"] = "policy-v2" },
		"catalog version": func(c map[string]any) { c["catalog_version"] = "catalog-v2" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			claims := cloneClaims(fixture.claims())
			mutate(claims)
			if _, err := fixture.verifier.Verify(fixture.sign(t, claims)); err == nil {
				t.Fatal("Verify() accepted mismatched approval context")
			}
		})
	}
}

func TestVerifyRollbackRequiresExpectedRecoveryManifestBinding(t *testing.T) {
	fixture := newApprovalFixture(t)
	config := Config{
		Issuer: "trusted-issuer", Audience: "agent-audience", AgentID: "agent-1", TargetID: "target-1", BindingGeneration: "generation-1",
		Operation: OperationRollback, PolicyVersion: "policy-v1", CatalogVersion: "catalog-v1", ExpectedAction: testAction(),
		ExpectedRecoveryManifest: testRecoveryManifest(),
		AllowedAlgorithms:        []string{AlgorithmES256}, TrustedKeys: map[string]*ecdsa.PublicKey{testKeyID: &fixture.privateKey.PublicKey},
		MaxClockSkew: MaxClockSkew, MaxLifetime: MaxApprovalLifetime, Now: func() time.Time { return fixture.now },
	}
	verifier, err := NewVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	claims := fixture.claims()
	claims["operation"] = OperationRollback
	delete(claims, "plan_digest")
	delete(claims, "evidence_digest")
	claims["recovery_manifest_digest"], err = RecoveryManifestDigest(config.ExpectedRecoveryManifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(fixture.sign(t, claims)); err != nil {
		t.Fatalf("Verify() rejected valid rollback binding: %v", err)
	}

	claims["recovery_manifest_digest"] = "sha256:" + strings.Repeat("6", 64)
	if _, err := verifier.Verify(fixture.sign(t, claims)); err == nil {
		t.Fatal("Verify() accepted a mismatched recovery manifest")
	}
	delete(claims, "recovery_manifest_digest")
	if _, err := verifier.Verify(fixture.sign(t, claims)); err == nil {
		t.Fatal("Verify() accepted a missing recovery manifest digest")
	}
}

func TestVerifyEnforcesTimeWindowAndClockSkew(t *testing.T) {
	fixture := newApprovalFixture(t)
	base := fixture.claims()
	cases := []struct {
		name   string
		update func(map[string]any)
		valid  bool
	}{
		{name: "expired beyond skew", update: func(c map[string]any) { c["exp"] = fixture.now.Add(-MaxClockSkew - time.Second).Unix() }},
		{name: "expiry plus skew exact boundary", update: func(c map[string]any) {
			c["iat"] = fixture.now.Add(-2 * time.Minute).Unix()
			c["nbf"] = fixture.now.Add(-time.Minute).Unix()
			c["exp"] = fixture.now.Add(-MaxClockSkew).Unix()
		}},
		{name: "future issued beyond skew", update: func(c map[string]any) {
			c["iat"] = fixture.now.Add(MaxClockSkew + time.Second).Unix()
			c["nbf"] = c["iat"]
		}},
		{name: "future not-before beyond skew", update: func(c map[string]any) { c["nbf"] = fixture.now.Add(MaxClockSkew + time.Second).Unix() }},
		{name: "not-before precedes issued-at", update: func(c map[string]any) { c["nbf"] = fixture.now.Add(-time.Second).Unix() }},
		{name: "expiry does not follow not-before", update: func(c map[string]any) { c["exp"] = c["nbf"] }},
		{name: "lifetime too long", update: func(c map[string]any) { c["exp"] = fixture.now.Add(MaxApprovalLifetime + time.Second).Unix() }},
		{name: "expiry just inside skew", update: func(c map[string]any) {
			c["iat"] = fixture.now.Add(-2 * time.Minute).Unix()
			c["nbf"] = fixture.now.Add(-time.Minute).Unix()
			c["exp"] = fixture.now.Add(-MaxClockSkew + time.Second).Unix()
		}, valid: true},
		{name: "issued at skew boundary", update: func(c map[string]any) { c["iat"] = fixture.now.Add(MaxClockSkew).Unix(); c["nbf"] = c["iat"] }, valid: true},
		{name: "not-before skew boundary", update: func(c map[string]any) { c["nbf"] = fixture.now.Add(MaxClockSkew).Unix() }, valid: true},
		{name: "maximum lifetime", update: func(c map[string]any) { c["exp"] = fixture.now.Add(MaxApprovalLifetime).Unix() }, valid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := cloneClaims(base)
			tc.update(claims)
			_, err := fixture.verifier.Verify(fixture.sign(t, claims))
			if tc.valid && err != nil {
				t.Fatalf("Verify() rejected boundary case: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("Verify() accepted invalid time window")
			}
		})
	}
}

func TestActionDigestIsDeterministicAndBindsEveryActionField(t *testing.T) {
	action := testAction()
	original, err := ActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ActionDigest(action)
	if err != nil || repeated != original {
		t.Fatalf("digest is not deterministic: %q, %v", repeated, err)
	}

	mutations := map[string]func(*planner.Action){
		"action ID":      func(a *planner.Action) { a.ActionID += "-changed" },
		"control ID":     func(a *planner.Action) { a.ControlID += "-changed" },
		"title":          func(a *planner.Action) { a.Title += " changed" },
		"action type":    func(a *planner.Action) { a.ActionType += "-changed" },
		"current value":  func(a *planner.Action) { a.CurrentValue += " changed" },
		"desired value":  func(a *planner.Action) { a.DesiredValue += " changed" },
		"risk score":     func(a *planner.Action) { a.RiskScore += 0.25 },
		"execution mode": func(a *planner.Action) { a.ExecutionMode = planner.ExecutionManual },
		"reason":         func(a *planner.Action) { a.Reason += " changed" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := action
			mutate(&changed)
			got, err := ActionDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == original {
				t.Fatal("digest did not change after action mutation")
			}
		})
	}
}

func TestActionDigestMatchesSharedGoldenVector(t *testing.T) {
	vectorBytes, err := os.ReadFile("testdata/action_digest_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Version   string         `json:"version"`
		Action    planner.Action `json:"action"`
		Canonical string         `json:"canonical_hex"`
		SHA256    string         `json:"sha256"`
	}
	if err := json.Unmarshal(vectorBytes, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Version != ActionDigestVersion {
		t.Fatalf("vector version = %q, want %q", vector.Version, ActionDigestVersion)
	}
	canonical, err := canonicalActionBytes(vector.Action)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(canonical); got != vector.Canonical {
		t.Fatalf("canonical bytes = %q, want %q", got, vector.Canonical)
	}
	got, err := ActionDigest(vector.Action)
	if err != nil {
		t.Fatal(err)
	}
	if got != "sha256:"+vector.SHA256 {
		t.Fatalf("ActionDigest() = %q, want sha256:%s", got, vector.SHA256)
	}
}

func TestNewVerifierRejectsNonAllowlistedAlgorithmsAndInvalidTrustConfig(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := Config{
		Issuer: "trusted-issuer", Audience: "agent-audience", AgentID: "agent-1", TargetID: "target-1", BindingGeneration: "generation-1", Operation: OperationExecute,
		PolicyVersion: "policy-v1", CatalogVersion: "catalog-v1", ExpectedAction: testAction(),
		ExpectedPlan: testPlan(), ExpectedEvidence: testEvidence(),
		AllowedAlgorithms: []string{AlgorithmES256}, TrustedKeys: map[string]*ecdsa.PublicKey{testKeyID: &privateKey.PublicKey},
		MaxClockSkew: MaxClockSkew, MaxLifetime: MaxApprovalLifetime, Now: time.Now,
	}
	for name, algorithms := range map[string][]string{
		"none": {"none"}, "HS256": {"HS256"}, "empty": {}, "mixed": {AlgorithmES256, "HS256"},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			config.AllowedAlgorithms = algorithms
			if _, err := NewVerifier(config); err == nil {
				t.Fatal("NewVerifier() accepted an invalid algorithm allowlist")
			}
		})
	}

	emptyKeys := base
	emptyKeys.TrustedKeys = nil
	if _, err := NewVerifier(emptyKeys); err == nil {
		t.Fatal("NewVerifier() accepted an empty trust key set")
	}

	tooMuchSkew := base
	tooMuchSkew.MaxClockSkew = MaxClockSkew + time.Nanosecond
	if _, err := NewVerifier(tooMuchSkew); err == nil {
		t.Fatal("NewVerifier() accepted clock skew above its hard maximum")
	}
	tooLongLifetime := base
	tooLongLifetime.MaxLifetime = MaxApprovalLifetime + time.Nanosecond
	if _, err := NewVerifier(tooLongLifetime); err == nil {
		t.Fatal("NewVerifier() accepted a lifetime above its hard maximum")
	}
	badOperation := base
	badOperation.Operation = "arbitrary"
	if _, err := NewVerifier(badOperation); err == nil {
		t.Fatal("NewVerifier() accepted an unsupported operation")
	}

	actionOutsidePlan := base
	actionOutsidePlan.ExpectedAction.ActionID = "ACT-NOT-IN-PLAN"
	if _, err := NewVerifier(actionOutsidePlan); err == nil {
		t.Fatal("NewVerifier() accepted an expected action outside the bound plan")
	}
	blockedPlan := base
	blockedPlan.ExpectedPlan.Status = planner.PlanStatusBlocked
	if _, err := NewVerifier(blockedPlan); err == nil {
		t.Fatal("NewVerifier() accepted a blocked plan for execution")
	}

	badCurveKey := base
	otherCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badCurveKey.TrustedKeys = map[string]*ecdsa.PublicKey{testKeyID: &otherCurve.PublicKey}
	if _, err := NewVerifier(badCurveKey); err == nil {
		t.Fatal("NewVerifier() accepted a non-P-256 trusted key")
	}
}

type approvalFixture struct {
	privateKey *ecdsa.PrivateKey
	verifier   *Verifier
	now        time.Time
}

func newApprovalFixture(t *testing.T) approvalFixture {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(Config{
		Issuer:            "trusted-issuer",
		Audience:          "agent-audience",
		AgentID:           "agent-1",
		TargetID:          "target-1",
		BindingGeneration: "generation-1",
		Operation:         OperationExecute,
		PolicyVersion:     "policy-v1",
		CatalogVersion:    "catalog-v1",
		ExpectedAction:    testAction(),
		ExpectedPlan:      testPlan(),
		ExpectedEvidence:  testEvidence(),
		AllowedAlgorithms: []string{AlgorithmES256},
		TrustedKeys:       map[string]*ecdsa.PublicKey{testKeyID: &privateKey.PublicKey},
		MaxClockSkew:      MaxClockSkew,
		MaxLifetime:       MaxApprovalLifetime,
		Now:               func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return approvalFixture{privateKey: privateKey, verifier: verifier, now: now}
}

func (f approvalFixture) claims() map[string]any {
	digest, _ := ActionDigest(testAction())
	planDigest, _ := PlanBindingDigest("target-1", OperationExecute, "policy-v1", "catalog-v1", testPlan(), testEvidence())
	evidenceDigest, _ := EvidenceDigest(testEvidence())
	return map[string]any{
		"iss": "trusted-issuer", "aud": "agent-audience", "sub": "user:approver-1",
		"approver_id": "user:approver-1", "agent_id": "agent-1", "target_id": "target-1", "binding_generation": "generation-1", "operation": OperationExecute,
		"action_id": testAction().ActionID, "action_digest": digest,
		"plan_digest": planDigest, "evidence_digest": evidenceDigest,
		"policy_version": "policy-v1", "catalog_version": "catalog-v1", "jti": "request-1",
		"iat": f.now.Unix(), "nbf": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(),
	}
}

func (f approvalFixture) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return f.signRaw(t, mustJSON(t, claims))
}

func (f approvalFixture) signRaw(t *testing.T, payload []byte) string {
	t.Helper()
	return f.signWith(t, f.privateKey, testKeyID, payload)
}

func (f approvalFixture) signWith(t *testing.T, key *ecdsa.PrivateKey, keyID string, payload []byte) string {
	t.Helper()
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		t.Fatal(err)
	}
	if err := headers.Set(jws.TypeKey, TokenType); err != nil {
		t.Fatal(err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func cloneClaims(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func testAction() planner.Action {
	return planner.Action{
		ActionID:      "ACT-SSH-5.1.20",
		ControlID:     "SSH-5.1.20",
		Title:         "Disable SSH root login",
		ActionType:    "set_sshd_option",
		CurrentValue:  "yes",
		DesiredValue:  "no",
		RiskScore:     3.5,
		ExecutionMode: planner.ExecutionApproval,
		Reason:        "Root login is currently enabled.",
	}
}
