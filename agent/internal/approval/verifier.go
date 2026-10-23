// Package approval verifies signed approval envelopes. It does not issue
// approvals, authenticate human users, store replay state, or execute actions.
package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/planner"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

const (
	// AlgorithmES256 is the only approval-signing algorithm accepted by this
	// verifier. It is asymmetric, requires a P-256 key, and uses SHA-256.
	AlgorithmES256    = "ES256"
	TokenType         = "application/approval+jwt"
	OperationExecute  = "execute"
	OperationRollback = "rollback"

	ActionDigestVersion = "planner-action/v1"
	MaxTokenBytes       = 16 * 1024
	MaxClockSkew        = 30 * time.Second
	MaxApprovalLifetime = 5 * time.Minute
)

var (
	ErrInvalidApproval = errors.New("approval envelope rejected")
	ErrInvalidConfig   = errors.New("invalid approval verifier configuration")
)

// Config is supplied by the trusted caller. TrustedKeys contains only
// out-of-band approval-issuer public keys indexed by their trusted key IDs;
// keys or key URLs inside an approval are never trusted.
type Config struct {
	Issuer                   string
	Audience                 string
	AgentID                  string
	TargetID                 string
	BindingGeneration        string
	Operation                string
	PolicyVersion            string
	CatalogVersion           string
	ExpectedAction           planner.Action
	ExpectedPlan             planner.Plan
	ExpectedEvidence         EvidenceProvenance
	ExpectedRecoveryManifest RecoveryManifest
	AllowedAlgorithms        []string
	TrustedKeys              map[string]*ecdsa.PublicKey
	MaxClockSkew             time.Duration
	MaxLifetime              time.Duration
	Now                      func() time.Time
}

// VerifiedApproval contains claims that passed cryptographic and contextual
// validation. ApproverID is only a claim attested by the trusted issuer; this
// package does not authenticate the human or authorize the approver's role.
// JTI is returned for a future replay store; this package does not consume it.
type VerifiedApproval struct {
	Issuer                 string
	Audience               string
	ApproverID             string
	AgentID                string
	TargetID               string
	BindingGeneration      string
	Operation              string
	ActionID               string
	ActionDigest           string
	PlanDigest             string
	EvidenceDigest         string
	RecoveryManifestDigest string
	PolicyVersion          string
	CatalogVersion         string
	JTI                    string
	IssuedAt               time.Time
	NotBefore              time.Time
	ExpiresAt              time.Time
	KeyID                  string
}

type Verifier struct {
	issuer                 string
	audience               string
	agentID                string
	targetID               string
	bindingGeneration      string
	operation              string
	policyVersion          string
	catalogVersion         string
	actionID               string
	actionDigest           string
	planDigest             string
	evidenceDigest         string
	recoveryManifestDigest string
	keys                   map[string]*ecdsa.PublicKey
	maxClockSkew           time.Duration
	maxLifetime            time.Duration
	now                    func() time.Time
}

// NewVerifier validates and copies the explicit trust configuration. The
// configured algorithm allowlist must contain exactly ES256.
func NewVerifier(config Config) (*Verifier, error) {
	if strings.TrimSpace(config.Issuer) == "" ||
		strings.TrimSpace(config.Audience) == "" ||
		strings.TrimSpace(config.AgentID) == "" ||
		strings.TrimSpace(config.TargetID) == "" ||
		strings.TrimSpace(config.BindingGeneration) == "" ||
		(config.Operation != OperationExecute && config.Operation != OperationRollback) ||
		strings.TrimSpace(config.PolicyVersion) == "" ||
		strings.TrimSpace(config.CatalogVersion) == "" ||
		config.Now == nil ||
		config.MaxClockSkew < 0 || config.MaxClockSkew > MaxClockSkew ||
		config.MaxLifetime <= 0 || config.MaxLifetime > MaxApprovalLifetime ||
		len(config.AllowedAlgorithms) != 1 || config.AllowedAlgorithms[0] != AlgorithmES256 {
		return nil, ErrInvalidConfig
	}
	if err := validateExpectedAction(config.ExpectedAction); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if len(config.TrustedKeys) == 0 {
		return nil, ErrInvalidConfig
	}

	keys := make(map[string]*ecdsa.PublicKey, len(config.TrustedKeys))
	for keyID, key := range config.TrustedKeys {
		if strings.TrimSpace(keyID) == "" || key == nil || key.Curve == nil ||
			key.Curve.Params().Name != elliptic.P256().Params().Name ||
			key.X == nil || key.Y == nil || !elliptic.P256().IsOnCurve(key.X, key.Y) {
			return nil, ErrInvalidConfig
		}
		keys[keyID] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).Set(key.X),
			Y:     new(big.Int).Set(key.Y),
		}
	}

	digest, err := ActionDigest(config.ExpectedAction)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid expected action", ErrInvalidConfig)
	}
	var expectedPlanDigest, expectedEvidenceDigest, expectedRecoveryManifestDigest string
	if config.Operation == OperationExecute {
		if config.ExpectedPlan.Status != planner.PlanStatusReady {
			return nil, ErrInvalidConfig
		}
		expectedEvidenceDigest, err = EvidenceDigest(config.ExpectedEvidence)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expected assessment evidence", ErrInvalidConfig)
		}
		expectedPlanDigest, err = PlanBindingDigest(config.TargetID, config.Operation, config.PolicyVersion, config.CatalogVersion, config.ExpectedPlan, config.ExpectedEvidence)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expected plan binding", ErrInvalidConfig)
		}
		foundAction := false
		for _, action := range config.ExpectedPlan.Actions {
			planActionDigest, digestErr := ActionDigest(action)
			if digestErr == nil && planActionDigest == digest {
				foundAction = true
				break
			}
		}
		if !foundAction {
			return nil, ErrInvalidConfig
		}
	} else {
		manifest := config.ExpectedRecoveryManifest
		if manifest.TargetID != config.TargetID || manifest.AgentID != config.AgentID ||
			manifest.BindingGeneration != config.BindingGeneration || manifest.Action.ActionID != config.ExpectedAction.ActionID {
			return nil, ErrInvalidConfig
		}
		expectedRecoveryManifestDigest, err = RecoveryManifestDigest(manifest)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expected recovery manifest", ErrInvalidConfig)
		}
		manifestActionDigest, digestErr := ActionDigest(manifest.Action)
		if digestErr != nil || manifestActionDigest != digest {
			return nil, ErrInvalidConfig
		}
	}

	return &Verifier{
		issuer:                 config.Issuer,
		audience:               config.Audience,
		agentID:                config.AgentID,
		targetID:               config.TargetID,
		bindingGeneration:      config.BindingGeneration,
		operation:              config.Operation,
		policyVersion:          config.PolicyVersion,
		catalogVersion:         config.CatalogVersion,
		actionID:               config.ExpectedAction.ActionID,
		actionDigest:           digest,
		planDigest:             expectedPlanDigest,
		evidenceDigest:         expectedEvidenceDigest,
		recoveryManifestDigest: expectedRecoveryManifestDigest,
		keys:                   keys,
		maxClockSkew:           config.MaxClockSkew,
		maxLifetime:            config.MaxLifetime,
		now:                    config.Now,
	}, nil
}

// ActionDigest returns the versioned SHA-256 digest of every planner.Action
// field. Its bytes use the language-neutral encoding documented in
// docs/SECURITY_MODEL.md and tested by the shared Go/Python golden vector.
func ActionDigest(action planner.Action) (string, error) {
	canonical, err := canonicalActionBytes(action)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func canonicalActionBytes(action planner.Action) ([]byte, error) {
	if err := validateExpectedAction(action); err != nil {
		return nil, err
	}

	var canonical bytes.Buffer
	canonical.WriteString("AHA-PLANNER-ACTION-DIGEST\x00")
	canonical.WriteString(ActionDigestVersion)
	canonical.WriteByte(0)
	for _, value := range []string{
		action.ActionID,
		action.ControlID,
		action.Title,
		action.ActionType,
		action.CurrentValue,
		action.DesiredValue,
	} {
		if err := writeCanonicalString(&canonical, value); err != nil {
			return nil, err
		}
	}
	var riskScore [8]byte
	binary.BigEndian.PutUint64(riskScore[:], math.Float64bits(action.RiskScore))
	canonical.Write(riskScore[:])
	if err := writeCanonicalString(&canonical, string(action.ExecutionMode)); err != nil {
		return nil, err
	}
	if err := writeCanonicalString(&canonical, action.Reason); err != nil {
		return nil, err
	}
	return canonical.Bytes(), nil
}

func writeCanonicalString(output *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) || uint64(len(value)) > uint64(^uint32(0)) {
		return errors.New("action string is not representable in digest format")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output.Write(length[:])
	output.WriteString(value)
	return nil
}

func validateExpectedAction(action planner.Action) error {
	if strings.TrimSpace(action.ActionID) == "" ||
		strings.TrimSpace(action.ControlID) == "" ||
		strings.TrimSpace(action.Title) == "" ||
		strings.TrimSpace(action.ActionType) == "" ||
		strings.TrimSpace(action.DesiredValue) == "" ||
		strings.TrimSpace(string(action.ExecutionMode)) == "" ||
		strings.TrimSpace(action.Reason) == "" ||
		math.IsNaN(action.RiskScore) || math.IsInf(action.RiskScore, 0) || action.RiskScore < 0 {
		return errors.New("action fields are incomplete or invalid")
	}
	return nil
}

// Verify validates a compact, single-signature ES256 approval JWT. The caller
// must still authorize the authenticated requester, persist/consume JTI in a
// durable replay store, and write audit events before any execution.
func (v *Verifier) Verify(raw string) (*VerifiedApproval, error) {
	if v == nil || len(raw) == 0 || len(raw) > MaxTokenBytes ||
		strings.TrimSpace(raw) != raw || strings.Count(raw, ".") != 2 {
		return nil, ErrInvalidApproval
	}

	message, err := jws.Parse([]byte(raw))
	if err != nil || len(message.Signatures()) != 1 {
		return nil, ErrInvalidApproval
	}
	signature := message.Signatures()[0]
	headers := signature.ProtectedHeaders()
	if headers == nil || signature.PublicHeaders() != nil {
		return nil, ErrInvalidApproval
	}
	if len(headers.Keys()) != 3 {
		return nil, ErrInvalidApproval
	}
	for _, name := range headers.Keys() {
		if name != jws.AlgorithmKey && name != jws.KeyIDKey && name != jws.TypeKey {
			return nil, ErrInvalidApproval
		}
	}
	algorithm, hasAlgorithm := headers.Algorithm()
	keyID, hasKeyID := headers.KeyID()
	tokenType, hasType := headers.Type()
	if !hasAlgorithm || algorithm.String() != AlgorithmES256 ||
		!hasKeyID || strings.TrimSpace(keyID) == "" ||
		!hasType || tokenType != TokenType {
		return nil, ErrInvalidApproval
	}
	key, ok := v.keys[keyID]
	if !ok {
		return nil, ErrInvalidApproval
	}

	parsed, err := jwt.Parse([]byte(raw),
		jwt.WithKey(jwa.ES256(), key),
		jwt.WithStrictStringClaims(true),
		jwt.WithValidate(false),
	)
	if err != nil {
		return nil, ErrInvalidApproval
	}
	if !hasOnlyExpectedClaims(parsed) {
		return nil, ErrInvalidApproval
	}

	issuer, ok := parsed.Issuer()
	if !ok || issuer != v.issuer {
		return nil, ErrInvalidApproval
	}
	audiences, ok := parsed.Audience()
	if !ok || len(audiences) != 1 || audiences[0] != v.audience {
		return nil, ErrInvalidApproval
	}
	approverID, ok := stringClaim(parsed, "approver_id")
	if !ok {
		return nil, ErrInvalidApproval
	}
	subject, hasSubject := parsed.Subject()
	if !hasSubject || subject != approverID {
		return nil, ErrInvalidApproval
	}
	agentID, ok := stringClaim(parsed, "agent_id")
	if !ok || agentID != v.agentID {
		return nil, ErrInvalidApproval
	}
	targetID, ok := stringClaim(parsed, "target_id")
	if !ok || targetID != v.targetID {
		return nil, ErrInvalidApproval
	}
	bindingGeneration, ok := stringClaim(parsed, "binding_generation")
	if !ok || bindingGeneration != v.bindingGeneration {
		return nil, ErrInvalidApproval
	}
	operation, ok := stringClaim(parsed, "operation")
	if !ok || operation != v.operation {
		return nil, ErrInvalidApproval
	}
	actionID, ok := stringClaim(parsed, "action_id")
	if !ok || actionID != v.actionID {
		return nil, ErrInvalidApproval
	}
	actionDigest, ok := stringClaim(parsed, "action_digest")
	if !ok || actionDigest != v.actionDigest {
		return nil, ErrInvalidApproval
	}
	var planDigest, evidenceDigest, recoveryManifestDigest string
	if v.operation == OperationExecute {
		planDigest, ok = stringClaim(parsed, "plan_digest")
		if !ok || planDigest != v.planDigest {
			return nil, ErrInvalidApproval
		}
		evidenceDigest, ok = stringClaim(parsed, "evidence_digest")
		if !ok || evidenceDigest != v.evidenceDigest {
			return nil, ErrInvalidApproval
		}
		if _, exists := parsed.Field("recovery_manifest_digest"); exists {
			return nil, ErrInvalidApproval
		}
	} else {
		recoveryManifestDigest, ok = stringClaim(parsed, "recovery_manifest_digest")
		if !ok || recoveryManifestDigest != v.recoveryManifestDigest {
			return nil, ErrInvalidApproval
		}
		if _, exists := parsed.Field("plan_digest"); exists {
			return nil, ErrInvalidApproval
		}
		if _, exists := parsed.Field("evidence_digest"); exists {
			return nil, ErrInvalidApproval
		}
	}
	policyVersion, ok := stringClaim(parsed, "policy_version")
	if !ok || policyVersion != v.policyVersion {
		return nil, ErrInvalidApproval
	}
	catalogVersion, ok := stringClaim(parsed, "catalog_version")
	if !ok || catalogVersion != v.catalogVersion {
		return nil, ErrInvalidApproval
	}
	jti, ok := parsed.JwtID()
	if !ok || strings.TrimSpace(jti) == "" {
		return nil, ErrInvalidApproval
	}
	issuedAt, hasIssuedAt := parsed.IssuedAt()
	notBefore, hasNotBefore := parsed.NotBefore()
	expiresAt, hasExpiresAt := parsed.Expiration()
	if !hasIssuedAt || !hasNotBefore || !hasExpiresAt || !validTimes(issuedAt, notBefore, expiresAt, v.now(), v.maxClockSkew, v.maxLifetime) {
		return nil, ErrInvalidApproval
	}

	return &VerifiedApproval{
		Issuer:                 issuer,
		Audience:               audiences[0],
		ApproverID:             approverID,
		AgentID:                agentID,
		TargetID:               targetID,
		BindingGeneration:      bindingGeneration,
		Operation:              operation,
		ActionID:               actionID,
		ActionDigest:           actionDigest,
		PlanDigest:             planDigest,
		EvidenceDigest:         evidenceDigest,
		RecoveryManifestDigest: recoveryManifestDigest,
		PolicyVersion:          policyVersion,
		CatalogVersion:         catalogVersion,
		JTI:                    jti,
		IssuedAt:               issuedAt,
		NotBefore:              notBefore,
		ExpiresAt:              expiresAt,
		KeyID:                  keyID,
	}, nil
}

func stringClaim(token jwt.Token, name string) (string, bool) {
	value, ok := token.Field(name)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok && strings.TrimSpace(text) != ""
}

func hasOnlyExpectedClaims(token jwt.Token) bool {
	allowed := map[string]struct{}{
		"iss": {}, "aud": {}, "sub": {}, "jti": {}, "iat": {}, "nbf": {}, "exp": {},
		"approver_id": {}, "agent_id": {}, "target_id": {}, "action_id": {},
		"binding_generation": {}, "operation": {}, "action_digest": {}, "plan_digest": {}, "evidence_digest": {}, "recovery_manifest_digest": {}, "policy_version": {}, "catalog_version": {},
	}
	for _, name := range token.Keys() {
		if _, ok := allowed[name]; !ok {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == strings.TrimPrefix(value, "sha256:")
}

func validTimes(issuedAt, notBefore, expiresAt, now time.Time, skew, maxLifetime time.Duration) bool {
	if issuedAt.IsZero() || notBefore.IsZero() || expiresAt.IsZero() || now.IsZero() ||
		issuedAt.After(now.Add(skew)) || notBefore.After(now.Add(skew)) ||
		notBefore.Before(issuedAt) || !expiresAt.After(notBefore) ||
		expiresAt.Sub(issuedAt) > maxLifetime {
		return false
	}
	return now.Before(expiresAt.Add(skew))
}
