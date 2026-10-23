// Package privhelper contains an isolated, feature-off foundation for the
// fixed Ubuntu SSH action. It is not an HTTP handler or a root helper binary.
package privhelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/approval"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/executor"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/planner"
)

const (
	MaxRequestBytes = 20 << 10
	MaxRequestID    = 128
	SupportedAction = executor.ActionSSHRootLogin
	RequestSchema   = "agent-privileged-request/v1"
)

var (
	ErrDisabled       = errors.New("privileged helper is disabled")
	ErrRequest        = errors.New("privileged helper request rejected")
	ErrReplay         = errors.New("approval request was already reserved")
	ErrReplayConflict = errors.New("request ID is already reserved for different approval bytes")
	ErrAuditBefore    = errors.New("pre-operation audit was not durably acknowledged")
	ErrAuditAfter     = errors.New("operation outcome could not be durably audited")
	ErrIncomplete     = errors.New("operation did not reach a verified terminal state")
)

// Request fields are all untrusted. The request deliberately contains no
// target, agent, command, path, key, plan, evidence or recovery-state input.
type Request struct {
	Schema        string `json:"schema"`
	RequestID     string `json:"request_id"`
	Operation     string `json:"operation"`
	ActionID      string `json:"action_id"`
	ApprovalToken string `json:"approval_token"`
}

// AuditEvent contains identifiers/digests only. ApproverSubjectClaim is a claim
// signed by the configured issuer, not proof that the human or role was
// independently authenticated here. Append must return nil only after durable
// persistence has been acknowledged by its implementation.
type AuditEvent struct {
	OccurredAt             time.Time
	EventType              string
	RequestID              string
	Issuer                 string
	ApproverSubjectClaim   string
	AgentID                string
	TargetID               string
	BindingGeneration      string
	Operation              string
	ActionID               string
	ActionDigest           string
	PolicyVersion          string
	CatalogVersion         string
	PlanDigest             string
	EvidenceDigest         string
	RecoveryManifestDigest string
	Outcome                string
	Verified               bool
}

type AuditSink interface {
	Append(AuditEvent) error
}

// ReplayStore reserves a JTI and request-content digest durably and atomically.
// A reservation is never cleared by this package, including after interruption.
type ReplayStore interface {
	Reserve(jti, requestDigest string) error
}

type Operation func() (executor.ExecutionResult, error)

type Config struct {
	// Enabled must be explicitly true. There is no startup wiring in this batch.
	Enabled     bool
	Verifier    *approval.Verifier
	ReplayStore ReplayStore
	AuditSink   AuditSink
	Operate     Operation

	Operation         string
	Issuer            string
	Audience          string
	AgentID           string
	TargetID          string
	BindingGeneration string
	PolicyVersion     string
	CatalogVersion    string
	Action            planner.Action
	Plan              planner.Plan
	Evidence          approval.EvidenceProvenance
	RecoveryManifest  approval.RecoveryManifest
}

type Helper struct {
	enabled  bool
	verifier *approval.Verifier
	replay   ReplayStore
	audit    AuditSink
	operate  Operation
	expected expectedContext
}

type expectedContext struct {
	operation              string
	issuer                 string
	audience               string
	agentID                string
	targetID               string
	bindingGeneration      string
	policyVersion          string
	catalogVersion         string
	actionID               string
	actionDigest           string
	planDigest             string
	evidenceDigest         string
	recoveryManifestDigest string
	recoveryEffectiveValue string
}

// New constructs a helper. A disabled helper may be created with zero-value
// configuration and will reject every request. Enabling requires all trust
// dependencies and typed expected data supplied by a future trusted caller.
func New(config Config) (*Helper, error) {
	helper := &Helper{enabled: config.Enabled}
	if !config.Enabled {
		return helper, nil
	}
	if config.Verifier == nil || config.ReplayStore == nil || config.AuditSink == nil || config.Operate == nil {
		return nil, errors.New("enabled helper requires verifier, durable replay store, audit sink, and fixed operation")
	}
	for _, item := range []struct{ value, name string }{
		{config.Issuer, "issuer"}, {config.Audience, "audience"}, {config.AgentID, "agent ID"},
		{config.TargetID, "target ID"}, {config.BindingGeneration, "binding generation"},
		{config.PolicyVersion, "policy version"}, {config.CatalogVersion, "catalog version"},
	} {
		if strings.TrimSpace(item.value) == "" || len(item.value) > 512 {
			return nil, fmt.Errorf("enabled helper requires a valid %s", item.name)
		}
	}
	if config.Operation != approval.OperationExecute && config.Operation != approval.OperationRollback {
		return nil, errors.New("helper operation is unsupported")
	}
	if config.Action.ActionID != SupportedAction || config.Action.ControlID != "SSH-5.1.20" ||
		config.Action.ActionType != "set_sshd_option" || config.Action.DesiredValue != "no" {
		return nil, errors.New("helper action is not the fixed Ubuntu SSH root-login action")
	}
	actionDigest, err := approval.ActionDigest(config.Action)
	if err != nil {
		return nil, fmt.Errorf("helper action is invalid: %w", err)
	}
	expected := expectedContext{
		operation: config.Operation, issuer: config.Issuer, audience: config.Audience,
		agentID: config.AgentID, targetID: config.TargetID, bindingGeneration: config.BindingGeneration,
		policyVersion: config.PolicyVersion, catalogVersion: config.CatalogVersion,
		actionID: config.Action.ActionID, actionDigest: actionDigest,
	}
	if config.Operation == approval.OperationExecute {
		if config.Plan.Status != planner.PlanStatusReady {
			return nil, errors.New("execute helper requires a READY expected plan")
		}
		evidenceDigest, digestErr := approval.EvidenceDigest(config.Evidence)
		if digestErr != nil {
			return nil, fmt.Errorf("expected assessment evidence is invalid: %w", digestErr)
		}
		planDigest, digestErr := approval.PlanBindingDigest(config.TargetID, config.Operation, config.PolicyVersion, config.CatalogVersion, config.Plan, config.Evidence)
		if digestErr != nil {
			return nil, fmt.Errorf("expected plan binding is invalid: %w", digestErr)
		}
		found := false
		for _, action := range config.Plan.Actions {
			candidate, candidateErr := approval.ActionDigest(action)
			if candidateErr == nil && candidate == actionDigest {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("fixed action is absent from the expected plan")
		}
		expected.planDigest = planDigest
		expected.evidenceDigest = evidenceDigest
	} else {
		manifest := config.RecoveryManifest
		if manifest.TargetID != config.TargetID || manifest.AgentID != config.AgentID ||
			manifest.BindingGeneration != config.BindingGeneration || manifest.Action.ActionID != config.Action.ActionID {
			return nil, errors.New("expected recovery manifest does not match helper context")
		}
		manifestActionDigest, digestErr := approval.ActionDigest(manifest.Action)
		if digestErr != nil || manifestActionDigest != actionDigest {
			return nil, errors.New("expected recovery manifest action does not match helper action")
		}
		recoveryDigest, digestErr := approval.RecoveryManifestDigest(manifest)
		if digestErr != nil {
			return nil, fmt.Errorf("expected recovery manifest is invalid: %w", digestErr)
		}
		expected.recoveryManifestDigest = recoveryDigest
		expected.recoveryEffectiveValue = manifest.State.PreviousEffectiveValue
	}
	return &Helper{
		enabled: true, verifier: config.Verifier, replay: config.ReplayStore,
		audit: config.AuditSink, operate: config.Operate, expected: expected,
	}, nil
}

// Process consumes one strict JSON request. All authoritative context is
// recomputed from Config; request-supplied context is rejected as unknown.
func (h *Helper) Process(raw []byte) (executor.ExecutionResult, error) {
	if h == nil || !h.enabled {
		return executor.ExecutionResult{}, ErrDisabled
	}
	if len(raw) == 0 || len(raw) > MaxRequestBytes {
		return executor.ExecutionResult{}, ErrRequest
	}
	var request Request
	if err := decodeStrict(raw, &request); err != nil {
		return executor.ExecutionResult{}, fmt.Errorf("%w: malformed request", ErrRequest)
	}
	if request.Schema != RequestSchema || !validRequestID(request.RequestID) || request.Operation != h.expected.operation ||
		request.ActionID != h.expected.actionID || strings.TrimSpace(request.ApprovalToken) == "" {
		return executor.ExecutionResult{}, ErrRequest
	}
	verified, err := h.verifier.Verify(request.ApprovalToken)
	if err != nil {
		return executor.ExecutionResult{}, ErrRequest
	}
	if err := h.checkVerified(verified, request); err != nil {
		return executor.ExecutionResult{}, ErrRequest
	}
	tokenHash := sha256.Sum256([]byte(request.ApprovalToken))
	requestDigest := "sha256:" + hex.EncodeToString(tokenHash[:])
	if err := h.replay.Reserve(verified.JTI, requestDigest); err != nil {
		return executor.ExecutionResult{}, err
	}
	baseEvent := h.auditEvent(verified)
	baseEvent.EventType = "action.started"
	baseEvent.Outcome = "reserved"
	if err := h.audit.Append(baseEvent); err != nil {
		return executor.ExecutionResult{}, fmt.Errorf("%w: %v", ErrAuditBefore, err)
	}

	result, operationErr := h.operate()
	completed := operationErr == nil && h.successResult(result)
	outcome := result.Status
	if operationErr != nil {
		outcome = "recovery_required"
	} else if !completed {
		outcome = "incomplete"
	}
	finishEvent := h.auditEvent(verified)
	finishEvent.EventType = "action.finished"
	finishEvent.Outcome = outcome
	finishEvent.Verified = completed
	auditErr := h.audit.Append(finishEvent)
	if operationErr != nil {
		result.Status = "RECOVERY_REQUIRED"
		if auditErr != nil {
			return result, errors.Join(fmt.Errorf("operation failed; recovery status requires reconciliation: %w", operationErr), fmt.Errorf("%w: %v", ErrAuditAfter, auditErr))
		}
		return result, fmt.Errorf("operation failed; recovery status requires reconciliation: %w", operationErr)
	}
	if auditErr != nil {
		result.Status = "AUDIT_INCOMPLETE"
		result.Message = "operation result was not durably audited; reconcile before retry"
		return result, fmt.Errorf("%w: %v", ErrAuditAfter, auditErr)
	}
	if !completed {
		result.Status = "INCOMPLETE"
		return result, ErrIncomplete
	}
	return result, nil
}

func (h *Helper) checkVerified(v *approval.VerifiedApproval, request Request) error {
	if v == nil {
		return ErrRequest
	}
	if v.Issuer != h.expected.issuer || v.Audience != h.expected.audience ||
		v.AgentID != h.expected.agentID || v.TargetID != h.expected.targetID ||
		v.BindingGeneration != h.expected.bindingGeneration || v.Operation != h.expected.operation ||
		v.ActionID != h.expected.actionID || v.ActionDigest != h.expected.actionDigest ||
		v.PolicyVersion != h.expected.policyVersion || v.CatalogVersion != h.expected.catalogVersion ||
		v.JTI != request.RequestID || strings.TrimSpace(v.ApproverID) == "" {
		return ErrRequest
	}
	if h.expected.operation == approval.OperationExecute {
		if v.PlanDigest != h.expected.planDigest || v.EvidenceDigest != h.expected.evidenceDigest || v.RecoveryManifestDigest != "" {
			return ErrRequest
		}
	} else if v.RecoveryManifestDigest != h.expected.recoveryManifestDigest || v.PlanDigest != "" || v.EvidenceDigest != "" {
		return ErrRequest
	}
	return nil
}

func (h *Helper) auditEvent(v *approval.VerifiedApproval) AuditEvent {
	return AuditEvent{
		OccurredAt: time.Now().UTC(),
		RequestID:  v.JTI, Issuer: v.Issuer, ApproverSubjectClaim: v.ApproverID,
		AgentID: v.AgentID, TargetID: v.TargetID, BindingGeneration: v.BindingGeneration,
		Operation: v.Operation, ActionID: v.ActionID, ActionDigest: v.ActionDigest,
		PolicyVersion: v.PolicyVersion, CatalogVersion: v.CatalogVersion,
		PlanDigest: v.PlanDigest, EvidenceDigest: v.EvidenceDigest,
		RecoveryManifestDigest: v.RecoveryManifestDigest,
	}
}

func (h *Helper) successResult(result executor.ExecutionResult) bool {
	if result.ActionID != h.expected.actionID {
		return false
	}
	if h.expected.operation == approval.OperationExecute {
		if result.Status == "VERIFIED" {
			return result.After == "no"
		}
		return result.Status == "ALREADY_COMPLIANT" && result.Before == "no" && result.After == "no"
	}
	return result.Status == "ROLLED_BACK" && result.After == h.expected.recoveryEffectiveValue
}

func validRequestID(value string) bool {
	if value == "" || len(value) > MaxRequestID || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func decodeStrict(raw []byte, target any) error {
	if err := rejectDuplicateMembers(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func rejectDuplicateMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var consume func() error
	consume = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				for existing := range seen {
					// encoding/json also matches struct fields case-insensitively.
					// Treat aliases as duplicates so two spellings cannot override
					// the same typed request field.
					if strings.EqualFold(existing, key) {
						return errors.New("duplicate JSON member")
					}
				}
				seen[key] = struct{}{}
				if err := consume(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			for decoder.More() {
				if err := consume(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := consume(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}
