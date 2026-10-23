package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/executor"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/planner"
)

const (
	PlanBindingVersion     = "plan-binding/v1"
	EvidenceBindingVersion = "assessment-evidence/v1"
	RecoveryBindingVersion = "recovery-manifest/v1"
	MaxBindingBytes        = 4 << 20
	MaxBindingStringBytes  = 1 << 20
	MaxBindingItems        = 4096
)

// EvidenceProvenance supplies immutable provenance absent from the current
// assessment.Assessment wire type. Values must come from the trusted
// assessment workflow, not from an approval token or display name.
type EvidenceProvenance struct {
	AssessmentID   string
	TargetID       string
	Source         string
	CatalogVersion string
	CollectedAt    time.Time
	Assessment     assessment.Assessment
}

// RecoveryManifest binds the executor's exact captured recovery state to the
// original execution and the intended target/action. ExecutionID must be a
// stable reference resolved from authoritative execution records by callers.
type RecoveryManifest struct {
	TargetID          string
	AgentID           string
	BindingGeneration string
	ExecutionID       string
	Action            planner.Action
	State             executor.ExecutionState
}

// EvidenceDigest computes a language-neutral digest over the evidence
// provenance envelope and every field in the ordered assessment payload.
func EvidenceDigest(provenance EvidenceProvenance) (string, error) {
	canonical, err := canonicalEvidenceBytes(provenance)
	if err != nil {
		return "", err
	}
	return digestCanonical(canonical), nil
}

// PlanBindingDigest binds target, operation, policy/catalog versions, the
// complete ordered plan, and the digest of its assessment provenance.
func PlanBindingDigest(targetID, operation, policyVersion, catalogVersion string, plan planner.Plan, evidence EvidenceProvenance) (string, error) {
	canonical, err := canonicalPlanBindingBytes(targetID, operation, policyVersion, catalogVersion, plan, evidence)
	if err != nil {
		return "", err
	}
	return digestCanonical(canonical), nil
}

func canonicalPlanBindingBytes(targetID, operation, policyVersion, catalogVersion string, plan planner.Plan, evidence EvidenceProvenance) ([]byte, error) {
	if strings.TrimSpace(targetID) == "" || targetID != evidence.TargetID ||
		(operation != OperationExecute && operation != OperationRollback) ||
		strings.TrimSpace(policyVersion) == "" || strings.TrimSpace(catalogVersion) == "" || catalogVersion != evidence.CatalogVersion ||
		strings.TrimSpace(plan.Platform) == "" || plan.Platform != evidence.Assessment.Platform ||
		(plan.Status != planner.PlanStatusReady && plan.Status != planner.PlanStatusBlocked) || len(plan.Actions) > MaxBindingItems {
		return nil, errors.New("plan binding context is incomplete or inconsistent")
	}
	evidenceDigest, err := EvidenceDigest(evidence)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("AHA-PLAN-BINDING\x00")
	out.WriteString(PlanBindingVersion)
	out.WriteByte(0)
	for _, value := range []string{targetID, operation, policyVersion, catalogVersion, string(plan.Status), plan.Platform} {
		if err := writeBindingString(&out, value); err != nil {
			return nil, err
		}
	}
	if err := writeBindingDigest(&out, evidenceDigest); err != nil {
		return nil, err
	}
	if err := writeBindingCount(&out, len(plan.Actions)); err != nil {
		return nil, err
	}
	for _, action := range plan.Actions {
		if err := validateBindingAction(action); err != nil {
			return nil, err
		}
		digest, err := ActionDigest(action)
		if err != nil {
			return nil, fmt.Errorf("invalid plan action: %w", err)
		}
		if err := writeBindingDigest(&out, digest); err != nil {
			return nil, err
		}
	}
	if out.Len() > MaxBindingBytes {
		return nil, errors.New("plan binding exceeds maximum canonical size")
	}
	return out.Bytes(), nil
}

// RecoveryManifestDigest binds exact recovery state. It validates the
// executor snapshot's content hash before accepting it as a manifest.
func RecoveryManifestDigest(manifest RecoveryManifest) (string, error) {
	canonical, err := canonicalRecoveryManifestBytes(manifest)
	if err != nil {
		return "", err
	}
	return digestCanonical(canonical), nil
}

func canonicalRecoveryManifestBytes(manifest RecoveryManifest) ([]byte, error) {
	state := manifest.State
	file := state.File
	if strings.TrimSpace(manifest.TargetID) == "" || strings.TrimSpace(manifest.AgentID) == "" ||
		strings.TrimSpace(manifest.BindingGeneration) == "" || strings.TrimSpace(manifest.ExecutionID) == "" ||
		state.ActionID != manifest.Action.ActionID || strings.TrimSpace(file.Path) == "" ||
		state.CapturedAt.IsZero() || file.CapturedAt.IsZero() || strings.TrimSpace(state.PreviousEffectiveValue) == "" ||
		len(file.Content) > MaxBindingBytes {
		return nil, errors.New("recovery manifest is incomplete")
	}
	actionDigest, err := ActionDigest(manifest.Action)
	if err != nil {
		return nil, err
	}
	var fileDigest []byte
	if file.Exists {
		if file.Mode&^uint32(0777) != 0 {
			return nil, errors.New("recovery file mode is invalid")
		}
		actual := sha256.Sum256(file.Content)
		if file.ContentSHA != hex.EncodeToString(actual[:]) {
			return nil, errors.New("recovery file content digest mismatch")
		}
		fileDigest = actual[:]
	} else if file.Mode != 0 || len(file.Content) != 0 || file.ContentSHA != "" {
		return nil, errors.New("absent recovery file contains state")
	}
	var out bytes.Buffer
	out.WriteString("AHA-RECOVERY-MANIFEST\x00")
	out.WriteString(RecoveryBindingVersion)
	out.WriteByte(0)
	for _, value := range []string{manifest.TargetID, manifest.AgentID, manifest.BindingGeneration, manifest.ExecutionID, state.ActionID} {
		if err := writeBindingString(&out, value); err != nil {
			return nil, err
		}
	}
	if err := writeBindingDigest(&out, actionDigest); err != nil {
		return nil, err
	}
	writeBindingTime(&out, state.CapturedAt)
	if err := writeBindingString(&out, state.PreviousEffectiveValue); err != nil {
		return nil, err
	}
	if err := writeBindingString(&out, file.Path); err != nil {
		return nil, err
	}
	if file.Exists {
		out.WriteByte(1)
	} else {
		out.WriteByte(0)
	}
	var mode [4]byte
	binary.BigEndian.PutUint32(mode[:], file.Mode)
	out.Write(mode[:])
	writeBindingTime(&out, file.CapturedAt)
	if file.Exists {
		out.Write(fileDigest)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(file.Content)))
		out.Write(size[:])
	} else {
		out.Write(make([]byte, sha256.Size+8))
	}
	if out.Len() > MaxBindingBytes {
		return nil, errors.New("recovery manifest exceeds maximum canonical size")
	}
	return out.Bytes(), nil
}

func canonicalEvidenceBytes(provenance EvidenceProvenance) ([]byte, error) {
	if strings.TrimSpace(provenance.AssessmentID) == "" || strings.TrimSpace(provenance.TargetID) == "" ||
		strings.TrimSpace(provenance.Source) == "" || strings.TrimSpace(provenance.CatalogVersion) == "" ||
		provenance.CollectedAt.IsZero() || strings.TrimSpace(provenance.Assessment.Platform) == "" ||
		len(provenance.Assessment.Findings) > MaxBindingItems {
		return nil, errors.New("assessment evidence provenance is incomplete")
	}
	var out bytes.Buffer
	out.WriteString("AHA-ASSESSMENT-EVIDENCE\x00")
	out.WriteString(EvidenceBindingVersion)
	out.WriteByte(0)
	for _, value := range []string{provenance.AssessmentID, provenance.TargetID, provenance.Source, provenance.CatalogVersion, provenance.Assessment.Platform} {
		if err := writeBindingString(&out, value); err != nil {
			return nil, err
		}
	}
	writeBindingTime(&out, provenance.CollectedAt)
	if err := writeBindingCount(&out, len(provenance.Assessment.Findings)); err != nil {
		return nil, err
	}
	for _, finding := range provenance.Assessment.Findings {
		for _, value := range []string{finding.ControlID, finding.Title, string(finding.Status), string(finding.Applicability), finding.Severity, finding.CurrentValue, finding.ExpectedValue, finding.Message, finding.Source} {
			if err := writeBindingString(&out, value); err != nil {
				return nil, err
			}
		}
		if len(finding.Evidence) > MaxBindingItems {
			return nil, errors.New("assessment evidence count exceeds maximum")
		}
		if err := writeBindingCount(&out, len(finding.Evidence)); err != nil {
			return nil, err
		}
		for _, item := range finding.Evidence {
			for _, value := range []string{item.Name, item.Value, item.Source} {
				if err := writeBindingString(&out, value); err != nil {
					return nil, err
				}
			}
		}
		if finding.Error == nil {
			out.WriteByte(0)
		} else {
			out.WriteByte(1)
			for _, value := range []string{finding.Error.Code, finding.Error.Message, finding.Error.Source} {
				if err := writeBindingString(&out, value); err != nil {
					return nil, err
				}
			}
		}
	}
	if out.Len() > MaxBindingBytes {
		return nil, errors.New("assessment evidence exceeds maximum canonical size")
	}
	return out.Bytes(), nil
}

func writeBindingString(out *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) || len(value) > MaxBindingStringBytes || out.Len()+4+len(value) > MaxBindingBytes {
		return errors.New("binding string is invalid or exceeds maximum length")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	out.Write(length[:])
	out.WriteString(value)
	return nil
}

func validateBindingAction(action planner.Action) error {
	for _, value := range []string{action.ActionID, action.ControlID, action.Title, action.ActionType, action.CurrentValue, action.DesiredValue, string(action.ExecutionMode), action.Reason} {
		if !utf8.ValidString(value) || len(value) > MaxBindingStringBytes {
			return errors.New("plan action string is invalid or exceeds maximum length")
		}
	}
	return nil
}

func writeBindingCount(out *bytes.Buffer, count int) error {
	if count < 0 || count > MaxBindingItems {
		return errors.New("binding item count exceeds maximum")
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(count))
	out.Write(encoded[:])
	return nil
}

func writeBindingDigest(out *bytes.Buffer, value string) error {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return errors.New("binding digest has invalid format")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != strings.TrimPrefix(value, "sha256:") {
		return errors.New("binding digest has invalid format")
	}
	out.Write(decoded)
	return nil
}

func writeBindingTime(out *bytes.Buffer, value time.Time) {
	var encoded [12]byte
	binary.BigEndian.PutUint64(encoded[:8], uint64(value.Unix()))
	binary.BigEndian.PutUint32(encoded[8:], uint32(value.Nanosecond()))
	out.Write(encoded[:])
}

func digestCanonical(canonical []byte) string {
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:])
}
