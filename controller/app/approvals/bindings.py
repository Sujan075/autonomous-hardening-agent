"""Typed Controller implementation of the agent's v1 binding contracts.

These functions calculate deterministic digests. They do not authenticate an
agent, establish assessment provenance, authorize a human, or enable dispatch.
Callers must obtain target identity from Controller-owned records and must not
promote an HTTP observation to trusted evidence without a separate verifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import math
import struct
from typing import Any, Callable, Mapping


ACTION_DIGEST_VERSION = "planner-action/v1"
EVIDENCE_BINDING_VERSION = "assessment-evidence/v1"
PLAN_BINDING_VERSION = "plan-binding/v1"
RECOVERY_BINDING_VERSION = "recovery-manifest/v1"
MAX_BINDING_BYTES = 4 << 20
MAX_BINDING_STRING_BYTES = 1 << 20
MAX_BINDING_ITEMS = 4096
MAX_ACTION_STRING_BYTES = (1 << 32) - 1
MAX_ASSESSMENT_JSON_BYTES = MAX_BINDING_BYTES


class BindingValidationError(ValueError):
    """An input cannot be safely represented by the v1 binding contract."""


class EvidenceOrigin(StrEnum):
    CONTROLLER_CAPTURED_UNAUTHENTICATED = "controller_captured_unauthenticated"
    AGENT_REPORTED_UNAUTHENTICATED = "agent_reported_unauthenticated"
    # This is still only a caller assertion. Trusted mode additionally needs
    # an injected verifier owned by a future authenticated provenance service.
    UPSTREAM_ASSERTED = "upstream_asserted"


@dataclass(frozen=True)
class Timestamp:
    """Exact contract timestamp: signed Unix seconds plus nanoseconds."""

    unix_seconds: int
    nanoseconds: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.unix_seconds, bool) or not isinstance(self.unix_seconds, int):
            raise BindingValidationError("timestamp seconds must be an integer")
        if not -(1 << 63) <= self.unix_seconds < (1 << 63):
            raise BindingValidationError("timestamp seconds are out of range")
        if isinstance(self.nanoseconds, bool) or not isinstance(self.nanoseconds, int):
            raise BindingValidationError("timestamp nanoseconds must be an integer")
        if not 0 <= self.nanoseconds < 1_000_000_000:
            raise BindingValidationError("timestamp nanoseconds are out of range")

    @classmethod
    def from_datetime(cls, value: datetime) -> Timestamp:
        if value.tzinfo is None or value.utcoffset() is None:
            raise BindingValidationError("timestamp must include a timezone")
        utc_value = value.astimezone(timezone.utc)
        delta = utc_value - datetime(1970, 1, 1, tzinfo=timezone.utc)
        seconds = delta.days * 86_400 + delta.seconds
        nanos = delta.microseconds * 1000
        return cls(seconds, nanos)

    def total_nanoseconds(self) -> int:
        return self.unix_seconds * 1_000_000_000 + self.nanoseconds


@dataclass(frozen=True)
class ControllerTargetContext:
    """Identity/context loaded from the Controller target record, never agent JSON."""

    target_id: str
    platform: str
    binding_generation: str | None = None
    agent_id: str | None = None

    @classmethod
    def from_target(cls, target: object) -> ControllerTargetContext:
        """Copy only Controller-owned identity fields from a target model."""
        return cls(
            target_id=getattr(target, "id", ""),
            platform=getattr(target, "platform", ""),
            binding_generation=getattr(target, "binding_generation", None),
            agent_id=getattr(target, "agent_id", None),
        )

    def validate(self) -> None:
        _required_text(self.target_id, "Controller target ID")
        _required_text(self.platform, "Controller target platform")


@dataclass(frozen=True)
class Action:
    action_id: str
    control_id: str
    title: str
    action_type: str
    current_value: str
    desired_value: str
    risk_score: float
    execution_mode: str
    reason: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Action:
        expected = {
            "action_id", "control_id", "title", "action_type", "current_value",
            "desired_value", "risk_score", "execution_mode", "reason",
        }
        value = _mapping(value, "action")
        _require_exact_keys(value, expected, "action")
        action = cls(**value)
        _validate_action(action)
        return action


@dataclass(frozen=True)
class EvidenceItem:
    name: str
    value: str
    source: str


@dataclass(frozen=True)
class NormalizedError:
    code: str
    message: str
    source: str


@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    status: str
    applicability: str
    severity: str
    current_value: str
    expected_value: str
    message: str
    source: str
    evidence: tuple[EvidenceItem, ...] = ()
    error: NormalizedError | None = None


@dataclass(frozen=True)
class Assessment:
    platform: str
    findings: tuple[Finding, ...]

    @classmethod
    def from_agent_payload(cls, value: object) -> Assessment:
        """Parse only the shared assessment payload, rejecting identity/digest extras."""
        payload = _mapping(value, "assessment")
        _require_exact_keys(payload, {"platform", "findings"}, "assessment")
        platform = _string(payload["platform"], "assessment platform")
        raw_findings = payload["findings"]
        if not isinstance(raw_findings, list) or len(raw_findings) > MAX_BINDING_ITEMS:
            raise BindingValidationError("assessment findings must be a bounded list")
        findings = tuple(_finding_from_mapping(item) for item in raw_findings)
        assessment = cls(platform=platform, findings=findings)
        _validate_assessment(assessment)
        return assessment


@dataclass(frozen=True)
class AssessmentProvenance:
    """Controller-maintained metadata associated with an assessment record.

    target_id and binding_generation are stored-record context, never values
    copied from the agent's assessment/status response. ``origin`` describes
    the evidence path, not a cryptographic verification result.
    """

    assessment_id: str
    target_id: str
    binding_generation: str | None
    source: str
    catalog_version: str
    collected_at: Timestamp
    origin: EvidenceOrigin
    agent_id: str | None = None
    verification_reference: str | None = None


@dataclass(frozen=True)
class Plan:
    status: str
    platform: str
    actions: tuple[Action, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Plan:
        value = _mapping(value, "plan")
        _require_exact_keys(value, {"status", "platform", "actions"}, "plan")
        raw_actions = value["actions"]
        if not isinstance(raw_actions, list) or len(raw_actions) > MAX_BINDING_ITEMS:
            raise BindingValidationError("plan actions must be a bounded list")
        plan = cls(
            status=_string(value["status"], "plan status"),
            platform=_string(value["platform"], "plan platform"),
            actions=tuple(Action.from_mapping(action) for action in raw_actions),
        )
        if plan.status not in {"READY", "BLOCKED"}:
            raise BindingValidationError("unsupported plan status")
        return plan


@dataclass(frozen=True)
class AssessmentRecord:
    provenance: AssessmentProvenance
    assessment: Assessment


@dataclass(frozen=True)
class RecoveryFileState:
    path: str
    exists: bool
    mode: int
    content_sha256: str
    content: bytes
    captured_at: Timestamp


@dataclass(frozen=True)
class RecoveryState:
    action_id: str
    file: RecoveryFileState
    previous_effective_value: str
    captured_at: Timestamp


@dataclass(frozen=True)
class RecoveryManifest:
    target_id: str
    agent_id: str
    binding_generation: str
    execution_id: str
    action: Action
    state: RecoveryState


@dataclass(frozen=True)
class BindingResult:
    """Digest and validated context only; deliberately has no dispatch-ready flag."""

    version: str
    digest: str
    target_id: str
    evidence_origin: EvidenceOrigin | None


def canonical_action_bytes(action: Action) -> bytes:
    _validate_action(action)
    out = bytearray(b"AHA-PLANNER-ACTION-DIGEST\x00planner-action/v1\x00")
    for value in (
        action.action_id,
        action.control_id,
        action.title,
        action.action_type,
        action.current_value,
        action.desired_value,
    ):
        out.extend(_action_string(value))
    try:
        out.extend(struct.pack(">d", float(action.risk_score)))
    except (OverflowError, struct.error) as exc:
        raise BindingValidationError("action risk score is not representable as binary64") from exc
    out.extend(_action_string(action.execution_mode))
    out.extend(_action_string(action.reason))
    return bytes(out)


def action_digest(action: Action) -> str:
    return _sha256(canonical_action_bytes(action))


def canonical_evidence_bytes(provenance: AssessmentProvenance, assessment: Assessment) -> bytes:
    if not isinstance(provenance, AssessmentProvenance) or not isinstance(assessment, Assessment):
        raise BindingValidationError("evidence inputs must be typed provenance and assessment records")
    _validate_provenance_shape(provenance)
    _validate_assessment(assessment)
    out = bytearray(b"AHA-ASSESSMENT-EVIDENCE\x00assessment-evidence/v1\x00")
    for value in (
        provenance.assessment_id,
        provenance.target_id,
        provenance.source,
        provenance.catalog_version,
        assessment.platform,
    ):
        out.extend(_binding_string(value, out))
    out.extend(_timestamp(provenance.collected_at))
    out.extend(_count(len(assessment.findings)))
    for finding in assessment.findings:
        for value in (
            finding.control_id,
            finding.title,
            finding.status,
            finding.applicability,
            finding.severity,
            finding.current_value,
            finding.expected_value,
            finding.message,
            finding.source,
        ):
            out.extend(_binding_string(value, out))
        out.extend(_count(len(finding.evidence)))
        for item in finding.evidence:
            for value in (item.name, item.value, item.source):
                out.extend(_binding_string(value, out))
        if finding.error is None:
            out.append(0)
        else:
            out.append(1)
            for value in (finding.error.code, finding.error.message, finding.error.source):
                out.extend(_binding_string(value, out))
    _check_total_size(out)
    return bytes(out)


def evidence_digest(provenance: AssessmentProvenance, assessment: Assessment) -> str:
    return _sha256(canonical_evidence_bytes(provenance, assessment))


def canonical_plan_binding_bytes(
    target: ControllerTargetContext,
    operation: str,
    policy_version: str,
    catalog_version: str,
    plan: Plan,
    evidence: AssessmentRecord,
    *,
    now: Timestamp,
    max_evidence_age_seconds: int,
    require_authenticated_context: bool = False,
    provenance_verifier: Callable[[ControllerTargetContext, AssessmentRecord], bool] | None = None,
) -> bytes:
    if not isinstance(target, ControllerTargetContext) or not isinstance(evidence, AssessmentRecord) or not isinstance(plan, Plan):
        raise BindingValidationError("plan binding inputs must use typed Controller context and records")
    _required_text(operation, "operation")
    _validate_expected_evidence(
        target,
        evidence,
        catalog_version=catalog_version,
        now=now,
        max_age_seconds=max_evidence_age_seconds,
        require_authenticated=require_authenticated_context,
        provenance_verifier=provenance_verifier,
    )
    if operation not in {"execute", "rollback"}:
        raise BindingValidationError("unsupported operation")
    _required_text(policy_version, "policy version")
    _required_text(catalog_version, "catalog version")
    if plan.platform != target.platform:
        raise BindingValidationError("plan platform does not match Controller target")
    if plan.status not in {"READY", "BLOCKED"} or len(plan.actions) > MAX_BINDING_ITEMS:
        raise BindingValidationError("plan status or action count is invalid")

    out = bytearray(b"AHA-PLAN-BINDING\x00plan-binding/v1\x00")
    for value in (target.target_id, operation, policy_version, catalog_version, plan.status, plan.platform):
        out.extend(_binding_string(value, out))
    out.extend(bytes.fromhex(evidence_digest(evidence.provenance, evidence.assessment).removeprefix("sha256:")))
    out.extend(_count(len(plan.actions)))
    for action in plan.actions:
        for value in _action_strings(action):
            _binding_string(value, bytearray())
        out.extend(bytes.fromhex(action_digest(action).removeprefix("sha256:")))
    _check_total_size(out)
    return bytes(out)


def plan_binding_digest(
    target: ControllerTargetContext,
    operation: str,
    policy_version: str,
    catalog_version: str,
    plan: Plan,
    evidence: AssessmentRecord,
    *,
    now: Timestamp,
    max_evidence_age_seconds: int,
    require_authenticated_context: bool = False,
    provenance_verifier: Callable[[ControllerTargetContext, AssessmentRecord], bool] | None = None,
) -> BindingResult:
    canonical = canonical_plan_binding_bytes(
        target,
        operation,
        policy_version,
        catalog_version,
        plan,
        evidence,
        now=now,
        max_evidence_age_seconds=max_evidence_age_seconds,
        require_authenticated_context=require_authenticated_context,
        provenance_verifier=provenance_verifier,
    )
    return BindingResult(
        version=PLAN_BINDING_VERSION,
        digest=_sha256(canonical),
        target_id=target.target_id,
        evidence_origin=evidence.provenance.origin,
    )


def canonical_recovery_manifest_bytes(
    manifest: RecoveryManifest,
    expected_target: ControllerTargetContext,
) -> bytes:
    if not isinstance(manifest, RecoveryManifest):
        raise BindingValidationError("recovery manifest must use the typed v1 contract")
    if not isinstance(expected_target, ControllerTargetContext):
        raise BindingValidationError("recovery binding requires Controller target context")
    expected_target.validate()
    if manifest.target_id != expected_target.target_id:
        raise BindingValidationError("recovery manifest target does not match Controller target")
    if expected_target.agent_id is not None and manifest.agent_id != expected_target.agent_id:
        raise BindingValidationError("recovery manifest agent does not match Controller target")
    if (
        expected_target.binding_generation is not None
        and manifest.binding_generation != expected_target.binding_generation
    ):
        raise BindingValidationError("recovery manifest belongs to a replaced target binding")
    state = manifest.state
    if not isinstance(state, RecoveryState) or not isinstance(state.file, RecoveryFileState):
        raise BindingValidationError("recovery state is incomplete or has an unsupported type")
    file_state = state.file
    for value, label in (
        (manifest.target_id, "target ID"),
        (manifest.agent_id, "agent ID"),
        (manifest.binding_generation, "binding generation"),
        (manifest.execution_id, "execution ID"),
        (state.action_id, "recovery state action ID"),
        (state.previous_effective_value, "previous effective value"),
        (file_state.path, "recovery path"),
    ):
        _required_text(value, label)
    _validate_action(manifest.action)
    if state.action_id != manifest.action.action_id:
        raise BindingValidationError("recovery action does not match captured state")
    if not isinstance(file_state.exists, bool):
        raise BindingValidationError("recovery file existence must be boolean")
    if isinstance(file_state.mode, bool) or not isinstance(file_state.mode, int) or not 0 <= file_state.mode <= 0o777:
        raise BindingValidationError("recovery file mode is invalid")
    if not isinstance(file_state.content, bytes) or len(file_state.content) > MAX_BINDING_BYTES:
        raise BindingValidationError("recovery content is invalid or oversized")
    actual_digest = hashlib.sha256(file_state.content).hexdigest()
    if file_state.exists:
        if file_state.content_sha256 != actual_digest:
            raise BindingValidationError("recovery file content digest mismatch")
        file_digest = bytes.fromhex(actual_digest)
    else:
        if file_state.mode != 0 or file_state.content or file_state.content_sha256:
            raise BindingValidationError("absent recovery file contains state")
        file_digest = bytes(32)

    out = bytearray(b"AHA-RECOVERY-MANIFEST\x00recovery-manifest/v1\x00")
    for value in (
        manifest.target_id,
        manifest.agent_id,
        manifest.binding_generation,
        manifest.execution_id,
        state.action_id,
    ):
        out.extend(_binding_string(value, out))
    out.extend(bytes.fromhex(action_digest(manifest.action).removeprefix("sha256:")))
    out.extend(_timestamp(state.captured_at))
    out.extend(_binding_string(state.previous_effective_value, out))
    out.extend(_binding_string(file_state.path, out))
    out.append(1 if file_state.exists else 0)
    out.extend(struct.pack(">I", file_state.mode))
    out.extend(_timestamp(file_state.captured_at))
    out.extend(file_digest)
    out.extend(struct.pack(">Q", len(file_state.content) if file_state.exists else 0))
    _check_total_size(out)
    return bytes(out)


def recovery_manifest_digest(
    manifest: RecoveryManifest,
    expected_target: ControllerTargetContext,
) -> BindingResult:
    canonical = canonical_recovery_manifest_bytes(manifest, expected_target)
    return BindingResult(
        version=RECOVERY_BINDING_VERSION,
        digest=_sha256(canonical),
        target_id=expected_target.target_id,
        evidence_origin=None,
    )


def _validate_expected_evidence(
    target: ControllerTargetContext,
    record: AssessmentRecord,
    *,
    catalog_version: str,
    now: Timestamp,
    max_age_seconds: int,
    require_authenticated: bool,
    provenance_verifier: Callable[[ControllerTargetContext, AssessmentRecord], bool] | None,
) -> None:
    target.validate()
    if not isinstance(now, Timestamp):
        raise BindingValidationError("current time is missing or invalid")
    _validate_provenance_shape(record.provenance)
    if record.provenance.target_id != target.target_id:
        raise BindingValidationError("assessment target does not match Controller target")
    if record.assessment.platform != target.platform:
        raise BindingValidationError("assessment platform does not match Controller target")
    if record.provenance.catalog_version != catalog_version:
        raise BindingValidationError("assessment catalog does not match expected catalog")
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds <= 0:
        raise BindingValidationError("maximum evidence age must be a positive integer")
    age_ns = now.total_nanoseconds() - record.provenance.collected_at.total_nanoseconds()
    if age_ns < 0 or age_ns > max_age_seconds * 1_000_000_000:
        raise BindingValidationError("assessment provenance is future-dated or stale")
    if target.binding_generation and record.provenance.binding_generation != target.binding_generation:
        raise BindingValidationError("assessment belongs to a replaced target binding")
    if require_authenticated:
        provenance = record.provenance
        if (
            provenance.origin is not EvidenceOrigin.UPSTREAM_ASSERTED
            or not provenance.verification_reference
            or not target.binding_generation
            or provenance.binding_generation != target.binding_generation
            or not target.agent_id
            or provenance.agent_id != target.agent_id
            or provenance_verifier is None
        ):
            raise BindingValidationError("authenticated assessment provenance is unavailable or mismatched")
        try:
            verified = provenance_verifier(target, record)
        except Exception as exc:
            raise BindingValidationError("assessment provenance verification failed") from exc
        if verified is not True:
            raise BindingValidationError("assessment provenance verification failed")


def _validate_provenance_shape(provenance: AssessmentProvenance) -> None:
    if not isinstance(provenance, AssessmentProvenance):
        raise BindingValidationError("assessment provenance is missing or invalid")
    _required_text(provenance.assessment_id, "assessment ID")
    _required_text(provenance.target_id, "assessment target ID")
    _required_text(provenance.source, "assessment source")
    _required_text(provenance.catalog_version, "assessment catalog version")
    if not isinstance(provenance.collected_at, Timestamp):
        raise BindingValidationError("assessment collection time is missing or invalid")
    if not isinstance(provenance.origin, EvidenceOrigin):
        raise BindingValidationError("assessment origin is missing or invalid")
    if provenance.binding_generation is not None:
        _required_text(provenance.binding_generation, "assessment binding generation")
    if provenance.agent_id is not None:
        _required_text(provenance.agent_id, "assessment agent ID")
    if provenance.verification_reference is not None:
        _required_text(provenance.verification_reference, "provenance verification reference")


def _finding_from_mapping(value: object) -> Finding:
    raw = _mapping(value, "finding")
    allowed = {
        "control_id", "title", "status", "applicability", "severity", "current_value",
        "expected_value", "message", "source", "evidence", "error",
    }
    if set(raw) - allowed:
        raise BindingValidationError("finding contains unsupported fields")
    required = {"control_id", "title", "status", "severity", "current_value", "expected_value", "message"}
    if required - raw.keys():
        raise BindingValidationError("finding is missing required fields")
    evidence_raw = raw.get("evidence", [])
    if not isinstance(evidence_raw, list) or len(evidence_raw) > MAX_BINDING_ITEMS:
        raise BindingValidationError("finding evidence must be a bounded list")
    evidence_items: list[EvidenceItem] = []
    for item in evidence_raw:
        item_map = _mapping(item, "evidence item")
        _require_exact_keys(item_map, {"name", "value", "source"}, "evidence item")
        evidence_items.append(EvidenceItem(**{key: _string(item_map[key], key) for key in item_map}))
    error_value = raw.get("error")
    error = None
    if error_value is not None:
        error_map = _mapping(error_value, "normalized error")
        _require_exact_keys(error_map, {"code", "message", "source"}, "normalized error")
        error = NormalizedError(**{key: _string(error_map[key], key) for key in error_map})
    optional_strings = ("applicability", "source")
    fields = {key: _string(raw.get(key, ""), key) for key in required | set(optional_strings)}
    finding = Finding(**fields, evidence=tuple(evidence_items), error=error)
    _validate_finding(finding)
    return finding


def _validate_assessment(assessment: Assessment) -> None:
    if not isinstance(assessment, Assessment) or not isinstance(assessment.findings, tuple):
        raise BindingValidationError("assessment must use the typed v1 schema")
    _required_text(assessment.platform, "assessment platform")
    if len(assessment.findings) > MAX_BINDING_ITEMS:
        raise BindingValidationError("assessment finding count exceeds maximum")
    for finding in assessment.findings:
        _validate_finding(finding)


def _validate_finding(finding: Finding) -> None:
    if not isinstance(finding, Finding) or not isinstance(finding.evidence, tuple):
        raise BindingValidationError("finding must use the typed v1 schema")
    for value in (
        finding.control_id, finding.title, finding.status, finding.applicability,
        finding.severity, finding.current_value, finding.expected_value,
        finding.message, finding.source,
    ):
        _validate_binding_text(value)
    if len(finding.evidence) > MAX_BINDING_ITEMS:
        raise BindingValidationError("finding evidence count exceeds maximum")
    for item in finding.evidence:
        for value in (item.name, item.value, item.source):
            _validate_binding_text(value)
    if finding.error is not None:
        for value in (finding.error.code, finding.error.message, finding.error.source):
            _validate_binding_text(value)


def _validate_action(action: Action) -> None:
    if not isinstance(action, Action):
        raise BindingValidationError("action must be a typed Action")
    for field_name in ("action_id", "control_id", "title", "action_type", "desired_value", "execution_mode", "reason"):
        _required_text(getattr(action, field_name), f"action {field_name}")
    _validate_action_text(action.current_value)
    if isinstance(action.risk_score, bool) or not isinstance(action.risk_score, (int, float)):
        raise BindingValidationError("action risk score must be numeric")
    try:
        score = float(action.risk_score)
    except (OverflowError, ValueError) as exc:
        raise BindingValidationError("action risk score is not representable as binary64") from exc
    if not math.isfinite(score) or score < 0:
        raise BindingValidationError("action risk score must be finite and non-negative")


def _action_strings(action: Action) -> tuple[str, ...]:
    return (
        action.action_id, action.control_id, action.title, action.action_type,
        action.current_value, action.desired_value, action.execution_mode, action.reason,
    )


def _action_string(value: str) -> bytes:
    encoded = _validate_action_text(value)
    if len(encoded) > MAX_ACTION_STRING_BYTES:
        raise BindingValidationError("action string exceeds v1 uint32 length")
    return struct.pack(">I", len(encoded)) + encoded


def _validate_action_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise BindingValidationError("action fields must be strings")
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise BindingValidationError("action text is not valid UTF-8") from exc


def _binding_string(value: str, out: bytearray) -> bytes:
    encoded = _validate_binding_text(value)
    if len(encoded) > MAX_BINDING_STRING_BYTES or len(out) + 4 + len(encoded) > MAX_BINDING_BYTES:
        raise BindingValidationError("binding string exceeds v1 limits")
    return struct.pack(">I", len(encoded)) + encoded


def _validate_binding_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise BindingValidationError("binding fields must be strings")
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise BindingValidationError("binding text is not valid UTF-8") from exc


def _required_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise BindingValidationError(f"{label} is required")
    _validate_binding_text(value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise BindingValidationError(f"{label} must be a string")
    _validate_binding_text(value)
    return value


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise BindingValidationError(f"{label} must be an object with string keys")
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise BindingValidationError(f"{label} fields do not match the v1 schema")


def _count(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_BINDING_ITEMS:
        raise BindingValidationError("binding collection count exceeds v1 limits")
    return struct.pack(">I", value)


def _timestamp(value: Timestamp) -> bytes:
    if not isinstance(value, Timestamp):
        raise BindingValidationError("binding timestamp is missing or invalid")
    return struct.pack(">qI", value.unix_seconds, value.nanoseconds)


def _check_total_size(value: bytearray) -> None:
    if len(value) > MAX_BINDING_BYTES:
        raise BindingValidationError("canonical binding exceeds v1 size limit")


def _sha256(canonical: bytes) -> str:
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _duplicate_rejecting_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BindingValidationError("duplicate JSON object key")
        result[key] = value
    return result


def parse_assessment_json(raw: str | bytes) -> Assessment:
    """Parse an agent response without accepting duplicate or identity claims."""
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise BindingValidationError("assessment JSON is not valid UTF-8") from exc
        if len(encoded) > MAX_ASSESSMENT_JSON_BYTES:
            raise BindingValidationError("assessment JSON exceeds maximum size")
        payload_text = raw
    elif isinstance(raw, bytes):
        if len(raw) > MAX_ASSESSMENT_JSON_BYTES:
            raise BindingValidationError("assessment JSON exceeds maximum size")
        try:
            payload_text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise BindingValidationError("assessment JSON is not valid UTF-8") from exc
    else:
        raise BindingValidationError("assessment JSON must be text or UTF-8 bytes")
    try:
        payload = json.loads(payload_text, object_pairs_hook=_duplicate_rejecting_pairs)
    except BindingValidationError:
        raise
    except (ValueError, RecursionError) as exc:
        raise BindingValidationError("assessment JSON is malformed") from exc
    return Assessment.from_agent_payload(payload)


def build_evidence_record(
    *,
    target: ControllerTargetContext,
    assessment_id: str,
    source: str,
    catalog_version: str,
    collected_at: Timestamp,
    origin: EvidenceOrigin,
    assessment: Assessment,
    binding_generation: str | None = None,
    agent_id: str | None = None,
    verification_reference: str | None = None,
) -> AssessmentRecord:
    """Bind provenance metadata to Controller context, not agent response fields."""
    target.validate()
    if assessment.platform != target.platform:
        raise BindingValidationError("assessment platform does not match Controller target")
    if binding_generation is not None and binding_generation != target.binding_generation:
        raise BindingValidationError("provenance generation does not match Controller target")
    if agent_id is not None and target.agent_id and agent_id != target.agent_id:
        raise BindingValidationError("provenance agent ID does not match Controller target")
    record = AssessmentRecord(
        provenance=AssessmentProvenance(
            assessment_id=assessment_id,
            target_id=target.target_id,
            binding_generation=target.binding_generation,
            source=source,
            catalog_version=catalog_version,
            collected_at=collected_at,
            origin=origin,
            agent_id=agent_id,
            verification_reference=verification_reference,
        ),
        assessment=assessment,
    )
    _validate_provenance_shape(record.provenance)
    _validate_assessment(record.assessment)
    return record
