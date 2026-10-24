"""Controller-owned, versioned policy/catalog records and target assignments."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json

from sqlalchemy import select
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.audit.service import append_event
from app.db.models import (
    AgentCredential,
    AgentCredentialState,
    AgentIdentity,
    AgentIdentityState,
    PolicyCatalogDefinition,
    PolicyReviewRecord,
    Target,
    TargetAgentBinding,
    TargetPolicyAssignment,
)
from app.policies.trust import (
    PolicyTrustConfigurationError,
    load_policy_trust_pins,
    matching_policy_pin,
)


MAX_DEFINITION_BYTES = 1 << 20


class RegistryError(ValueError):
    """A policy/catalog definition or assignment cannot be trusted."""


@dataclass(frozen=True)
class ResolvedPolicyAssignment:
    target_id: str
    agent_id: str
    binding_generation: str
    platform: str
    policy_version: str
    catalog_version: str
    definition_digest: str
    provenance_reference: str


def canonical_definition(value: object) -> tuple[str, str]:
    """Canonical JSON v1: UTF-8, sorted keys, compact separators, no NaN."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise RegistryError("policy definition is not valid JSON data") from exc
    if not isinstance(value, dict) or len(encoded) > MAX_DEFINITION_BYTES:
        raise RegistryError("policy definition must be a bounded JSON object")
    return encoded.decode("utf-8"), "sha256:" + hashlib.sha256(
        b"policy-catalog-definition/v1\x00" + encoded
    ).hexdigest()


def register_definition(
    db: Session,
    *,
    platform: str,
    policy_version: str,
    catalog_version: str,
    definition: object,
    provenance_reference: str,
) -> PolicyCatalogDefinition:
    """Persist an unverified entry; this function never upgrades trust state."""
    _required(platform, "platform", 50)
    _required(policy_version, "policy version", 128)
    _required(catalog_version, "catalog version", 128)
    _required(provenance_reference, "provenance reference", 512)
    definition_json, digest = canonical_definition(definition)
    row = PolicyCatalogDefinition(
        platform=platform,
        policy_version=policy_version,
        catalog_version=catalog_version,
        definition_json=definition_json,
        definition_sha256=digest,
        provenance_reference=provenance_reference,
        verification_status="unverified",
        applicability_status="unconfirmed",
        enabled=False,
    )
    db.add(row)
    try:
        db.flush()
        append_event(
            db,
            event_type="policy.definition.registered",
            policy_definition_id=row.id,
            metadata={
                "definition_digest": digest,
                "platform": platform,
                "policy_version": policy_version,
                "catalog_version": catalog_version,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(row)
    return row


def resolve_target_assignment(db: Session, *, target_id: str) -> ResolvedPolicyAssignment:
    target = db.get(Target, target_id)
    if target is None:
        raise RegistryError("target is not registered")
    binding = db.scalar(
        select(TargetAgentBinding).where(
            TargetAgentBinding.target_id == target_id,
            TargetAgentBinding.state == "active",
        )
    )
    assignment = db.get(TargetPolicyAssignment, target_id)
    if binding is None or assignment is None or assignment.state != "active":
        raise RegistryError("target has no active agent/policy assignment")
    identity = db.get(AgentIdentity, binding.agent_id)
    credential = db.get(AgentCredential, binding.credential_id)
    now = datetime.now(timezone.utc)
    if (
        identity is None
        or identity.state != AgentIdentityState.ACTIVE.value
        or credential is None
        or credential.agent_id != binding.agent_id
        or credential.state != AgentCredentialState.ACTIVE.value
        or credential.revoked_at is not None
        or now < _utc(credential.not_before)
        or now >= _utc(credential.expires_at)
    ):
        raise RegistryError("target agent credential is not currently active")
    if assignment.binding_generation != binding.generation:
        raise RegistryError("policy assignment belongs to a stale agent binding")
    definition = db.get(PolicyCatalogDefinition, assignment.definition_id)
    if definition is None:
        raise RegistryError("assigned policy/catalog definition is missing")
    _validate_definition(definition)
    _require_current_approval(db, definition)
    if not definition.enabled:
        raise RegistryError("policy/catalog definition is disabled")
    if definition.verification_status != "verified":
        raise RegistryError("policy/catalog definition is not verified")
    if definition.applicability_status != "confirmed":
        raise RegistryError("policy/catalog applicability is not confirmed")
    if definition.platform != target.platform:
        raise RegistryError("policy/catalog platform does not match target")
    return ResolvedPolicyAssignment(
        target_id=target.id,
        agent_id=binding.agent_id,
        binding_generation=binding.generation,
        platform=target.platform,
        policy_version=definition.policy_version,
        catalog_version=definition.catalog_version,
        definition_digest=definition.definition_sha256,
        provenance_reference=definition.provenance_reference,
    )


def assign_policy_to_target(db: Session, *, target_id: str, definition_id: int) -> TargetPolicyAssignment:
    """Bind a verified definition to the target's current agent generation."""
    target = db.get(Target, target_id)
    binding = db.scalar(
        select(TargetAgentBinding).where(
            TargetAgentBinding.target_id == target_id,
            TargetAgentBinding.state == "active",
        )
    )
    definition = db.get(PolicyCatalogDefinition, definition_id)
    if target is None or binding is None:
        raise RegistryError("target has no active target-agent binding")
    if definition is None:
        raise RegistryError("policy/catalog definition is unknown")
    _validate_definition(definition)
    _require_current_approval(db, definition)
    if (
        definition.platform != target.platform
        or definition.verification_status != "verified"
        or definition.applicability_status != "confirmed"
        or not definition.enabled
    ):
        raise RegistryError("policy/catalog definition is not authorized for this target")
    assignment = db.get(TargetPolicyAssignment, target_id)
    if assignment is None:
        assignment = TargetPolicyAssignment(target_id=target_id)
        db.add(assignment)
    assignment.definition_id = definition_id
    assignment.binding_generation = binding.generation
    assignment.state = "active"
    try:
        db.flush()
        append_event(
            db,
            event_type="policy.assignment.created",
            target_id=target.id,
            policy_definition_id=definition.id,
            metadata={"binding_generation": binding.generation},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(assignment)
    return assignment


def revoke_definition(db: Session, *, definition_id: int) -> None:
    definition = db.get(PolicyCatalogDefinition, definition_id)
    if definition is None:
        raise RegistryError("policy/catalog definition is unknown")
    definition.verification_status = "revoked"
    definition.enabled = False
    try:
        db.execute(
            update(TargetPolicyAssignment)
            .where(TargetPolicyAssignment.definition_id == definition_id)
            .values(state="stale")
        )
        append_event(
            db,
            event_type="policy.definition.revoked",
            policy_definition_id=definition.id,
            metadata={"definition_digest": definition.definition_sha256},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise


def _validate_definition(row: PolicyCatalogDefinition) -> None:
    try:
        definition = json.loads(row.definition_json)
    except (TypeError, ValueError) as exc:
        raise RegistryError("stored policy/catalog definition is malformed") from exc
    canonical, digest = canonical_definition(definition)
    if canonical != row.definition_json or digest != row.definition_sha256:
        raise RegistryError("stored policy/catalog definition integrity check failed")


def _require_current_approval(db: Session, row: PolicyCatalogDefinition) -> PolicyReviewRecord:
    review = db.scalar(
        select(PolicyReviewRecord)
        .where(PolicyReviewRecord.policy_definition_id == row.id)
        .order_by(PolicyReviewRecord.id.desc())
        .limit(1)
    )
    if (
        review is None
        or review.decision != "approved"
        or review.reviewed_definition_sha256 != row.definition_sha256
        or review.platform != row.platform
        or review.policy_version != row.policy_version
        or review.catalog_version != row.catalog_version
        or review.provenance_reference != row.provenance_reference
        or review.reviewed_source_evidence_sha256 is None
    ):
        raise RegistryError("policy has no current digest-bound approval review")
    try:
        pins = load_policy_trust_pins()
    except PolicyTrustConfigurationError as exc:
        raise RegistryError("policy trust verification is not configured") from exc
    pin = matching_policy_pin(
        pins,
        provenance_reference=row.provenance_reference,
        source_evidence_sha256=review.reviewed_source_evidence_sha256,
        definition_sha256=row.definition_sha256,
        platform=row.platform,
        policy_version=row.policy_version,
        catalog_version=row.catalog_version,
    )
    if pin is None or row.applicability_status != "confirmed" or row.verification_status != "verified":
        raise RegistryError("policy review trust pin or applicability is no longer valid")
    return review


def _required(value: str, label: str, limit: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise RegistryError(f"{label} is invalid")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
