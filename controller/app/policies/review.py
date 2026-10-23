"""Authenticated policy review transitions bound to operator trust pins."""

from datetime import datetime, timezone
import hashlib

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit.service import append_event
from app.auth.oidc import Principal
from app.db.models import PolicyCatalogDefinition, PolicyReviewRecord, TargetPolicyAssignment
from app.policies.registry import RegistryError, _require_current_approval, _validate_definition
from app.policies.trust import PolicyTrustPin, matching_policy_pin


class PolicyReviewError(ValueError):
    """Policy review transition is invalid or not authorized by trusted pins."""


def review_policy_definition(
    db: Session,
    *,
    definition_id: int,
    decision: str,
    rationale: str,
    source_evidence_sha256: str | None,
    reviewer: Principal,
    trust_pins: tuple[PolicyTrustPin, ...],
    now: datetime | None = None,
) -> PolicyReviewRecord:
    if decision not in {"approved", "rejected"}:
        raise PolicyReviewError("review decision must be approved or rejected")
    rationale = _validate_rationale(rationale)
    definition = db.get(PolicyCatalogDefinition, definition_id)
    if definition is None:
        raise PolicyReviewError("policy definition was not found")
    _validate_definition(definition)
    if definition.verification_status == "revoked":
        raise PolicyReviewError("revoked definitions cannot be reviewed again")

    if decision == "approved":
        pin = matching_policy_pin(
            trust_pins,
            provenance_reference=definition.provenance_reference,
            source_evidence_sha256=source_evidence_sha256 or "",
            definition_sha256=definition.definition_sha256,
            platform=definition.platform,
            policy_version=definition.policy_version,
            catalog_version=definition.catalog_version,
        )
        if pin is None:
            raise PolicyReviewError("no trusted source/applicability pin matches this exact definition")
    elif source_evidence_sha256 is not None and not any(
        pin.source_evidence_sha256 == source_evidence_sha256 for pin in trust_pins
    ):
        raise PolicyReviewError("rejection evidence digest is not present in trusted configuration")

    reviewed_at = _utc(now or datetime.now(timezone.utc))
    review = PolicyReviewRecord(
        policy_definition_id=definition.id,
        decision=decision,
        rationale=rationale,
        reviewer_issuer=reviewer.issuer,
        reviewer_subject=reviewer.subject,
        reviewed_definition_sha256=definition.definition_sha256,
        reviewed_source_evidence_sha256=source_evidence_sha256,
        platform=definition.platform,
        policy_version=definition.policy_version,
        catalog_version=definition.catalog_version,
        provenance_reference=definition.provenance_reference,
        reviewed_at=reviewed_at,
    )
    db.add(review)
    try:
        if decision == "approved":
            definition.verification_status = "verified"
            definition.applicability_status = "confirmed"
            definition.enabled = True
        else:
            definition.verification_status = "unverified"
            definition.applicability_status = "unconfirmed"
            definition.enabled = False
            _stale_assignments(db, definition.id)
        db.flush()
        append_event(
            db,
            event_type=f"policy.review.{decision}",
            actor_issuer=reviewer.issuer,
            actor_subject=reviewer.subject,
            policy_definition_id=definition.id,
            metadata={
                "decision": decision,
                "definition_digest": definition.definition_sha256,
                "source_evidence_digest": source_evidence_sha256,
                "rationale_digest": "sha256:" + hashlib.sha256(rationale.encode("utf-8")).hexdigest(),
            },
            occurred_at=reviewed_at,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return review


def set_policy_enabled(
    db: Session,
    *,
    definition_id: int,
    enabled: bool,
    rationale: str,
    reviewer: Principal,
    trust_pins: tuple[PolicyTrustPin, ...],
    now: datetime | None = None,
) -> PolicyCatalogDefinition:
    if not isinstance(enabled, bool):
        raise PolicyReviewError("enabled must be a boolean")
    rationale = _validate_rationale(rationale)
    definition = db.get(PolicyCatalogDefinition, definition_id)
    if definition is None:
        raise PolicyReviewError("policy definition was not found")
    _validate_definition(definition)
    if enabled:
        if definition.verification_status != "verified" or definition.applicability_status != "confirmed":
            raise PolicyReviewError("unverified or inapplicable policy cannot be enabled")
        _require_current_approval(db, definition)
        latest_review = db.scalar(
            select(PolicyReviewRecord)
            .where(PolicyReviewRecord.policy_definition_id == definition.id)
            .order_by(PolicyReviewRecord.id.desc())
            .limit(1)
        )
        if matching_policy_pin(
            trust_pins,
            provenance_reference=definition.provenance_reference,
            source_evidence_sha256=latest_review.reviewed_source_evidence_sha256,
            definition_sha256=definition.definition_sha256,
            platform=definition.platform,
            policy_version=definition.policy_version,
            catalog_version=definition.catalog_version,
        ) is None:
            raise PolicyReviewError("current trusted source/applicability pin is unavailable")
    else:
        _stale_assignments(db, definition.id)

    changed_at = _utc(now or datetime.now(timezone.utc))
    try:
        definition.enabled = enabled
        append_event(
            db,
            event_type="policy.definition.enabled" if enabled else "policy.definition.disabled",
            actor_issuer=reviewer.issuer,
            actor_subject=reviewer.subject,
            policy_definition_id=definition.id,
            metadata={
                "enabled": enabled,
                "definition_digest": definition.definition_sha256,
                "rationale_digest": "sha256:" + hashlib.sha256(rationale.encode("utf-8")).hexdigest(),
            },
            occurred_at=changed_at,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return definition


def revoke_policy_definition(
    db: Session,
    *,
    definition_id: int,
    rationale: str,
    reviewer: Principal,
    trust_pins: tuple[PolicyTrustPin, ...],
    now: datetime | None = None,
) -> PolicyReviewRecord:
    del trust_pins  # Revocation is a safe denial and remains possible if a pin is withdrawn.
    rationale = _validate_rationale(rationale)
    definition = db.get(PolicyCatalogDefinition, definition_id)
    if definition is None:
        raise PolicyReviewError("policy definition was not found")
    _validate_definition(definition)
    revoked_at = _utc(now or datetime.now(timezone.utc))
    review = PolicyReviewRecord(
        policy_definition_id=definition.id,
        decision="revoked",
        rationale=rationale,
        reviewer_issuer=reviewer.issuer,
        reviewer_subject=reviewer.subject,
        reviewed_definition_sha256=definition.definition_sha256,
        reviewed_source_evidence_sha256=None,
        platform=definition.platform,
        policy_version=definition.policy_version,
        catalog_version=definition.catalog_version,
        provenance_reference=definition.provenance_reference,
        reviewed_at=revoked_at,
    )
    db.add(review)
    try:
        definition.verification_status = "revoked"
        definition.enabled = False
        _stale_assignments(db, definition.id)
        db.flush()
        append_event(
            db,
            event_type="policy.review.revoked",
            actor_issuer=reviewer.issuer,
            actor_subject=reviewer.subject,
            policy_definition_id=definition.id,
            metadata={
                "definition_digest": definition.definition_sha256,
                "rationale_digest": "sha256:" + hashlib.sha256(rationale.encode("utf-8")).hexdigest(),
            },
            occurred_at=revoked_at,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return review


def _stale_assignments(db: Session, definition_id: int) -> None:
    db.execute(
        update(TargetPolicyAssignment)
        .where(TargetPolicyAssignment.definition_id == definition_id)
        .values(state="stale")
    )


def _validate_rationale(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise PolicyReviewError("review rationale is required and must be at most 2048 characters")
    return value.strip()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
