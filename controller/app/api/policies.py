from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit.service import AuditError
from app.auth.oidc import Principal, require_policy_review
from app.db.database import get_db
from app.db.models import PolicyReviewRecord
from app.policies.registry import RegistryError
from app.policies.review import (
    PolicyReviewError,
    review_policy_definition,
    revoke_policy_definition,
    set_policy_enabled,
)
from app.policies.trust import PolicyTrustConfigurationError, load_policy_trust_pins


router = APIRouter(prefix="/api/policies", tags=["policy-review"])


class PolicyReviewRequest(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    rationale: str = Field(min_length=1, max_length=2048)
    source_evidence_sha256: str | None = Field(default=None, max_length=71)


class PolicyStateRequest(BaseModel):
    enabled: bool
    rationale: str = Field(min_length=1, max_length=2048)


class PolicyRevocationRequest(BaseModel):
    rationale: str = Field(min_length=1, max_length=2048)


def _optional_trust_pins(*, required: bool):
    try:
        return load_policy_trust_pins()
    except PolicyTrustConfigurationError as exc:
        if required:
            raise HTTPException(status_code=503, detail="Policy trust verification is not configured") from exc
        return ()


def _review_response(row: PolicyReviewRecord) -> dict:
    return {
        "review_id": row.id,
        "policy_definition_id": row.policy_definition_id,
        "decision": row.decision,
        "reviewer_issuer": row.reviewer_issuer,
        "reviewer_subject": row.reviewer_subject,
        "reviewed_definition_sha256": row.reviewed_definition_sha256,
        "reviewed_source_evidence_sha256": row.reviewed_source_evidence_sha256,
        "platform": row.platform,
        "policy_version": row.policy_version,
        "catalog_version": row.catalog_version,
        "provenance_reference": row.provenance_reference,
        "reviewed_at": row.reviewed_at,
    }


def _raise_review_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AuditError):
        return HTTPException(status_code=503, detail="Security audit storage is unavailable")
    if isinstance(exc, (RegistryError, PolicyReviewError)):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=503, detail="Policy review storage is unavailable")


@router.post("/{definition_id}/review", dependencies=[Depends(require_policy_review)])
def review_policy(
    definition_id: int,
    data: PolicyReviewRequest,
    db: Session = Depends(get_db),
    reviewer: Principal = Depends(require_policy_review),
) -> dict:
    pins = _optional_trust_pins(required=data.decision == "approved")
    try:
        row = review_policy_definition(
            db,
            definition_id=definition_id,
            decision=data.decision,
            rationale=data.rationale,
            source_evidence_sha256=data.source_evidence_sha256,
            reviewer=reviewer,
            trust_pins=pins,
        )
        return _review_response(row)
    except (AuditError, RegistryError, PolicyReviewError) as exc:
        db.rollback()
        raise _raise_review_error(exc) from exc


@router.post("/{definition_id}/state", dependencies=[Depends(require_policy_review)])
def change_policy_state(
    definition_id: int,
    data: PolicyStateRequest,
    db: Session = Depends(get_db),
    reviewer: Principal = Depends(require_policy_review),
) -> dict:
    pins = _optional_trust_pins(required=data.enabled)
    try:
        row = set_policy_enabled(
            db,
            definition_id=definition_id,
            enabled=data.enabled,
            rationale=data.rationale,
            reviewer=reviewer,
            trust_pins=pins,
        )
        return {
            "policy_definition_id": row.id,
            "enabled": row.enabled,
            "verification_status": row.verification_status,
            "applicability_status": row.applicability_status,
        }
    except (AuditError, RegistryError, PolicyReviewError) as exc:
        db.rollback()
        raise _raise_review_error(exc) from exc


@router.post("/{definition_id}/revoke", dependencies=[Depends(require_policy_review)])
def revoke_policy(
    definition_id: int,
    data: PolicyRevocationRequest,
    db: Session = Depends(get_db),
    reviewer: Principal = Depends(require_policy_review),
) -> dict:
    pins = _optional_trust_pins(required=False)
    try:
        row = revoke_policy_definition(
            db,
            definition_id=definition_id,
            rationale=data.rationale,
            reviewer=reviewer,
            trust_pins=pins,
        )
        return _review_response(row)
    except (AuditError, RegistryError, PolicyReviewError) as exc:
        db.rollback()
        raise _raise_review_error(exc) from exc
