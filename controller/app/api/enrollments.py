from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.agents.enrollment import (
    EnrollmentConflict,
    EnrollmentError,
    EnrollmentNotFound,
    EnrollmentStorageUnavailable,
    inspect_enrollment_challenge,
    issue_enrollment_challenge,
    revoke_enrollment_challenge,
)
from app.auth.oidc import Principal, require_enrollment_admin
from app.db.database import get_db
from app.db.models import EnrollmentChallenge


router = APIRouter(prefix="/api/enrollments", tags=["enrollment"])


class EnrollmentCreate(BaseModel):
    target_id: str = Field(min_length=1, max_length=36)
    expected_agent_id: str = Field(min_length=1, max_length=128)
    workload_identity_uri: str = Field(min_length=1, max_length=255)


def _metadata(row: EnrollmentChallenge) -> dict:
    return {
        "enrollment_id": row.enrollment_id,
        "target_id": row.target_id,
        "expected_agent_id": row.expected_agent_id,
        "workload_identity_uri": row.workload_identity_uri,
        "created_at": row.created_at,
        "expires_at": row.expires_at,
        "requester_issuer": row.requester_issuer,
        "requester_subject": row.requester_subject,
        "state": row.state,
        "consumed_at": row.consumed_at,
        "revoked_at": row.revoked_at,
    }


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_enrollment_admin)])
def create_enrollment(
    data: EnrollmentCreate,
    response: Response,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_enrollment_admin),
) -> dict:
    try:
        issued = issue_enrollment_challenge(
            db,
            target_id=data.target_id,
            expected_agent_id=data.expected_agent_id,
            workload_identity_uri=data.workload_identity_uri,
            requester_issuer=principal.issuer,
            requester_subject=principal.subject,
        )
    except EnrollmentNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EnrollmentConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except EnrollmentStorageUnavailable as exc:
        raise HTTPException(status_code=503, detail="Enrollment storage is unavailable") from exc
    except EnrollmentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    body = _metadata(issued.challenge)
    body["bootstrap_token"] = issued.bootstrap_token
    return body


@router.get("/{enrollment_id}", dependencies=[Depends(require_enrollment_admin)])
def get_enrollment(
    enrollment_id: str,
    db: Session = Depends(get_db),
    _principal: Principal = Depends(require_enrollment_admin),
) -> dict:
    try:
        return _metadata(inspect_enrollment_challenge(db, enrollment_id=enrollment_id))
    except EnrollmentNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EnrollmentStorageUnavailable as exc:
        raise HTTPException(status_code=503, detail="Enrollment storage is unavailable") from exc


@router.delete("/{enrollment_id}", dependencies=[Depends(require_enrollment_admin)])
def revoke_enrollment(
    enrollment_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_enrollment_admin),
) -> dict:
    try:
        return _metadata(
            revoke_enrollment_challenge(
                db,
                enrollment_id=enrollment_id,
                actor_issuer=principal.issuer,
                actor_subject=principal.subject,
            )
        )
    except EnrollmentNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except EnrollmentConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except EnrollmentStorageUnavailable as exc:
        raise HTTPException(status_code=503, detail="Enrollment storage is unavailable") from exc
