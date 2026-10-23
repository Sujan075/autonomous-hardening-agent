from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit.service import AuditError, append_event
from app.auth.oidc import require_target_admin, require_target_read
from app.db.database import get_db
from app.schemas.target import TargetCreate, TargetResponse
from app.targets.manager import create_target, list_targets


router = APIRouter(
    prefix="/api/targets",
    tags=["targets"],
)


@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_target(
    data: TargetCreate,
    db: Session = Depends(get_db),
    _principal=Depends(require_target_admin),
) -> TargetResponse:
    try:
        target = create_target(db, data)
        response = TargetResponse.model_validate(target)
        append_event(
            db,
            event_type="target.registered",
            actor_issuer=_principal.issuer,
            actor_subject=_principal.subject,
            target_id=target.id,
            metadata={"platform": target.platform, "status": target.status},
        )
        db.commit()
        return response
    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except (AuditError, SQLAlchemyError) as exc:
        db.rollback()
        if isinstance(exc, IntegrityError):
            raise HTTPException(status_code=409, detail="Target registration conflicts with existing data") from exc
        raise HTTPException(status_code=503, detail="Target registration or audit storage is unavailable") from exc


@router.get(
    "",
    response_model=list[TargetResponse],
)
def get_targets(
    db: Session = Depends(get_db),
    _principal=Depends(require_target_read),
) -> list[TargetResponse]:
    return list_targets(db)
