from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

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
) -> TargetResponse:
    try:
        return create_target(db, data)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.get(
    "",
    response_model=list[TargetResponse],
)
def get_targets(
    db: Session = Depends(get_db),
) -> list[TargetResponse]:
    return list_targets(db)
