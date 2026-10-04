from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.client import get_agent_status
from app.db.database import get_db
from app.db.models import Target


router = APIRouter(
    prefix="/api/targets",
    tags=["agent-status"],
)


@router.get("/{target_id}/agent-status")
def agent_status(
    target_id: str,
    db: Session = Depends(get_db),
) -> dict:
    target = db.scalar(
        select(Target).where(Target.id == target_id)
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    if not target.address:
        raise HTTPException(
            status_code=400,
            detail="Target has no agent address",
        )

    result = get_agent_status(
        f"http://{target.address}:9000"
    )

    return {
        "target_id": target.id,
        "target_name": target.name,
        "agent": {
            "reachable": result.reachable,
            "agent_id": result.agent_id,
            "status": result.status,
            "error": result.error,
        },
    }
