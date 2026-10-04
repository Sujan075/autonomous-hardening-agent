from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Target
from app.schemas.target import TargetCreate


def create_target(db: Session, data: TargetCreate) -> Target:
    existing = db.scalar(
        select(Target).where(Target.name == data.name)
    )

    if existing is not None:
        raise ValueError("Target with this name already exists")

    target = Target(
        name=data.name,
        platform=data.platform,
        address=data.address,
        status="REGISTERED",
    )

    db.add(target)
    db.commit()
    db.refresh(target)

    return target


def list_targets(db: Session) -> list[Target]:
    return list(
        db.scalars(
            select(Target).order_by(Target.created_at.desc())
        ).all()
    )
