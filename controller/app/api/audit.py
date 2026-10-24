"""Read-only access to the Controller's append-only audit chain."""

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import verify_chain
from app.auth.oidc import require_audit_read
from app.db.database import get_db
from app.db.models import SecurityAuditEvent


router = APIRouter(prefix="/api/audit", tags=["audit"], dependencies=[Depends(require_audit_read)])


@router.get("/events")
def audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    target_id: str | None = Query(default=None, min_length=1, max_length=36),
    event_type: str | None = Query(default=None, min_length=1, max_length=128),
    db: Session = Depends(get_db),
) -> dict:
    integrity = verify_chain(db)
    statement = select(SecurityAuditEvent).order_by(SecurityAuditEvent.sequence.desc()).limit(limit)
    if target_id:
        statement = statement.where(SecurityAuditEvent.target_id == target_id)
    if event_type:
        statement = statement.where(SecurityAuditEvent.event_type == event_type)
    rows = db.scalars(statement).all()
    return {
        "integrity": {"status": "VALID" if integrity.valid else "INVALID", "event_count": integrity.event_count, "error": integrity.error},
        "events": [
            {
                "sequence": row.sequence,
                "event_id": row.event_id,
                "occurred_at": row.occurred_at.isoformat(),
                "event_type": row.event_type,
                "actor_issuer": row.actor_issuer,
                "actor_subject": row.actor_subject,
                "target_id": row.target_id,
                "agent_id": row.agent_id,
                "metadata": json.loads(row.metadata_json),
                "previous_digest": row.previous_digest,
                "event_digest": row.event_digest,
            }
            for row in rows
        ],
    }
