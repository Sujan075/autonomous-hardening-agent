"""Read-only APIs for explicitly labelled local demo records."""

import json
import os

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.oidc import require_target_read
from app.db.database import get_db
from app.db.models import DemoDecoyEvent, SandboxRemediationRun


router = APIRouter(prefix="/api/demo", tags=["local-demo"])


def _require_demo_read() -> None:
    if os.environ.get("AHA_ENABLE_DEMO_READ_API", "").strip() != "1":
        raise HTTPException(status_code=404, detail="Local demo read API is disabled")


@router.get("/remediation-runs", dependencies=[Depends(require_target_read)])
def remediation_runs(
    limit: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db),
) -> dict:
    _require_demo_read()
    rows = db.scalars(select(SandboxRemediationRun).order_by(SandboxRemediationRun.recorded_at.desc()).limit(limit)).all()
    return {
        "classification": "LOCAL_SANDBOX_ONLY",
        "runs": [
            {
                "run_id": row.run_id,
                "target_id": row.target_id,
                "platform": row.platform,
                "scenario": row.scenario,
                "status": row.status,
                "sandbox_only": row.sandbox_only,
                "test_only_trust": row.test_only_trust,
                "live_target_modified": row.live_target_modified,
                "recorded_at": row.recorded_at.isoformat(),
                "result": json.loads(row.result_json),
            }
            for row in rows
        ],
    }


@router.get("/decoy-events", dependencies=[Depends(require_target_read)])
def decoy_events(
    limit: int = Query(default=100, ge=1, le=500),
    batch_id: str | None = Query(default=None, min_length=1, max_length=36),
    category: str | None = Query(default=None, min_length=1, max_length=64),
    db: Session = Depends(get_db),
) -> dict:
    _require_demo_read()
    statement = select(DemoDecoyEvent).order_by(DemoDecoyEvent.occurred_at.desc()).limit(limit)
    if batch_id:
        statement = statement.where(DemoDecoyEvent.batch_id == batch_id)
    if category:
        statement = statement.where(DemoDecoyEvent.category == category)
    rows = db.scalars(statement).all()
    return {
        "classification": "SIMULATED",
        "active_listener_count": 0,
        "decoys": [{"decoy_id": "loopback-decoy-simulator", "mode": "SIMULATED", "listener": "none", "executor_connected": False}],
        "count": len(rows),
        "events": [
            {
                "event_id": row.event_id,
                "batch_id": row.batch_id,
                "decoy_id": row.decoy_id,
                "occurred_at": row.occurred_at.isoformat(),
                "category": row.category,
                "source_address": row.source_address,
                "source_classification": row.source_classification,
                "correlation_id": row.correlation_id,
                "outcome": row.outcome,
                "simulation_mode": row.simulation_mode,
            }
            for row in rows
        ],
    }
