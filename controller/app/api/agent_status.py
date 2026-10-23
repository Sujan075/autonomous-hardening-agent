import json

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.client import (
    AgentStatusURLConfigurationError,
    get_agent_read_only_bytes,
    get_agent_read_only_payload,
    get_agent_status,
    resolve_agent_status_url,
)
from app.assessments.provenance import (
    ObservationStorageUnavailable,
    store_assessment_observation,
)
from app.db.database import get_db
from app.db.models import Target


router = APIRouter(
    prefix="/api/targets",
    tags=["agent-status"],
)


def _get_target(target_id: str, db: Session) -> Target:
    target = db.scalar(select(Target).where(Target.id == target_id))
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.address:
        raise HTTPException(status_code=400, detail="Target has no agent address")
    return target


def _get_agent_base_url(target: Target) -> str:
    try:
        return resolve_agent_status_url(target.id, target.address)
    except AgentStatusURLConfigurationError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/{target_id}/agent-status")
def agent_status(
    target_id: str,
    db: Session = Depends(get_db),
) -> dict:
    target = _get_target(target_id, db)
    result = get_agent_status(_get_agent_base_url(target))

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


def _proxy_agent_json(target_id: str, db: Session, endpoint: str, payload_name: str) -> dict:
    target = _get_target(target_id, db)
    base_url = _get_agent_base_url(target)
    try:
        payload = get_agent_read_only_payload(base_url, endpoint)
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Agent {endpoint} request failed: {exc}",
        ) from exc

    return {
        "target_id": target.id,
        "target_name": target.name,
        payload_name: payload,
    }


@router.get("/{target_id}/assessment")
def assessment(target_id: str, db: Session = Depends(get_db)) -> dict:
    target = _get_target(target_id, db)
    base_url = _get_agent_base_url(target)
    try:
        raw_payload = get_agent_read_only_bytes(base_url, "assessment")
        observation = store_assessment_observation(
            db,
            target=target,
            raw_payload=raw_payload,
            # There is no Controller-owned policy/catalog registry yet.
            policy_version=None,
            catalog_version=None,
        )
        payload = json.loads(raw_payload.decode("utf-8", errors="strict"))
    except ObservationStorageUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="Assessment was received but could not be stored",
        ) from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Agent assessment could not be validated: {exc}",
        ) from exc

    return {
        "target_id": target.id,
        "target_name": target.name,
        "assessment": payload,
        "assessment_observation_id": observation.observation_id,
        "assessment_trust_status": observation.trust_status,
    }


@router.get("/{target_id}/plan")
def plan(target_id: str, db: Session = Depends(get_db)) -> dict:
    return _proxy_agent_json(target_id, db, "plan", "plan")
