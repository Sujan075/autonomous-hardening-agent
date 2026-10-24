import json

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.agents.client import (
    AgentStatusURLConfigurationError,
    get_agent_read_only_bytes,
    get_agent_read_only_payload,
    get_agent_status,
    resolve_agent_status_url,
    target_agent_transport,
)
from app.agents.mtls import AgentTransportError
from app.auth.oidc import Principal, require_target_read
from app.audit.service import AuditError, append_event
from app.approvals.bindings import parse_assessment_json
from app.assessments.policy import (
    AssessmentPolicyError,
    evaluate_assessment,
    resolve_assessment_policy,
    validate_assessment_matches_policy,
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
    dependencies=[Depends(require_target_read)],
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


def _record_assessment_failure(db: Session, *, target: Target, principal: Principal, reason_code: str) -> bool:
    """Persist a sanitized denial/failure after rolling back any partial work."""
    try:
        db.rollback()
        append_event(
            db,
            event_type="assessment.failed",
            actor_issuer=principal.issuer,
            actor_subject=principal.subject,
            target_id=target.id,
            metadata={"outcome": "failed", "reason_code": reason_code},
        )
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


@router.get("/{target_id}/agent-status")
def agent_status(
    target_id: str,
    db: Session = Depends(get_db),
) -> dict:
    target = _get_target(target_id, db)
    base_url = _get_agent_base_url(target)
    try:
        with target_agent_transport(db, target, base_url) as transport:
            result = get_agent_status(base_url, transport=transport)
    except AgentTransportError as exc:
        raise HTTPException(status_code=502, detail="Agent transport identity validation failed") from exc

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


@router.get("/{target_id}/discovery")
def discovery(target_id: str, db: Session = Depends(get_db)) -> dict:
    """Return the agent's read-only system identity payload through Controller auth."""
    return _proxy_agent_json(target_id, db, "discovery", "discovery")


def _proxy_agent_json(target_id: str, db: Session, endpoint: str, payload_name: str) -> dict:
    target = _get_target(target_id, db)
    base_url = _get_agent_base_url(target)
    try:
        with target_agent_transport(db, target, base_url) as transport:
            payload = get_agent_read_only_payload(base_url, endpoint, transport=transport)
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
def assessment(
    target_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_target_read),
) -> dict:
    target = _get_target(target_id, db)
    base_url = _get_agent_base_url(target)
    try:
        policy = resolve_assessment_policy(db, target=target)
        with target_agent_transport(db, target, base_url) as transport:
            discovery = get_agent_read_only_payload(base_url, "discovery", transport=transport)
            raw_payload = get_agent_read_only_bytes(base_url, "assessment", transport=transport)
            authenticated_peer = transport.authenticated_peer if transport is not None else None
        parse_assessment_json(raw_payload)
        parsed_assessment = validate_assessment_matches_policy(
            policy,
            target=target,
            discovery=discovery,
            raw_assessment=raw_payload,
        )
        policy_evaluation = evaluate_assessment(
            policy,
            parsed_assessment,
            authenticated_peer=authenticated_peer,
        )
        payload = json.loads(raw_payload.decode("utf-8", errors="strict"))
        observation = store_assessment_observation(
            db,
            target=target,
            raw_payload=raw_payload,
            policy_version=policy.assignment.policy_version,
            catalog_version=policy.assignment.catalog_version,
            authenticated_peer=authenticated_peer,
            commit=False,
        )
        append_event(
            db,
            event_type="assessment.collected",
            actor_issuer=principal.issuer,
            actor_subject=principal.subject,
            target_id=target.id,
            agent_id=authenticated_peer.agent_id if authenticated_peer is not None else None,
            policy_definition_id=policy.definition_id,
            metadata={
                "observation_id": observation.observation_id,
                "assessment_digest": observation.payload_sha256,
                "policy_version": policy.assignment.policy_version,
                "catalog_version": policy.assignment.catalog_version,
                "definition_digest": policy.assignment.definition_digest,
                "trust_status": observation.trust_status,
                "finding_count": len(parsed_assessment.findings),
                "policy_decision": policy_evaluation.decision,
                "reported_decision": policy_evaluation.reported_decision,
                "assessment_identity_status": policy_evaluation.identity_status,
            },
        )
        observation_id = observation.observation_id
        observation_trust_status = observation.trust_status
        db.commit()
    except AssessmentPolicyError as exc:
        if not _record_assessment_failure(
            db, target=target, principal=principal, reason_code="policy_or_result_rejected"
        ):
            raise HTTPException(status_code=503, detail="Assessment denial could not be audited") from exc
        raise HTTPException(status_code=409, detail=f"Assessment policy is unavailable: {exc}") from exc
    except ObservationStorageUnavailable as exc:
        _record_assessment_failure(
            db, target=target, principal=principal, reason_code="observation_storage_unavailable"
        )
        raise HTTPException(
            status_code=503,
            detail="Assessment was received but could not be stored",
        ) from exc
    except (AuditError, SQLAlchemyError) as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Assessment could not be committed with its audit event") from exc
    except AgentTransportError as exc:
        if not _record_assessment_failure(
            db, target=target, principal=principal, reason_code="agent_transport_rejected"
        ):
            raise HTTPException(status_code=503, detail="Assessment transport failure could not be audited") from exc
        raise HTTPException(status_code=502, detail="Agent transport identity validation failed") from exc
    except (httpx.HTTPError, ValueError) as exc:
        if not _record_assessment_failure(
            db, target=target, principal=principal, reason_code="agent_assessment_invalid_or_unavailable"
        ):
            raise HTTPException(status_code=503, detail="Assessment failure could not be audited") from exc
        raise HTTPException(
            status_code=502,
            detail="Agent assessment could not be validated",
        ) from exc

    return {
        "target_id": target.id,
        "target_name": target.name,
        "assessment": payload,
        "assessment_observation_id": observation_id,
        "assessment_trust_status": observation_trust_status,
        "policy_status": "reviewed_assignment_matched_to_agent_reported_result",
        "policy": {
            "policy_version": policy.assignment.policy_version,
            "catalog_version": policy.assignment.catalog_version,
            "definition_digest": policy.assignment.definition_digest,
            "platform": policy.assignment.platform,
            "os_version": policy.os_version,
            "architecture": policy.architecture,
            "agent_channel_authenticated": authenticated_peer is not None,
            "planning_recommendations": "available_separately_at_plan_endpoint",
        },
        "policy_evaluation": policy_evaluation.as_dict(),
    }


@router.get("/{target_id}/plan")
def plan(target_id: str, db: Session = Depends(get_db)) -> dict:
    return _proxy_agent_json(target_id, db, "plan", "plan")
