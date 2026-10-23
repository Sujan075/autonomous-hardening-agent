"""Durable, append-only storage and resolution for Controller observations.

Stored payload hashes detect accidental or unauthorized content changes when a
record is read. They are not signatures, authenticated provenance, or a
tamper-evident audit log.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import hmac

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.approvals.bindings import (
    Assessment,
    AssessmentRecord,
    BindingValidationError,
    ControllerTargetContext,
    EvidenceOrigin,
    Timestamp,
    build_evidence_record,
    evidence_digest,
    parse_assessment_json,
)
from app.db.models import AssessmentObservation, AssessmentObservationTrust, Target


PAYLOAD_SCHEMA_VERSION = "agent-assessment-json/v1"
COLLECTION_SOURCE = "controller-agent-assessment-http"


class ObservationError(ValueError):
    """Base class for rejected or unavailable observation operations."""


class ObservationNotFound(ObservationError):
    """The Controller-issued observation ID does not exist."""


class ObservationRejected(ObservationError):
    """An observation does not match the requested target or integrity checks."""


class ObservationStorageUnavailable(ObservationError):
    """The observation database could not complete the requested operation."""


class ObservationTrustState(StrEnum):
    CONTROLLER_OBSERVED_UNAUTHENTICATED = "controller_observed_unauthenticated"
    AUTHENTICATED_AGENT_TARGET_BOUND = "authenticated_agent_target_bound"
    APPROVAL_PROVENANCE_VERIFIED = "approval_provenance_verified"
    UNRESOLVED_UNTRUSTED = "unresolved_untrusted"


@dataclass(frozen=True)
class SupportedBindingVersions:
    """Controller-owned allowlist; empty defaults mean no version is approved."""

    policy_versions: frozenset[str] = frozenset()
    catalog_versions: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ResolvedAssessmentObservation:
    observation_id: str
    target_id: str
    observation_state: ObservationTrustState
    approval_state: ObservationTrustState
    assessment: Assessment
    evidence_digest: str | None
    assessment_record: AssessmentRecord | None
    approval_context: None = None
    unresolved_reason: str | None = None


def store_assessment_observation(
    db: Session,
    *,
    target: Target,
    raw_payload: str | bytes,
    collection_source: str = COLLECTION_SOURCE,
    policy_version: str | None = None,
    catalog_version: str | None = None,
    reported_agent_id: str | None = None,
    collected_at: datetime | None = None,
) -> AssessmentObservation:
    """Validate and append an agent response under Controller target context.

    Trust status is assigned here, never accepted from the caller or payload.
    The current HTTP path cannot establish agent identity, so every collected
    record remains explicitly unauthenticated.
    """
    try:
        if not isinstance(target, Target):
            raise ObservationRejected("assessment target must come from Controller storage")
        persisted_target = db.get(Target, target.id)
        if persisted_target is None:
            raise ObservationRejected("assessment target is not a persisted Controller target")
        target_context = ControllerTargetContext.from_target(persisted_target)
        target_context.validate()
        assessment = parse_assessment_json(raw_payload)
        if assessment.platform != target_context.platform:
            raise ObservationRejected("assessment platform does not match Controller target")
        _optional_version(policy_version, "policy version")
        _optional_version(catalog_version, "catalog version")
        _required_source(collection_source)
        if reported_agent_id is not None:
            _optional_version(reported_agent_id, "reported agent ID")
        when = _normalize_datetime(collected_at or datetime.now(timezone.utc))
        raw_bytes = _utf8_bytes(raw_payload)
        row = AssessmentObservation(
            target_id=target_context.target_id,
            collected_at=when,
            platform=assessment.platform,
            policy_version=policy_version,
            catalog_version=catalog_version,
            payload_schema_version=PAYLOAD_SCHEMA_VERSION,
            assessment_json=raw_bytes.decode("utf-8"),
            payload_sha256=_payload_digest(raw_bytes),
            collection_source=collection_source,
            reported_agent_id=reported_agent_id,
            target_binding_generation=target_context.binding_generation,
            trust_status=AssessmentObservationTrust.CONTROLLER_OBSERVED_UNAUTHENTICATED.value,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row
    except BindingValidationError as exc:
        raise ObservationRejected(str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise ObservationStorageUnavailable("assessment observation storage is unavailable") from exc


def resolve_assessment_observation(
    db: Session,
    *,
    observation_id: str,
    target: Target,
    now: datetime,
    max_age: timedelta,
    versions: SupportedBindingVersions,
    expected_policy_version: str | None,
    expected_catalog_version: str | None,
    require_latest: bool = True,
) -> ResolvedAssessmentObservation:
    """Resolve a persisted observation, verify its digest and recompute evidence.

    Even when versioned evidence can be recomputed, this returns no approval
    context while channel identity and target binding generation are absent.
    """
    try:
        if not isinstance(target, Target):
            raise ObservationRejected("target must come from Controller storage")
        persisted_target = db.get(Target, target.id)
        if persisted_target is None:
            raise ObservationRejected("target is not a persisted Controller target")
        target_context = ControllerTargetContext.from_target(persisted_target)
        target_context.validate()
        row = db.scalar(
            select(AssessmentObservation).where(
                AssessmentObservation.observation_id == observation_id
            )
        )
        if row is None:
            raise ObservationNotFound("assessment observation was not found")
        if row.target_id != target_context.target_id:
            raise ObservationRejected("assessment observation belongs to another target")
        if row.platform != target_context.platform:
            raise ObservationRejected("assessment platform does not match current target")
        if row.payload_schema_version != PAYLOAD_SCHEMA_VERSION:
            raise ObservationRejected("assessment payload schema version is unsupported")
        if row.trust_status != AssessmentObservationTrust.CONTROLLER_OBSERVED_UNAUTHENTICATED.value:
            raise ObservationRejected("assessment trust status is unsupported")

        raw_bytes = _utf8_bytes(row.assessment_json)
        if not hmac.compare_digest(_payload_digest(raw_bytes), row.payload_sha256):
            raise ObservationRejected("stored assessment payload integrity check failed")
        try:
            assessment = parse_assessment_json(raw_bytes)
        except BindingValidationError as exc:
            raise ObservationRejected("stored assessment payload is malformed") from exc
        if assessment.platform != row.platform:
            raise ObservationRejected("stored assessment platform is inconsistent")

        observed_at = _normalize_datetime(row.collected_at)
        current_time = _normalize_datetime(now)
        if not isinstance(max_age, timedelta) or max_age <= timedelta(0):
            raise ObservationRejected("maximum observation age must be positive")
        age = current_time - observed_at
        if age < timedelta(0) or age > max_age:
            raise ObservationRejected("assessment observation is future-dated or stale")
        if (
            target_context.binding_generation is not None
            and row.target_binding_generation != target_context.binding_generation
        ):
            raise ObservationRejected("assessment observation belongs to a replaced target binding")
        if require_latest:
            latest = db.scalar(
                select(AssessmentObservation)
                .where(AssessmentObservation.target_id == target_context.target_id)
                .order_by(AssessmentObservation.collected_at.desc(), AssessmentObservation.id.desc())
                .limit(1)
            )
            if latest is None or latest.observation_id != row.observation_id:
                raise ObservationRejected("assessment observation has been replaced by a newer observation")

        unresolved = _version_gap_or_reject(
            row,
            versions,
            expected_policy_version,
            expected_catalog_version,
        )
        if unresolved is not None:
            return ResolvedAssessmentObservation(
                observation_id=row.observation_id,
                target_id=target_context.target_id,
                observation_state=ObservationTrustState.CONTROLLER_OBSERVED_UNAUTHENTICATED,
                approval_state=ObservationTrustState.UNRESOLVED_UNTRUSTED,
                assessment=assessment,
                evidence_digest=None,
                assessment_record=None,
                unresolved_reason=unresolved,
            )

        record = build_evidence_record(
            target=target_context,
            assessment_id=row.observation_id,
            source=row.collection_source,
            catalog_version=row.catalog_version,
            collected_at=Timestamp.from_datetime(observed_at),
            origin=EvidenceOrigin.CONTROLLER_CAPTURED_UNAUTHENTICATED,
            assessment=assessment,
            binding_generation=row.target_binding_generation,
            # Agent identity is stored only as a report and never promoted here.
            agent_id=None,
        )
        digest = evidence_digest(record.provenance, record.assessment)
        return ResolvedAssessmentObservation(
            observation_id=row.observation_id,
            target_id=target_context.target_id,
            observation_state=ObservationTrustState.CONTROLLER_OBSERVED_UNAUTHENTICATED,
            approval_state=ObservationTrustState.UNRESOLVED_UNTRUSTED,
            assessment=assessment,
            evidence_digest=digest,
            assessment_record=record,
            unresolved_reason="authenticated agent identity and target binding are not implemented",
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise ObservationStorageUnavailable("assessment observation storage is unavailable") from exc
    except BindingValidationError as exc:
        raise ObservationRejected("assessment provenance is invalid") from exc


def _version_gap_or_reject(
    row: AssessmentObservation,
    versions: SupportedBindingVersions,
    expected_policy_version: str | None,
    expected_catalog_version: str | None,
) -> str | None:
    if not isinstance(versions, SupportedBindingVersions):
        raise ObservationRejected("Controller policy/catalog registry is unavailable")
    if not expected_policy_version or not expected_catalog_version:
        return "Controller policy/catalog provenance is unavailable"
    if expected_policy_version not in versions.policy_versions:
        raise ObservationRejected("policy version is unknown to the Controller")
    if expected_catalog_version not in versions.catalog_versions:
        raise ObservationRejected("catalog version is unknown to the Controller")
    if row.policy_version is None or row.catalog_version is None:
        return "observation lacks policy/catalog provenance"
    if row.policy_version != expected_policy_version or row.catalog_version != expected_catalog_version:
        raise ObservationRejected("observation policy/catalog provenance does not match expected versions")
    return None


def _payload_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _utf8_bytes(raw: str | bytes) -> bytes:
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="strict")
    raise ObservationRejected("assessment payload must be UTF-8 text or bytes")


def _normalize_datetime(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        raise ObservationRejected("observation timestamp must be a datetime")
    return value.astimezone(timezone.utc)


def _required_source(value: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ObservationRejected("collection source is missing or too long")


def _optional_version(value: str | None, label: str) -> None:
    if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 128):
        raise ObservationRejected(f"{label} is invalid")
