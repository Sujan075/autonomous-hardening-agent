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
from app.agents.mtls import AuthenticatedAgentPeer, is_verified_agent_peer
from app.db.models import (
    AgentCredential,
    AgentCredentialState,
    AgentIdentity,
    AgentIdentityState,
    AssessmentObservation,
    AssessmentObservationTrust,
    Target,
    TargetAgentBinding,
)
from app.policies.registry import RegistryError, resolve_target_assignment


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
    authenticated_peer: AuthenticatedAgentPeer | None = None,
    collected_at: datetime | None = None,
    commit: bool = True,
) -> AssessmentObservation:
    """Validate and append an agent response under Controller target context.

    Trust status is assigned here, never accepted from the caller or payload.
    A verified mTLS peer can establish channel identity only when it still
    matches the Controller's active target binding. This does not establish
    assessment provenance or approval authorization.
    """
    try:
        if not isinstance(target, Target):
            raise ObservationRejected("assessment target must come from Controller storage")
        persisted_target = db.get(Target, target.id)
        if persisted_target is None:
            raise ObservationRejected("assessment target is not a persisted Controller target")
        target_context = ControllerTargetContext.from_target(persisted_target)
        target_context.validate()
        when = _normalize_datetime(collected_at or datetime.now(timezone.utc))
        active_binding = _current_binding(db, target_context.target_id, datetime.now(timezone.utc))
        if active_binding is not None:
            target_context = ControllerTargetContext(
                target_id=target_context.target_id,
                platform=target_context.platform,
                binding_generation=active_binding.generation,
                agent_id=active_binding.agent_id,
            )
        assessment = parse_assessment_json(raw_payload)
        if assessment.platform != target_context.platform:
            raise ObservationRejected("assessment platform does not match Controller target")
        _optional_version(policy_version, "policy version")
        _optional_version(catalog_version, "catalog version")
        _required_source(collection_source)
        if reported_agent_id is not None:
            _optional_version(reported_agent_id, "reported agent ID")
        trust_status = AssessmentObservationTrust.CONTROLLER_OBSERVED_UNAUTHENTICATED.value
        authenticated_agent_id = None
        authenticated_fingerprint = None
        if authenticated_peer is not None:
            if (
                not is_verified_agent_peer(authenticated_peer)
                or active_binding is None
                or authenticated_peer.target_id != target_context.target_id
                or authenticated_peer.agent_id != active_binding.agent_id
                or authenticated_peer.binding_generation != active_binding.generation
                or authenticated_peer.credential_id != active_binding.credential_id
            ):
                raise ObservationRejected("authenticated peer does not match the current target binding")
            credential = db.get(AgentCredential, authenticated_peer.credential_id)
            if (
                credential is None
                or credential.agent_id != active_binding.agent_id
                or credential.state != AgentCredentialState.ACTIVE.value
                or credential.revoked_at is not None
                or credential.fingerprint_sha256 != authenticated_peer.certificate_fingerprint
                or credential.identity_uri != authenticated_peer.identity_uri
                or datetime.now(timezone.utc) < _normalize_datetime(credential.not_before)
                or datetime.now(timezone.utc) >= _normalize_datetime(credential.expires_at)
            ):
                raise ObservationRejected("authenticated peer credential is no longer active")
            authenticated_agent_id = active_binding.agent_id
            authenticated_fingerprint = credential.fingerprint_sha256
            trust_status = AssessmentObservationTrust.AUTHENTICATED_AGENT_TARGET_BOUND.value
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
            authenticated_agent_id=authenticated_agent_id,
            authenticated_credential_fingerprint=authenticated_fingerprint,
            target_binding_generation=(
                target_context.binding_generation
                or (active_binding.generation if active_binding is not None else None)
            ),
            trust_status=trust_status,
        )
        db.add(row)
        db.flush()
        if commit:
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
        active_binding = _current_binding(db, target_context.target_id, now)
        if active_binding is not None:
            target_context = ControllerTargetContext(
                target_id=target_context.target_id,
                platform=target_context.platform,
                binding_generation=active_binding.generation,
                agent_id=active_binding.agent_id,
            )
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
        if row.trust_status not in {
            AssessmentObservationTrust.CONTROLLER_OBSERVED_UNAUTHENTICATED.value,
            AssessmentObservationTrust.AUTHENTICATED_AGENT_TARGET_BOUND.value,
        }:
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
        current_generation = target_context.binding_generation or (
            active_binding.generation if active_binding is not None else None
        )
        if row.target_binding_generation != current_generation:
            raise ObservationRejected("assessment observation belongs to a replaced target binding")
        observation_state = ObservationTrustState(row.trust_status)
        if observation_state == ObservationTrustState.AUTHENTICATED_AGENT_TARGET_BOUND:
            if (
                active_binding is None
                or row.authenticated_agent_id != active_binding.agent_id
                or row.authenticated_credential_fingerprint is None
            ):
                raise ObservationRejected("authenticated observation no longer matches the active binding")
            credential = db.scalar(
                select(AgentCredential).where(
                    AgentCredential.agent_id == active_binding.agent_id,
                    AgentCredential.fingerprint_sha256 == row.authenticated_credential_fingerprint,
                    AgentCredential.state == AgentCredentialState.ACTIVE.value,
                    AgentCredential.revoked_at.is_(None),
                )
            )
            if credential is None or credential.id != active_binding.credential_id:
                raise ObservationRejected("authenticated observation credential is no longer active")
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
                observation_state=observation_state,
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
            observation_state=observation_state,
            approval_state=ObservationTrustState.UNRESOLVED_UNTRUSTED,
            assessment=assessment,
            evidence_digest=digest,
            assessment_record=record,
            unresolved_reason=(
                "authenticated agent identity is channel-bound, but authenticated transport "
                "does not establish assessment provenance or approval authorization"
            ),
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise ObservationStorageUnavailable("assessment observation storage is unavailable") from exc
    except BindingValidationError as exc:
        raise ObservationRejected("assessment provenance is invalid") from exc


def resolve_assigned_assessment_observation(
    db: Session,
    *,
    observation_id: str,
    target: Target,
    now: datetime,
    max_age: timedelta,
) -> ResolvedAssessmentObservation:
    """Resolve evidence using versions assigned by Controller-owned records.

    No agent-supplied version string participates in this path. Missing or
    unverified assignment remains unresolved and cannot produce an evidence
    digest or approval context.
    """
    try:
        assignment = resolve_target_assignment(db, target_id=target.id)
    except RegistryError:
        return resolve_assessment_observation(
            db,
            observation_id=observation_id,
            target=target,
            now=now,
            max_age=max_age,
            versions=SupportedBindingVersions(),
            expected_policy_version=None,
            expected_catalog_version=None,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise ObservationStorageUnavailable("assessment observation storage is unavailable") from exc
    return resolve_assessment_observation(
        db,
        observation_id=observation_id,
        target=target,
        now=now,
        max_age=max_age,
        versions=SupportedBindingVersions(
            frozenset({assignment.policy_version}),
            frozenset({assignment.catalog_version}),
        ),
        expected_policy_version=assignment.policy_version,
        expected_catalog_version=assignment.catalog_version,
    )


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


def _current_binding(db: Session, target_id: str, now: datetime) -> TargetAgentBinding | None:
    binding = db.scalar(
        select(TargetAgentBinding).where(
            TargetAgentBinding.target_id == target_id,
            TargetAgentBinding.state == "active",
        )
    )
    if binding is None:
        return None
    identity = db.get(AgentIdentity, binding.agent_id)
    credential = db.get(AgentCredential, binding.credential_id)
    current = _normalize_datetime(now)
    if (
        identity is None
        or identity.state != AgentIdentityState.ACTIVE.value
        or credential is None
        or credential.agent_id != binding.agent_id
        or credential.state != AgentCredentialState.ACTIVE.value
        or credential.revoked_at is not None
        or current < _normalize_datetime(credential.not_before)
        or current >= _normalize_datetime(credential.expires_at)
    ):
        return None
    return binding


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
