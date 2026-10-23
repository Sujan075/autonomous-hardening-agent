"""Persisted one-time enrollment challenges; never activates agent credentials."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import hmac
import secrets
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit.service import AuditError, append_event
from app.db.models import (
    AgentCredential,
    AgentIdentity,
    AgentIdentityState,
    EnrollmentChallenge,
    EnrollmentChallengeState,
    Target,
    TargetAgentBinding,
)


CHALLENGE_TTL = timedelta(minutes=15)
TOKEN_BYTES = 32


class EnrollmentError(ValueError):
    """Enrollment operation denied or invalid."""


class EnrollmentConflict(EnrollmentError):
    """An enrollment or target/agent identity already exists."""


class EnrollmentNotFound(EnrollmentError):
    """Enrollment ID is unknown."""


class EnrollmentExpired(EnrollmentError):
    """Enrollment challenge has expired."""


class EnrollmentStorageUnavailable(RuntimeError):
    """Enrollment transaction could not be persisted."""


@dataclass(frozen=True)
class IssuedEnrollment:
    challenge: EnrollmentChallenge
    bootstrap_token: str = field(repr=False)


def _database_guard(function):
    @wraps(function)
    def guarded(db: Session, *args, **kwargs):
        try:
            return function(db, *args, **kwargs)
        except AuditError as exc:
            db.rollback()
            raise EnrollmentStorageUnavailable("enrollment audit storage is unavailable") from exc
        except SQLAlchemyError as exc:
            db.rollback()
            raise EnrollmentStorageUnavailable("enrollment storage is unavailable") from exc

    return guarded


@_database_guard
def issue_enrollment_challenge(
    db: Session,
    *,
    target_id: str,
    expected_agent_id: str,
    workload_identity_uri: str,
    requester_issuer: str,
    requester_subject: str,
    now: datetime | None = None,
) -> IssuedEnrollment:
    current = _aware(now or datetime.now(timezone.utc))
    _required(target_id, "target ID", 36)
    _required(expected_agent_id, "expected agent ID", 128)
    _required(workload_identity_uri, "agent workload identity URI", 255)
    _required(requester_issuer, "requester issuer", 512)
    _required(requester_subject, "requester subject", 512)
    parsed = urlsplit(workload_identity_uri)
    if not parsed.scheme or not parsed.netloc or parsed.query or parsed.fragment:
        raise EnrollmentError("agent workload identity must be an absolute URI without query or fragment")
    if db.get(Target, target_id) is None:
        raise EnrollmentNotFound("target is not registered")
    active_binding = db.scalar(
        select(TargetAgentBinding).where(
            TargetAgentBinding.target_id == target_id,
            TargetAgentBinding.state == "active",
        )
    )
    if active_binding is not None:
        raise EnrollmentConflict("target already has an active agent binding")

    identity = db.get(AgentIdentity, expected_agent_id)
    if identity is not None:
        if (
            identity.state != AgentIdentityState.PENDING.value
            or identity.workload_identity_uri != workload_identity_uri
            or db.scalar(
                select(AgentCredential.id).where(
                    AgentCredential.agent_id == expected_agent_id,
                    AgentCredential.state.in_(("active", "pending")),
                )
            ) is not None
        ):
            raise EnrollmentConflict("agent identity already exists or is not an unused pending identity")
    else:
        identity = AgentIdentity(
            agent_id=expected_agent_id,
            workload_identity_uri=workload_identity_uri,
            state=AgentIdentityState.PENDING.value,
            created_at=current,
            updated_at=current,
        )
        db.add(identity)

    raw_token = secrets.token_urlsafe(TOKEN_BYTES)
    token_hash = _token_digest(raw_token)
    challenge = EnrollmentChallenge(
        enrollment_id=str(uuid4()),
        target_id=target_id,
        expected_agent_id=expected_agent_id,
        workload_identity_uri=workload_identity_uri,
        created_at=current,
        expires_at=current + CHALLENGE_TTL,
        requester_issuer=requester_issuer,
        requester_subject=requester_subject,
        bootstrap_token_sha256=token_hash,
        state=EnrollmentChallengeState.PENDING.value,
    )
    db.add(challenge)
    try:
        db.flush()
        append_event(
            db,
            event_type="enrollment.challenge.created",
            actor_issuer=requester_issuer,
            actor_subject=requester_subject,
            target_id=target_id,
            agent_id=expected_agent_id,
            enrollment_id=challenge.enrollment_id,
            metadata={
                "workload_identity_uri": workload_identity_uri,
                "expires_at": challenge.expires_at.isoformat(),
            },
            occurred_at=current,
        )
        db.commit()
        return IssuedEnrollment(challenge=challenge, bootstrap_token=raw_token)
    except IntegrityError as exc:
        db.rollback()
        raise EnrollmentConflict("target/agent enrollment already exists or conflicts") from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise EnrollmentStorageUnavailable("enrollment storage is unavailable") from exc


@_database_guard
def consume_enrollment_challenge(
    db: Session,
    *,
    enrollment_id: str,
    bootstrap_token: str,
    now: datetime | None = None,
) -> EnrollmentChallenge:
    """Atomically consume a challenge after secret possession is demonstrated.

    This service primitive does not verify key possession, issue a certificate,
    activate an identity, or create an active target binding.
    """
    current = _aware(now or datetime.now(timezone.utc))
    _required(enrollment_id, "enrollment ID", 36)
    if not isinstance(bootstrap_token, str) or not bootstrap_token or len(bootstrap_token) > 256:
        raise EnrollmentError("bootstrap token is invalid")
    row = db.scalar(
        select(EnrollmentChallenge).where(EnrollmentChallenge.enrollment_id == enrollment_id)
    )
    if row is None:
        raise EnrollmentNotFound("enrollment challenge was not found")
    if row.state != EnrollmentChallengeState.PENDING.value:
        raise EnrollmentConflict("enrollment challenge is no longer pending")
    if current >= _aware(row.expires_at, database_value=True):
        result = db.execute(
            update(EnrollmentChallenge)
            .where(
                EnrollmentChallenge.id == row.id,
                EnrollmentChallenge.state == EnrollmentChallengeState.PENDING.value,
            )
            .values(state=EnrollmentChallengeState.EXPIRED.value)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            append_event(
                db,
                event_type="enrollment.challenge.expired",
                target_id=row.target_id,
                agent_id=row.expected_agent_id,
                enrollment_id=row.enrollment_id,
            metadata={"expired_at": current.isoformat()},
                occurred_at=current,
            )
        db.commit()
        raise EnrollmentExpired("enrollment challenge has expired")
    if not hmac.compare_digest(_token_digest(bootstrap_token), row.bootstrap_token_sha256):
        raise EnrollmentError("bootstrap token is invalid")

    result = db.execute(
        update(EnrollmentChallenge)
        .where(
            EnrollmentChallenge.id == row.id,
            EnrollmentChallenge.state == EnrollmentChallengeState.PENDING.value,
            EnrollmentChallenge.expires_at > current,
            EnrollmentChallenge.bootstrap_token_sha256 == _token_digest(bootstrap_token),
        )
        .values(
            state=EnrollmentChallengeState.CONSUMED.value,
            consumed_at=current,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise EnrollmentConflict("enrollment challenge was already consumed or changed")
    try:
        append_event(
            db,
            event_type="enrollment.challenge.consumed",
            target_id=row.target_id,
            agent_id=row.expected_agent_id,
            enrollment_id=row.enrollment_id,
            metadata={"consumed_at": current.isoformat(), "identity_authenticated": False},
            occurred_at=current,
        )
        db.commit()
        db.refresh(row)
        return row
    except SQLAlchemyError as exc:
        db.rollback()
        raise EnrollmentStorageUnavailable("enrollment storage is unavailable") from exc


@_database_guard
def inspect_enrollment_challenge(
    db: Session, *, enrollment_id: str, now: datetime | None = None
) -> EnrollmentChallenge:
    current = _aware(now or datetime.now(timezone.utc))
    row = db.scalar(
        select(EnrollmentChallenge).where(EnrollmentChallenge.enrollment_id == enrollment_id)
    )
    if row is None:
        raise EnrollmentNotFound("enrollment challenge was not found")
    if row.state == EnrollmentChallengeState.PENDING.value and current >= _aware(row.expires_at, database_value=True):
        result = db.execute(
            update(EnrollmentChallenge)
            .where(
                EnrollmentChallenge.id == row.id,
                EnrollmentChallenge.state == EnrollmentChallengeState.PENDING.value,
                EnrollmentChallenge.expires_at <= current,
            )
            .values(state=EnrollmentChallengeState.EXPIRED.value)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            append_event(
                db,
                event_type="enrollment.challenge.expired",
                target_id=row.target_id,
                agent_id=row.expected_agent_id,
                enrollment_id=row.enrollment_id,
                metadata={"expired_at": current.isoformat()},
                occurred_at=current,
            )
        db.commit()
        if result.rowcount == 1:
            row.state = EnrollmentChallengeState.EXPIRED.value
        else:
            row = db.scalar(
                select(EnrollmentChallenge)
                .where(EnrollmentChallenge.id == row.id)
                .execution_options(populate_existing=True)
            )
    return row


@_database_guard
def revoke_enrollment_challenge(
    db: Session,
    *,
    enrollment_id: str,
    actor_issuer: str | None = None,
    actor_subject: str | None = None,
    now: datetime | None = None,
) -> EnrollmentChallenge:
    current = _aware(now or datetime.now(timezone.utc))
    row = inspect_enrollment_challenge(db, enrollment_id=enrollment_id, now=current)
    if row.state != EnrollmentChallengeState.PENDING.value:
        raise EnrollmentConflict("only a pending enrollment challenge can be revoked")
    result = db.execute(
        update(EnrollmentChallenge)
        .where(
            EnrollmentChallenge.id == row.id,
            EnrollmentChallenge.state == EnrollmentChallengeState.PENDING.value,
            EnrollmentChallenge.expires_at > current,
        )
        .values(
            state=EnrollmentChallengeState.REVOKED.value,
            revoked_at=current,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise EnrollmentConflict("enrollment challenge was already consumed or changed")
    try:
        append_event(
            db,
            event_type="enrollment.challenge.revoked",
            actor_issuer=actor_issuer,
            actor_subject=actor_subject,
            target_id=row.target_id,
            agent_id=row.expected_agent_id,
            enrollment_id=row.enrollment_id,
            metadata={"revoked_at": current.isoformat()},
            occurred_at=current,
        )
        db.commit()
    except (AuditError, SQLAlchemyError) as exc:
        db.rollback()
        raise EnrollmentStorageUnavailable("enrollment storage is unavailable") from exc
    row.state = EnrollmentChallengeState.REVOKED.value
    row.revoked_at = current
    return row


def _token_digest(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8", errors="strict")).hexdigest()


def _required(value: str, label: str, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise EnrollmentError(f"{label} is invalid")


def _aware(value: datetime, *, database_value: bool = False) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        if database_value and isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        raise EnrollmentError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)
