"""Transactional, tamper-evident (but not rewrite-proof) SQLite audit chain."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import re
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.models import AuditChainHead, SecurityAuditEvent


GENESIS_DIGEST = "sha256:" + "0" * 64
AUDIT_DOMAIN = b"AHA-SECURITY-AUDIT-EVENT\x00security-audit-event/v1\x00"
MAX_AUDIT_METADATA_BYTES = 16 * 1024
MAX_AUDIT_COLLECTION_ITEMS = 100
MAX_AUDIT_STRING_LENGTH = 4096
_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "privatekey",
    "private_key",
    "bearer",
    "apikey",
    "api_key",
)


class AuditError(RuntimeError):
    """Audit append or verification could not complete safely."""


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    event_count: int
    error: str | None = None


def append_event(
    db: Session,
    *,
    event_type: str,
    actor_issuer: str | None = None,
    actor_subject: str | None = None,
    target_id: str | None = None,
    agent_id: str | None = None,
    enrollment_id: str | None = None,
    policy_definition_id: int | None = None,
    metadata: dict | None = None,
    occurred_at: datetime | None = None,
) -> SecurityAuditEvent:
    """Append inside the caller's transaction; caller commits business + audit."""
    if not isinstance(event_type, str) or not _EVENT_TYPE.fullmatch(event_type):
        raise AuditError("audit event type is invalid")
    if (actor_issuer is None) != (actor_subject is None):
        raise AuditError("audit actor issuer and subject must be supplied together")
    for value, maximum, label in (
        (actor_issuer, 512, "actor issuer"),
        (actor_subject, 512, "actor subject"),
        (target_id, 36, "target ID"),
        (agent_id, 128, "agent ID"),
        (enrollment_id, 36, "enrollment ID"),
    ):
        if value is not None and (not isinstance(value, str) or not value or len(value) > maximum):
            raise AuditError(f"audit {label} is invalid")
    if policy_definition_id is not None and (
        isinstance(policy_definition_id, bool)
        or not isinstance(policy_definition_id, int)
        or policy_definition_id < 1
    ):
        raise AuditError("audit policy definition ID is invalid")
    if metadata is not None and not isinstance(metadata, dict):
        raise AuditError("audit metadata must be an object")
    at = _utc(occurred_at or datetime.now(timezone.utc))
    safe_metadata = _sanitize_metadata(metadata or {})
    metadata_json = _canonical_json(safe_metadata)
    if len(metadata_json.encode("utf-8")) > MAX_AUDIT_METADATA_BYTES:
        raise AuditError("audit metadata exceeds the size limit")
    if db.get_bind().dialect.name != "sqlite":
        raise AuditError("audit chain append requires the configured SQLite backend")

    event_id = str(uuid4())
    try:
        # The no-op upsert is the first write in this transaction. SQLite's
        # single-writer lock serializes concurrent appends before reading head.
        db.execute(
            sqlite_insert(AuditChainHead)
            .values(id=1, last_sequence=0, last_digest=GENESIS_DIGEST)
            .on_conflict_do_update(
                index_elements=[AuditChainHead.id],
                set_={"last_sequence": AuditChainHead.last_sequence},
            )
        )
        head = db.scalar(
            select(AuditChainHead)
            .where(AuditChainHead.id == 1)
            .execution_options(populate_existing=True)
        )
        if head is None:
            raise AuditError("audit chain head is unavailable")
        sequence = head.last_sequence + 1
        previous_digest = head.last_digest
        body = _event_body(
            sequence=sequence,
            event_id=event_id,
            occurred_at=at,
            event_type=event_type,
            actor_issuer=actor_issuer,
            actor_subject=actor_subject,
            target_id=target_id,
            agent_id=agent_id,
            enrollment_id=enrollment_id,
            policy_definition_id=policy_definition_id,
            metadata=safe_metadata,
            previous_digest=previous_digest,
        )
        digest = _digest(body)
        row = SecurityAuditEvent(
            sequence=sequence,
            event_id=event_id,
            occurred_at=at,
            event_type=event_type,
            actor_issuer=actor_issuer,
            actor_subject=actor_subject,
            target_id=target_id,
            agent_id=agent_id,
            enrollment_id=enrollment_id,
            policy_definition_id=policy_definition_id,
            metadata_json=metadata_json,
            previous_digest=previous_digest,
            event_digest=digest,
        )
        db.add(row)
        head.last_sequence = sequence
        head.last_digest = digest
        db.flush()
        return row
    except AuditError:
        raise
    except SQLAlchemyError as exc:
        raise AuditError("audit append failed; business transaction must be rolled back") from exc


def verify_chain(db: Session) -> AuditVerification:
    """Verify ordering, canonical representation, links, digests, and stored head."""
    try:
        rows = db.scalars(
            select(SecurityAuditEvent).order_by(SecurityAuditEvent.sequence.asc())
        ).all()
        previous = GENESIS_DIGEST
        expected_sequence = 1
        for row in rows:
            if row.sequence != expected_sequence:
                return AuditVerification(False, len(rows), "event sequence has a gap or reorder")
            if not isinstance(row.metadata_json, str) or len(row.metadata_json.encode("utf-8", errors="strict")) > MAX_AUDIT_METADATA_BYTES:
                return AuditVerification(False, len(rows), "event metadata exceeds the size limit")
            metadata = json.loads(row.metadata_json, object_pairs_hook=_reject_duplicate_members)
            if not isinstance(metadata, dict) or _canonical_json(_sanitize_metadata(metadata)) != row.metadata_json:
                return AuditVerification(False, len(rows), "event metadata is not canonical")
            if not hmac.compare_digest(row.previous_digest, previous):
                return AuditVerification(False, len(rows), "previous-event digest does not match")
            body = _event_body(
                sequence=row.sequence,
                event_id=row.event_id,
                occurred_at=row.occurred_at,
                event_type=row.event_type,
                actor_issuer=row.actor_issuer,
                actor_subject=row.actor_subject,
                target_id=row.target_id,
                agent_id=row.agent_id,
                enrollment_id=row.enrollment_id,
                policy_definition_id=row.policy_definition_id,
                metadata=metadata,
                previous_digest=row.previous_digest,
            )
            if not hmac.compare_digest(row.event_digest, _digest(body)):
                return AuditVerification(False, len(rows), "event digest does not match")
            previous = row.event_digest
            expected_sequence += 1
        head = db.get(AuditChainHead, 1)
        if rows:
            if head is None or head.last_sequence != len(rows) or not hmac.compare_digest(head.last_digest, previous):
                return AuditVerification(False, len(rows), "stored chain head does not match events")
        elif head is not None and (head.last_sequence != 0 or head.last_digest != GENESIS_DIGEST):
            return AuditVerification(False, 0, "empty event list has a non-empty chain head")
        return AuditVerification(True, len(rows))
    except Exception as exc:
        return AuditVerification(False, 0, f"audit verification failed: {type(exc).__name__}")


def _event_body(**values) -> dict:
    return {
        "schema": "security-audit-event/v1",
        "sequence": values["sequence"],
        "event_id": values["event_id"],
        "occurred_at": _utc(values["occurred_at"]).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "event_type": values["event_type"],
        "actor_issuer": values["actor_issuer"],
        "actor_subject": values["actor_subject"],
        "target_id": values["target_id"],
        "agent_id": values["agent_id"],
        "enrollment_id": values["enrollment_id"],
        "policy_definition_id": values["policy_definition_id"],
        "metadata": values["metadata"],
        "previous_digest": values["previous_digest"],
    }


def _digest(body: dict) -> str:
    encoded = _canonical_json(body).encode("utf-8", errors="strict")
    return "sha256:" + hashlib.sha256(AUDIT_DOMAIN + encoded).hexdigest()


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise AuditError("audit data is not canonical JSON") from exc


def _sanitize_metadata(value: object, *, depth: int = 0) -> object:
    if depth > 8:
        raise AuditError("audit metadata nesting is too deep")
    if isinstance(value, dict):
        if len(value) > MAX_AUDIT_COLLECTION_ITEMS:
            raise AuditError("audit metadata has too many fields")
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise AuditError("audit metadata key is invalid")
            normalized = key.lower().replace("-", "").replace("_", "")
            if any(part in normalized for part in _SENSITIVE_KEY_PARTS):
                raise AuditError("sensitive fields are forbidden in audit metadata")
            result[key] = _sanitize_metadata(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        if len(value) > MAX_AUDIT_COLLECTION_ITEMS:
            raise AuditError("audit metadata list is too long")
        return [_sanitize_metadata(item, depth=depth + 1) for item in value]
    if isinstance(value, str):
        if len(value) > MAX_AUDIT_STRING_LENGTH:
            raise AuditError("audit metadata string is too long")
        return value
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise AuditError("audit metadata contains an unsupported value")


def _reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise AuditError("audit timestamp is invalid")
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
