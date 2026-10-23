"""Local agent identity and target-binding lifecycle primitives.

These operations are intentionally not exposed as HTTP endpoints. Calling them
requires a future authenticated administrative enrollment boundary.
"""

from datetime import datetime, timezone
import re
from uuid import uuid4
from urllib.parse import urlsplit

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import (
    AgentCredential,
    AgentCredentialState,
    AgentIdentity,
    AgentIdentityState,
    Target,
    TargetAgentBinding,
    TargetPolicyAssignment,
)


_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")


class IdentityLifecycleError(ValueError):
    """A requested identity lifecycle transition is not valid."""


def create_pending_agent(db: Session, *, agent_id: str, workload_identity_uri: str) -> AgentIdentity:
    _required(agent_id, "agent ID", 128)
    _required(workload_identity_uri, "agent workload identity URI", 255)
    parsed_identity = urlsplit(workload_identity_uri)
    if not parsed_identity.scheme or not parsed_identity.netloc or parsed_identity.query or parsed_identity.fragment:
        raise IdentityLifecycleError("agent workload identity must be an absolute URI without query or fragment")
    identity = AgentIdentity(
        agent_id=agent_id,
        workload_identity_uri=workload_identity_uri,
        state=AgentIdentityState.PENDING.value,
    )
    db.add(identity)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise IdentityLifecycleError("agent ID is already registered") from exc
    db.refresh(identity)
    return identity


def add_pending_credential(
    db: Session,
    *,
    agent_id: str,
    fingerprint_sha256: str,
    identity_uri: str,
    not_before: datetime,
    expires_at: datetime,
    public_key_sha256: str | None = None,
    public_key_metadata: str | None = None,
) -> AgentCredential:
    identity = db.get(AgentIdentity, agent_id)
    if identity is None or identity.state not in {
        AgentIdentityState.PENDING.value,
        AgentIdentityState.ACTIVE.value,
    }:
        raise IdentityLifecycleError("agent identity is unavailable")
    if identity_uri != identity.workload_identity_uri:
        raise IdentityLifecycleError("credential URI does not match registered agent identity")
    if not isinstance(fingerprint_sha256, str) or not _FINGERPRINT.fullmatch(fingerprint_sha256):
        raise IdentityLifecycleError("credential fingerprint must be sha256:<lowercase hex>")
    if public_key_sha256 is not None and (
        not isinstance(public_key_sha256, str) or not _FINGERPRINT.fullmatch(public_key_sha256)
    ):
        raise IdentityLifecycleError("public key fingerprint must be sha256:<lowercase hex>")
    _required(identity_uri, "credential identity URI", 255)
    start = _aware(not_before)
    end = _aware(expires_at)
    if end <= start:
        raise IdentityLifecycleError("credential expiry must follow not-before")
    if public_key_metadata is not None:
        _required(public_key_metadata, "public key metadata", 8192)
    credential = AgentCredential(
        agent_id=agent_id,
        fingerprint_sha256=fingerprint_sha256,
        public_key_sha256=public_key_sha256,
        identity_uri=identity_uri,
        public_key_metadata=public_key_metadata,
        state=AgentCredentialState.PENDING.value,
        not_before=start,
        expires_at=end,
    )
    db.add(credential)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise IdentityLifecycleError("credential fingerprint collision") from exc
    db.refresh(credential)
    return credential


def activate_agent(db: Session, agent_id: str) -> None:
    """Activate a previously provisioned identity; not an enrollment endpoint."""
    identity = db.get(AgentIdentity, agent_id)
    if identity is None or identity.state not in {"pending", "active"}:
        raise IdentityLifecycleError("agent identity cannot be activated")
    identity.state = AgentIdentityState.ACTIVE.value
    identity.updated_at = datetime.now(timezone.utc)
    db.commit()


def activate_credential(db: Session, credential_id: int, *, now: datetime) -> AgentCredential:
    credential = db.get(AgentCredential, credential_id)
    current = _aware(now)
    if credential is None or credential.state != AgentCredentialState.PENDING.value:
        raise IdentityLifecycleError("credential is not pending")
    identity = db.get(AgentIdentity, credential.agent_id)
    if identity is None or identity.state != AgentIdentityState.ACTIVE.value:
        raise IdentityLifecycleError("agent identity is not active")
    if current < _aware(credential.not_before, database_value=True) or current >= _aware(credential.expires_at, database_value=True):
        raise IdentityLifecycleError("credential is outside its validity interval")
    prior_credentials = db.scalars(
        select(AgentCredential).where(
            AgentCredential.agent_id == credential.agent_id,
            AgentCredential.id != credential.id,
            AgentCredential.state == AgentCredentialState.ACTIVE.value,
        )
    ).all()
    for prior in prior_credentials:
        prior.state = AgentCredentialState.REPLACED.value
        prior.revoked_at = current
        _invalidate_credential_bindings(db, prior.id, current, state="replaced")
    credential.state = AgentCredentialState.ACTIVE.value
    db.commit()
    db.refresh(credential)
    return credential


def bind_target_to_agent(
    db: Session,
    *,
    target_id: str,
    agent_id: str,
    credential_id: int,
    now: datetime | None = None,
) -> TargetAgentBinding:
    target = db.get(Target, target_id)
    identity = db.get(AgentIdentity, agent_id)
    credential = db.get(AgentCredential, credential_id)
    if target is None:
        raise IdentityLifecycleError("target is not registered")
    if identity is None or identity.state != AgentIdentityState.ACTIVE.value:
        raise IdentityLifecycleError("agent identity is not active")
    if (
        credential is None
        or credential.agent_id != agent_id
        or credential.state != AgentCredentialState.ACTIVE.value
    ):
        raise IdentityLifecycleError("credential is not active for this agent")
    when = _aware(now or datetime.now(timezone.utc))
    if when < _aware(credential.not_before, database_value=True) or when >= _aware(credential.expires_at, database_value=True):
        raise IdentityLifecycleError("credential is outside its validity interval")

    active = db.scalar(
        select(TargetAgentBinding).where(
            TargetAgentBinding.target_id == target_id,
            TargetAgentBinding.state == "active",
        )
    )
    if active is not None:
        active.state = "replaced"
        active.ended_at = when
        db.execute(
            update(TargetPolicyAssignment)
            .where(TargetPolicyAssignment.target_id == target_id)
            .values(state="stale")
        )
    binding = TargetAgentBinding(
        target_id=target_id,
        agent_id=agent_id,
        credential_id=credential_id,
        generation=str(uuid4()),
        state="active",
        created_at=when,
    )
    db.add(binding)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise IdentityLifecycleError("target already has an active agent binding") from exc
    db.refresh(binding)
    return binding


def revoke_credential(db: Session, credential_id: int, *, now: datetime | None = None) -> None:
    credential = db.get(AgentCredential, credential_id)
    if credential is None:
        raise IdentityLifecycleError("credential is unknown")
    when = _aware(now or datetime.now(timezone.utc))
    credential.state = AgentCredentialState.REVOKED.value
    credential.revoked_at = when
    bindings = db.scalars(
        select(TargetAgentBinding).where(
            TargetAgentBinding.credential_id == credential_id,
            TargetAgentBinding.state == "active",
        )
    ).all()
    for binding in bindings:
        binding.state = "revoked"
        binding.ended_at = when
        db.execute(
            update(TargetPolicyAssignment)
            .where(TargetPolicyAssignment.target_id == binding.target_id)
            .values(state="stale")
        )
    other_active = db.scalar(
        select(AgentCredential.id).where(
            AgentCredential.agent_id == credential.agent_id,
            AgentCredential.id != credential_id,
            AgentCredential.state == AgentCredentialState.ACTIVE.value,
        )
    )
    if other_active is None:
        identity = db.get(AgentIdentity, credential.agent_id)
        if identity is not None:
            identity.state = AgentIdentityState.REVOKED.value
            identity.updated_at = when
    db.commit()


def revoke_agent(db: Session, agent_id: str, *, now: datetime | None = None) -> None:
    identity = db.get(AgentIdentity, agent_id)
    if identity is None:
        raise IdentityLifecycleError("agent identity is unknown")
    when = _aware(now or datetime.now(timezone.utc))
    identity.state = AgentIdentityState.REVOKED.value
    identity.updated_at = when
    credentials = db.scalars(
        select(AgentCredential).where(
            AgentCredential.agent_id == agent_id,
            AgentCredential.state.in_(("pending", "active")),
        )
    ).all()
    for credential in credentials:
        credential.state = AgentCredentialState.REVOKED.value
        credential.revoked_at = when
    _invalidate_bindings(db, agent_id, when)
    db.commit()


def quarantine_agent(db: Session, agent_id: str, *, now: datetime | None = None) -> None:
    identity = db.get(AgentIdentity, agent_id)
    if identity is None:
        raise IdentityLifecycleError("agent identity is unknown")
    when = _aware(now or datetime.now(timezone.utc))
    identity.state = AgentIdentityState.QUARANTINED.value
    identity.updated_at = when
    for credential in db.scalars(
        select(AgentCredential).where(
            AgentCredential.agent_id == agent_id,
            AgentCredential.state.in_(("pending", "active")),
        )
    ).all():
        credential.state = AgentCredentialState.QUARANTINED.value
        credential.revoked_at = when
    _invalidate_bindings(db, agent_id, when, state="quarantined")
    db.commit()


def replace_agent_identity(
    db: Session, *, old_agent_id: str, replacement_agent_id: str,
    replacement_identity_uri: str, now: datetime | None = None
) -> AgentIdentity:
    if old_agent_id == replacement_agent_id:
        raise IdentityLifecycleError("replacement agent ID must be unique")
    old_identity = db.get(AgentIdentity, old_agent_id)
    if old_identity is None:
        raise IdentityLifecycleError("agent identity is unknown")
    _required(replacement_agent_id, "replacement agent ID", 128)
    _required(replacement_identity_uri, "replacement workload identity URI", 255)
    if db.get(AgentIdentity, replacement_agent_id) is not None:
        raise IdentityLifecycleError("replacement agent ID is already registered")
    when = _aware(now or datetime.now(timezone.utc))
    replacement = AgentIdentity(
        agent_id=replacement_agent_id,
        workload_identity_uri=replacement_identity_uri,
        state=AgentIdentityState.PENDING.value,
        created_at=when,
        updated_at=when,
    )
    db.add(replacement)
    old_identity.state = AgentIdentityState.REPLACED.value
    old_identity.updated_at = when
    for credential in db.scalars(
        select(AgentCredential).where(
            AgentCredential.agent_id == old_agent_id,
            AgentCredential.state.in_(("pending", "active")),
        )
    ).all():
        credential.state = AgentCredentialState.REPLACED.value
        credential.revoked_at = when
    _invalidate_bindings(db, old_agent_id, when, state="replaced")
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise IdentityLifecycleError("replacement agent ID or workload URI collision") from exc
    db.refresh(replacement)
    return replacement


def _invalidate_bindings(
    db: Session, agent_id: str, when: datetime, *, state: str = "revoked"
) -> None:
    bindings = db.scalars(
        select(TargetAgentBinding).where(
            TargetAgentBinding.agent_id == agent_id,
            TargetAgentBinding.state == "active",
        )
    ).all()
    for binding in bindings:
        binding.state = state
        binding.ended_at = when
        db.execute(
            update(TargetPolicyAssignment)
            .where(TargetPolicyAssignment.target_id == binding.target_id)
            .values(state="stale")
        )


def _invalidate_credential_bindings(
    db: Session, credential_id: int, when: datetime, *, state: str
) -> None:
    bindings = db.scalars(
        select(TargetAgentBinding).where(
            TargetAgentBinding.credential_id == credential_id,
            TargetAgentBinding.state == "active",
        )
    ).all()
    for binding in bindings:
        binding.state = state
        binding.ended_at = when
        db.execute(
            update(TargetPolicyAssignment)
            .where(TargetPolicyAssignment.target_id == binding.target_id)
            .values(state="stale")
        )


def _required(value: str, label: str, limit: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise IdentityLifecycleError(f"{label} is invalid")


def _aware(value: datetime, *, database_value: bool = False) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        if database_value and isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        raise IdentityLifecycleError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)
