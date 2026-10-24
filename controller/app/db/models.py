from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.schema import DDL


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
    )
    platform: Mapped[str] = mapped_column(String(50))
    address: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default="UNKNOWN",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )


class AssessmentObservationTrust(StrEnum):
    CONTROLLER_OBSERVED_UNAUTHENTICATED = "controller_observed_unauthenticated"
    AUTHENTICATED_AGENT_TARGET_BOUND = "authenticated_agent_target_bound"
    APPROVAL_PROVENANCE_VERIFIED = "approval_provenance_verified"


class AssessmentObservation(Base):
    """Append-only record of an assessment payload collected by the Controller."""

    __tablename__ = "assessment_observations"
    __table_args__ = (
        UniqueConstraint("observation_id", name="uq_assessment_observations_observation_id"),
        Index("ix_assessment_observations_target_collected", "target_id", "collected_at", "id"),
        CheckConstraint(
            "trust_status IN ('controller_observed_unauthenticated', 'authenticated_agent_target_bound')",
            name="ck_assessment_observations_untrusted_only",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observation_id: Mapped[str] = mapped_column(
        String(36), nullable=False, default=lambda: str(uuid4())
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id", ondelete="RESTRICT"), nullable=False
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    policy_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    catalog_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_json: Mapped[str] = mapped_column(Text, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    collection_source: Mapped[str] = mapped_column(String(128), nullable=False)
    reported_agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    authenticated_agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    authenticated_credential_fingerprint: Mapped[str | None] = mapped_column(String(71), nullable=True)
    target_binding_generation: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trust_status: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default=AssessmentObservationTrust.CONTROLLER_OBSERVED_UNAUTHENTICATED.value,
    )


class AgentIdentityState(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"
    REPLACED = "replaced"
    QUARANTINED = "quarantined"


class AgentCredentialState(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"
    REPLACED = "replaced"
    EXPIRED = "expired"
    QUARANTINED = "quarantined"


class AgentIdentity(Base):
    __tablename__ = "agent_identities"
    __table_args__ = (
        UniqueConstraint("workload_identity_uri", name="uq_agent_identity_workload_uri"),
        CheckConstraint(
            "state IN ('pending', 'active', 'revoked', 'replaced', 'quarantined')",
            name="ck_agent_identity_state",
        ),
    )

    agent_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workload_identity_uri: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default=AgentIdentityState.PENDING.value)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class AgentCredential(Base):
    __tablename__ = "agent_credentials"
    __table_args__ = (
        UniqueConstraint("fingerprint_sha256", name="uq_agent_credentials_fingerprint"),
        UniqueConstraint("public_key_sha256", name="uq_agent_credentials_public_key"),
        CheckConstraint(
            "state IN ('pending', 'active', 'revoked', 'replaced', 'expired', 'quarantined')",
            name="ck_agent_credential_state",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(128), ForeignKey("agent_identities.agent_id", ondelete="RESTRICT"), nullable=False, index=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    public_key_sha256: Mapped[str | None] = mapped_column(String(71), nullable=True)
    public_key_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)
    identity_uri: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default=AgentCredentialState.PENDING.value)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TargetAgentBinding(Base):
    __tablename__ = "target_agent_bindings"
    __table_args__ = (
        Index("uq_active_target_agent_binding", "target_id", unique=True, sqlite_where=text("state = 'active'")),
        CheckConstraint(
            "state IN ('pending', 'active', 'revoked', 'replaced', 'quarantined')",
            name="ck_target_agent_binding_state",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id", ondelete="RESTRICT"), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(128), ForeignKey("agent_identities.agent_id", ondelete="RESTRICT"), nullable=False, index=True)
    generation: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    credential_id: Mapped[int] = mapped_column(Integer, ForeignKey("agent_credentials.id", ondelete="RESTRICT"), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PolicyCatalogDefinition(Base):
    __tablename__ = "policy_catalog_definitions"
    __table_args__ = (
        UniqueConstraint("platform", "policy_version", "catalog_version", name="uq_policy_catalog_scope_version"),
        CheckConstraint("verification_status IN ('unverified', 'verified', 'revoked')", name="ck_policy_registry_verification"),
        CheckConstraint("applicability_status IN ('unconfirmed', 'confirmed', 'not_applicable')", name="ck_policy_registry_applicability"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(128), nullable=False)
    definition_json: Mapped[str] = mapped_column(Text, nullable=False)
    definition_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    provenance_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unverified")
    applicability_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unconfirmed")
    enabled: Mapped[bool] = mapped_column(nullable=False, default=False)


class PolicyReviewRecord(Base):
    """Append-only review decision bound to one exact definition and source pin."""

    __tablename__ = "policy_review_records"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('approved', 'rejected', 'revoked')",
            name="ck_policy_review_decision",
        ),
        Index("ix_policy_review_policy_time", "policy_definition_id", "reviewed_at", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_definition_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("policy_catalog_definitions.id", ondelete="RESTRICT"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    reviewer_issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    reviewer_subject: Mapped[str] = mapped_column(String(512), nullable=False)
    reviewed_definition_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    reviewed_source_evidence_sha256: Mapped[str | None] = mapped_column(String(71), nullable=True)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(128), nullable=False)
    provenance_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TargetPolicyAssignment(Base):
    __tablename__ = "target_policy_assignments"

    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id", ondelete="RESTRICT"), primary_key=True)
    definition_id: Mapped[int] = mapped_column(Integer, ForeignKey("policy_catalog_definitions.id", ondelete="RESTRICT"), nullable=False)
    binding_generation: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="active")


class EnrollmentChallengeState(StrEnum):
    PENDING = "pending"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class EnrollmentChallenge(Base):
    """One-time bootstrap challenge; only its SHA-256 digest is persisted."""

    __tablename__ = "enrollment_challenges"
    __table_args__ = (
        UniqueConstraint("enrollment_id", name="uq_enrollment_challenge_id"),
        UniqueConstraint("target_id", "expected_agent_id", name="uq_enrollment_target_agent"),
        UniqueConstraint("bootstrap_token_sha256", name="uq_enrollment_bootstrap_hash"),
        CheckConstraint(
            "state IN ('pending', 'consumed', 'revoked', 'expired')",
            name="ck_enrollment_challenge_state",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    enrollment_id: Mapped[str] = mapped_column(String(36), nullable=False)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    expected_agent_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("agent_identities.agent_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    workload_identity_uri: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    requester_issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    requester_subject: Mapped[str] = mapped_column(String(512), nullable=False)
    bootstrap_token_sha256: Mapped[str] = mapped_column(String(71), nullable=False)
    state: Mapped[str] = mapped_column(
        String(24), nullable=False, default=EnrollmentChallengeState.PENDING.value
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditChainHead(Base):
    __tablename__ = "security_audit_chain_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    last_digest: Mapped[str] = mapped_column(String(71), nullable=False)


class SecurityAuditEvent(Base):
    __tablename__ = "security_audit_events"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_security_audit_event_id"),
        UniqueConstraint("event_digest", name="uq_security_audit_event_digest"),
        Index("ix_security_audit_event_type_time", "event_type", "occurred_at"),
    )

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    actor_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enrollment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_definition_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False)
    previous_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    event_digest: Mapped[str] = mapped_column(String(71), nullable=False)


class SandboxRemediationRun(Base):
    """Persisted output from the local-only, fixed-action verification sandbox."""

    __tablename__ = "sandbox_remediation_runs"
    __table_args__ = (
        CheckConstraint("sandbox_only = 1 AND test_only_trust = 1 AND live_target_modified = 0", name="ck_sandbox_runs_isolated"),
        Index("ix_sandbox_run_recorded_at", "recorded_at"),
    )

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    platform: Mapped[str] = mapped_column(String(64), nullable=False)
    scenario: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    sandbox_only: Mapped[bool] = mapped_column(default=True, nullable=False)
    test_only_trust: Mapped[bool] = mapped_column(default=True, nullable=False)
    live_target_modified: Mapped[bool] = mapped_column(default=False, nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class DemoDecoyEvent(Base):
    """Synthetic events only; this model has no link to target or executor state."""

    __tablename__ = "demo_decoy_events"
    __table_args__ = (
        CheckConstraint("simulation_mode = 'SIMULATED'", name="ck_demo_decoy_events_simulated_only"),
        Index("ix_demo_decoy_batch_time", "batch_id", "occurred_at"),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    decoy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    source_address: Mapped[str] = mapped_column(String(64), nullable=False)
    source_classification: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    simulation_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="SIMULATED")


# SQLite's create_all adds this new table to an existing database without
# changing the existing targets schema. Triggers make ordinary SQL/ORM writes
# append-only; the payload hash is still only an integrity comparison, not an
# authenticated or tamper-evident audit mechanism.
event.listen(
    AssessmentObservation.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS assessment_observations_no_update "
        "BEFORE UPDATE ON assessment_observations BEGIN "
        "SELECT RAISE(ABORT, 'assessment observations are immutable'); END"
    ).execute_if(dialect="sqlite"),
)
event.listen(
    SecurityAuditEvent.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS security_audit_events_no_update "
        "BEFORE UPDATE ON security_audit_events BEGIN "
        "SELECT RAISE(ABORT, 'security audit events are append-only'); END"
    ).execute_if(dialect="sqlite"),
)
event.listen(
    PolicyReviewRecord.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS policy_review_records_no_update "
        "BEFORE UPDATE ON policy_review_records BEGIN "
        "SELECT RAISE(ABORT, 'policy review records are append-only'); END"
    ).execute_if(dialect="sqlite"),
)
event.listen(
    PolicyReviewRecord.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS policy_review_records_no_delete "
        "BEFORE DELETE ON policy_review_records BEGIN "
        "SELECT RAISE(ABORT, 'policy review records are append-only'); END"
    ).execute_if(dialect="sqlite"),
)
event.listen(
    SecurityAuditEvent.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS security_audit_events_no_delete "
        "BEFORE DELETE ON security_audit_events BEGIN "
        "SELECT RAISE(ABORT, 'security audit events are append-only'); END"
    ).execute_if(dialect="sqlite"),
)
event.listen(
    AssessmentObservation.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS assessment_observations_no_delete "
        "BEFORE DELETE ON assessment_observations BEGIN "
        "SELECT RAISE(ABORT, 'assessment observations are immutable'); END"
    ).execute_if(dialect="sqlite"),
)
