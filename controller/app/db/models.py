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
            "trust_status = 'controller_observed_unauthenticated'",
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
    target_binding_generation: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trust_status: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default=AssessmentObservationTrust.CONTROLLER_OBSERVED_UNAUTHENTICATED.value,
    )


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
    AssessmentObservation.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS assessment_observations_no_delete "
        "BEFORE DELETE ON assessment_observations BEGIN "
        "SELECT RAISE(ABORT, 'assessment observations are immutable'); END"
    ).execute_if(dialect="sqlite"),
)
