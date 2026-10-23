from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, inspect, text, update, event
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.assessments.provenance import (
    ObservationNotFound,
    ObservationRejected,
    ObservationStorageUnavailable,
    ObservationTrustState,
    SupportedBindingVersions,
    resolve_assessment_observation,
    store_assessment_observation,
)
from app.db.models import (
    AssessmentObservation,
    AssessmentObservationTrust,
    Base,
    Target,
)


POLICY = "policy-test-v1"
CATALOG = "ubuntu-catalog-test-v1"
VERSIONS = SupportedBindingVersions(frozenset({POLICY}), frozenset({CATALOG}))


def raw_assessment() -> bytes:
    return (
        b'{ "platform": "ubuntu", "findings": [{"control_id":"SSH-1",'
        b'"title":"SSH setting","status":"FAIL","severity":"HIGH",'
        b'"current_value":"yes","expected_value":"no","message":"disable",'
        b'"source":"sshd","evidence":[{"name":"PermitRootLogin",'
        b'"value":"yes","source":"sshd -T"}]}] }\n'
    )


class AssessmentProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tempdir.name) / "controller-test.sqlite"
        self.engine = create_engine(
            f"sqlite:///{self.database_path}", connect_args={"check_same_thread": False}
        )

        @event.listens_for(self.engine, "connect")
        def enable_foreign_keys(connection, _record) -> None:
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db: Session = self.SessionLocal()
        self.target = Target(
            id="target-controller-1",
            name="Test target",
            platform="ubuntu",
            address="127.0.0.1",
            status="REGISTERED",
        )
        self.db.add(self.target)
        self.db.commit()
        self.now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()
        self.tempdir.cleanup()

    def store(
        self,
        *,
        raw_payload: bytes | str | None = None,
        collected_at: datetime | None = None,
        **kwargs,
    ) -> AssessmentObservation:
        return store_assessment_observation(
            self.db,
            target=self.target,
            raw_payload=raw_assessment() if raw_payload is None else raw_payload,
            policy_version=POLICY,
            catalog_version=CATALOG,
            collected_at=self.now if collected_at is None else collected_at,
            **kwargs,
        )

    def resolve(self, observation_id: str, **kwargs):
        return resolve_assessment_observation(
            self.db,
            observation_id=observation_id,
            target=self.target,
            now=kwargs.pop("now", self.now + timedelta(seconds=5)),
            max_age=kwargs.pop("max_age", timedelta(minutes=5)),
            versions=kwargs.pop("versions", VERSIONS),
            expected_policy_version=kwargs.pop("expected_policy_version", POLICY),
            expected_catalog_version=kwargs.pop("expected_catalog_version", CATALOG),
            **kwargs,
        )

    def test_store_resolve_recomputes_binding_and_keeps_observation_untrusted(self) -> None:
        raw = raw_assessment()
        row = self.store(raw_payload=raw, reported_agent_id="self-reported-agent")

        self.assertEqual(row.assessment_json.encode("utf-8"), raw)
        self.assertEqual(row.payload_sha256, "sha256:" + hashlib.sha256(raw).hexdigest())
        self.assertEqual(
            row.trust_status,
            AssessmentObservationTrust.CONTROLLER_OBSERVED_UNAUTHENTICATED.value,
        )

        result = self.resolve(row.observation_id)

        self.assertEqual(result.target_id, self.target.id)
        self.assertEqual(result.observation_state, ObservationTrustState.CONTROLLER_OBSERVED_UNAUTHENTICATED)
        self.assertEqual(result.approval_state, ObservationTrustState.UNRESOLVED_UNTRUSTED)
        self.assertEqual(result.assessment.findings[0].control_id, "SSH-1")
        self.assertIsNotNone(result.evidence_digest)
        self.assertIsNone(result.approval_context)
        self.assertIn("authenticated agent identity", result.unresolved_reason)

    def test_unknown_missing_or_inconsistent_policy_catalog_provenance_fails_closed(self) -> None:
        row = self.store()
        missing = self.resolve(
            row.observation_id,
            expected_policy_version=None,
            expected_catalog_version=None,
        )
        self.assertEqual(missing.approval_state, ObservationTrustState.UNRESOLVED_UNTRUSTED)
        self.assertIsNone(missing.evidence_digest)

        with self.assertRaises(ObservationRejected):
            self.resolve(row.observation_id, expected_policy_version="unknown-policy")
        with self.assertRaises(ObservationRejected):
            self.resolve(row.observation_id, expected_catalog_version="unknown-catalog")
        with self.assertRaises(ObservationRejected):
            self.resolve(row.observation_id, expected_policy_version="policy-other")
        expanded_versions = SupportedBindingVersions(
            frozenset({POLICY, "policy-old"}),
            frozenset({CATALOG, "catalog-old"}),
        )
        with self.assertRaises(ObservationRejected):
            self.resolve(
                row.observation_id,
                versions=expanded_versions,
                expected_policy_version="policy-old",
            )
        with self.assertRaises(ObservationRejected):
            self.resolve(
                row.observation_id,
                versions=expanded_versions,
                expected_catalog_version="catalog-old",
            )

        missing_record = store_assessment_observation(
            self.db,
            target=self.target,
            raw_payload=raw_assessment(),
            collected_at=self.now + timedelta(seconds=1),
        )
        unresolved = self.resolve(missing_record.observation_id)
        self.assertEqual(unresolved.approval_state, ObservationTrustState.UNRESOLVED_UNTRUSTED)
        self.assertIsNone(unresolved.evidence_digest)

    def test_missing_observation_and_wrong_target_are_rejected(self) -> None:
        with self.assertRaises(ObservationNotFound):
            self.resolve("missing-observation-id")
        row = self.store()
        other = Target(
            id="target-controller-2",
            name="Other target",
            platform="ubuntu",
            address="127.0.0.2",
            status="REGISTERED",
        )
        self.db.add(other)
        self.db.commit()
        with self.assertRaises(ObservationRejected):
            resolve_assessment_observation(
                self.db,
                observation_id=row.observation_id,
                target=other,
                now=self.now + timedelta(seconds=5),
                max_age=timedelta(minutes=5),
                versions=VERSIONS,
                expected_policy_version=POLICY,
                expected_catalog_version=CATALOG,
            )

    def test_target_fields_are_reloaded_from_controller_storage(self) -> None:
        forged_view = Target(
            id=self.target.id,
            name="Agent supplied display name",
            platform="windows",
            address="203.0.113.99",
            status="UNKNOWN",
        )
        row = store_assessment_observation(
            self.db,
            target=forged_view,
            raw_payload=raw_assessment(),
            policy_version=POLICY,
            catalog_version=CATALOG,
            collected_at=self.now,
        )
        self.assertEqual(row.platform, "ubuntu")
        resolved = resolve_assessment_observation(
            self.db,
            observation_id=row.observation_id,
            target=forged_view,
            now=self.now + timedelta(seconds=1),
            max_age=timedelta(minutes=5),
            versions=VERSIONS,
            expected_policy_version=POLICY,
            expected_catalog_version=CATALOG,
        )
        self.assertEqual(resolved.target_id, self.target.id)
        self.assertEqual(resolved.assessment.platform, "ubuntu")

    def test_stale_future_and_superseded_observations_are_rejected(self) -> None:
        first = self.store()
        with self.assertRaises(ObservationRejected):
            self.resolve(first.observation_id, now=self.now + timedelta(minutes=6))
        with self.assertRaises(ObservationRejected):
            self.resolve(first.observation_id, now=self.now - timedelta(seconds=1))

        self.store(collected_at=self.now + timedelta(seconds=1))
        with self.assertRaises(ObservationRejected):
            self.resolve(first.observation_id)

    def test_stored_payload_tampering_and_malformed_replacement_are_rejected(self) -> None:
        row = self.store()
        # Simulate out-of-band database tampering; normal application UPDATE is
        # blocked by the table's immutability trigger.
        self.db.execute(text("DROP TRIGGER assessment_observations_no_update"))
        self.db.execute(
            text("UPDATE assessment_observations SET assessment_json = :payload WHERE observation_id = :id"),
            {"payload": '{"platform":"ubuntu","findings":[]}', "id": row.observation_id},
        )
        self.db.commit()
        self.db.expire_all()
        with self.assertRaises(ObservationRejected):
            self.resolve(row.observation_id)

        self.db.execute(
            text("UPDATE assessment_observations SET payload_sha256 = :digest WHERE observation_id = :id"),
            {
                "digest": "sha256:" + hashlib.sha256(b"not-json").hexdigest(),
                "id": row.observation_id,
            },
        )
        self.db.execute(
            text("UPDATE assessment_observations SET assessment_json = 'not-json' WHERE observation_id = :id"),
            {"id": row.observation_id},
        )
        self.db.commit()
        self.db.expire_all()
        with self.assertRaises(ObservationRejected):
            self.resolve(row.observation_id)

    def test_database_triggers_prevent_ordinary_updates_and_deletes(self) -> None:
        row = self.store()
        with self.assertRaises(IntegrityError):
            self.db.execute(
                update(AssessmentObservation)
                .where(AssessmentObservation.observation_id == row.observation_id)
                .values(collection_source="rewritten")
            )
        self.db.rollback()
        with self.assertRaises(IntegrityError):
            self.db.delete(row)
            self.db.commit()
        self.db.rollback()

        with self.assertRaises(IntegrityError):
            self.db.add(
                AssessmentObservation(
                    observation_id="forged-trust-row",
                    target_id=self.target.id,
                    collected_at=self.now,
                    platform="ubuntu",
                    payload_schema_version="agent-assessment-json/v1",
                    assessment_json=raw_assessment().decode(),
                    payload_sha256="sha256:" + hashlib.sha256(raw_assessment()).hexdigest(),
                    collection_source="test",
                    trust_status=AssessmentObservationTrust.APPROVAL_PROVENANCE_VERIFIED.value,
                )
            )
            self.db.commit()
        self.db.rollback()

    def test_storage_and_resolution_database_failures_are_reported(self) -> None:
        with patch.object(self.db, "commit", side_effect=OperationalError("commit", {}, Exception("offline"))):
            with self.assertRaises(ObservationStorageUnavailable):
                self.store()

        class BrokenSession:
            def get(self, *_args, **_kwargs):
                raise OperationalError("get", {}, Exception("offline"))

            def rollback(self):
                pass

        broken = BrokenSession()
        with self.assertRaises(ObservationStorageUnavailable):
            resolve_assessment_observation(
                broken,
                observation_id="missing",
                target=self.target,
                now=self.now,
                max_age=timedelta(minutes=5),
                versions=VERSIONS,
                expected_policy_version=POLICY,
                expected_catalog_version=CATALOG,
            )

    def test_create_all_adds_new_table_without_changing_existing_target_columns(self) -> None:
        legacy_engine = create_engine(f"sqlite:///{Path(self.tempdir.name) / 'legacy.sqlite'}")
        Target.__table__.create(legacy_engine)
        old_columns = [column["name"] for column in inspect(legacy_engine).get_columns("targets")]

        Base.metadata.create_all(legacy_engine)

        inspector = inspect(legacy_engine)
        self.assertTrue(inspector.has_table("assessment_observations"))
        self.assertEqual(
            [column["name"] for column in inspector.get_columns("targets")], old_columns
        )
        self.assertIn("trust_status", {column["name"] for column in inspector.get_columns("assessment_observations")})
        legacy_engine.dispose()


if __name__ == "__main__":
    unittest.main()
