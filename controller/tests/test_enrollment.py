from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app.agents.enrollment import (
    EnrollmentConflict,
    EnrollmentError,
    EnrollmentExpired,
    EnrollmentStorageUnavailable,
    consume_enrollment_challenge,
    inspect_enrollment_challenge,
    issue_enrollment_challenge,
    revoke_enrollment_challenge,
)
from app.audit.service import AuditError, verify_chain
from app.db.models import (
    AgentCredential,
    AgentIdentity,
    Base,
    EnrollmentChallenge,
    SecurityAuditEvent,
    Target,
)


class EnrollmentServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "enrollment.sqlite"
        self.engine = create_engine(
            f"sqlite:///{self.path}",
            connect_args={"check_same_thread": False, "timeout": 5},
        )

        @event.listens_for(self.engine, "connect")
        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db = self.Session()
        self.target = Target(
            id="enrollment-target",
            name="Enrollment target",
            platform="ubuntu",
            address="127.0.0.1",
            status="REGISTERED",
        )
        self.db.add(self.target)
        self.db.commit()
        self.now = datetime.now(timezone.utc)

    def tearDown(self):
        self.db.close()
        self.engine.dispose()
        self.temp.cleanup()

    def issue(self, **overrides):
        values = {
            "target_id": self.target.id,
            "expected_agent_id": "enroll-agent-1",
            "workload_identity_uri": "spiffe://lab/agent/enroll-agent-1",
            "requester_issuer": "https://idp.example.test",
            "requester_subject": "admin-1",
            "now": self.now,
        }
        values.update(overrides)
        return issue_enrollment_challenge(self.db, **values)

    def test_issue_persists_pending_identity_and_target_binding_without_raw_token(self):
        issued = self.issue()
        self.assertEqual(issued.challenge.target_id, self.target.id)
        self.assertEqual(issued.challenge.expected_agent_id, "enroll-agent-1")
        self.assertEqual(issued.challenge.state, "pending")
        self.assertEqual(
            issued.challenge.bootstrap_token_sha256,
            "sha256:" + hashlib.sha256(issued.bootstrap_token.encode()).hexdigest(),
        )
        self.assertNotEqual(issued.challenge.bootstrap_token_sha256, issued.bootstrap_token)
        self.assertEqual(issued.challenge.requester_subject, "admin-1")
        identity = self.db.get(AgentIdentity, "enroll-agent-1")
        self.assertEqual(identity.state, "pending")
        self.assertEqual(identity.workload_identity_uri, issued.challenge.workload_identity_uri)
        self.assertEqual(self.db.scalars(select(AgentCredential)).all(), [])
        audit_rows = self.db.scalars(select(SecurityAuditEvent)).all()
        self.assertEqual([row.event_type for row in audit_rows], ["enrollment.challenge.created"])
        self.assertNotIn(issued.bootstrap_token, "".join(row.metadata_json for row in audit_rows))
        self.assertTrue(verify_chain(self.db).valid)

    def test_audit_failure_rolls_back_new_identity_and_challenge(self):
        with patch("app.agents.enrollment.append_event", side_effect=AuditError("audit unavailable")):
            with self.assertRaises(EnrollmentStorageUnavailable):
                self.issue()
        self.assertIsNone(self.db.get(AgentIdentity, "enroll-agent-1"))
        self.assertEqual(self.db.scalars(select(EnrollmentChallenge)).all(), [])
        self.assertEqual(self.db.scalars(select(SecurityAuditEvent)).all(), [])

    def test_issue_does_not_depend_on_post_commit_refresh(self):
        with patch.object(self.db, "refresh", side_effect=SQLAlchemyError("connection lost")):
            issued = self.issue()
        self.assertEqual(issued.challenge.state, "pending")
        self.assertIsNotNone(
            self.db.scalar(
                select(EnrollmentChallenge).where(
                    EnrollmentChallenge.enrollment_id == issued.challenge.enrollment_id
                )
            )
        )

    def test_duplicate_target_agent_and_existing_active_agent_conflict(self):
        self.issue()
        with self.assertRaises(EnrollmentConflict):
            self.issue()
        with self.assertRaises(EnrollmentConflict):
            self.issue(expected_agent_id="enroll-agent-1", workload_identity_uri="spiffe://lab/agent/other")

    def test_wrong_target_and_invalid_identity_uri_rejected(self):
        with self.assertRaises(EnrollmentError):
            self.issue(target_id="missing-target")
        with self.assertRaises(EnrollmentError):
            self.issue(workload_identity_uri="not a URI")
        self.assertEqual(self.db.scalars(select(EnrollmentChallenge)).all(), [])

    def test_consume_is_single_use_and_inspection_never_returns_token(self):
        issued = self.issue()
        consumed = consume_enrollment_challenge(
            self.db,
            enrollment_id=issued.challenge.enrollment_id,
            bootstrap_token=issued.bootstrap_token,
            now=self.now + timedelta(seconds=1),
        )
        self.assertEqual(consumed.state, "consumed")
        with self.assertRaises(EnrollmentConflict):
            consume_enrollment_challenge(
                self.db,
                enrollment_id=issued.challenge.enrollment_id,
                bootstrap_token=issued.bootstrap_token,
                now=self.now + timedelta(seconds=2),
            )
        inspected = inspect_enrollment_challenge(
            self.db, enrollment_id=issued.challenge.enrollment_id, now=self.now + timedelta(seconds=3)
        )
        self.assertFalse(hasattr(inspected, "bootstrap_token"))
        self.assertEqual(inspected.bootstrap_token_sha256, issued.challenge.bootstrap_token_sha256)

    def test_expired_revoked_and_wrong_bootstrap_tokens_cannot_be_consumed(self):
        expired = self.issue(expected_agent_id="agent-expired", workload_identity_uri="spiffe://lab/agent/agent-expired")
        expires_at = expired.challenge.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        with self.assertRaises(EnrollmentExpired):
            consume_enrollment_challenge(
                self.db,
                enrollment_id=expired.challenge.enrollment_id,
                bootstrap_token=expired.bootstrap_token,
                now=expires_at + timedelta(seconds=1),
            )
        self.assertEqual(
            inspect_enrollment_challenge(
                self.db, enrollment_id=expired.challenge.enrollment_id, now=expires_at
            ).state,
            "expired",
        )

        revoked = self.issue(expected_agent_id="agent-revoked", workload_identity_uri="spiffe://lab/agent/agent-revoked")
        revoke_enrollment_challenge(
            self.db, enrollment_id=revoked.challenge.enrollment_id, now=self.now + timedelta(seconds=1)
        )
        with self.assertRaises(EnrollmentConflict):
            consume_enrollment_challenge(
                self.db,
                enrollment_id=revoked.challenge.enrollment_id,
                bootstrap_token=revoked.bootstrap_token,
                now=self.now + timedelta(seconds=2),
            )

        wrong = self.issue(expected_agent_id="agent-wrong", workload_identity_uri="spiffe://lab/agent/agent-wrong")
        with self.assertRaises(EnrollmentError):
            consume_enrollment_challenge(
                self.db,
                enrollment_id=wrong.challenge.enrollment_id,
                bootstrap_token="incorrect",
                now=self.now + timedelta(seconds=1),
            )
        self.assertEqual(wrong.challenge.state, "pending")

    def test_concurrent_consumption_has_exactly_one_winner(self):
        issued = self.issue()
        barrier = threading.Barrier(2)

        def consume():
            session = self.Session()
            try:
                barrier.wait(timeout=3)
                return consume_enrollment_challenge(
                    session,
                    enrollment_id=issued.challenge.enrollment_id,
                    bootstrap_token=issued.bootstrap_token,
                    now=self.now + timedelta(seconds=1),
                ).state
            except Exception as exc:
                return exc
            finally:
                session.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), range(2)))
        self.assertEqual(sum(result == "consumed" for result in results), 1)
        self.assertEqual(sum(isinstance(result, (EnrollmentConflict, EnrollmentStorageUnavailable)) for result in results), 1)

    def test_concurrent_consume_and_revoke_have_one_terminal_transition(self):
        issued = self.issue()
        barrier = threading.Barrier(2)

        def consume():
            session = self.Session()
            try:
                barrier.wait(timeout=3)
                return consume_enrollment_challenge(
                    session,
                    enrollment_id=issued.challenge.enrollment_id,
                    bootstrap_token=issued.bootstrap_token,
                    now=self.now + timedelta(seconds=1),
                )
            except Exception as exc:
                return exc
            finally:
                session.close()

        def revoke():
            session = self.Session()
            try:
                barrier.wait(timeout=3)
                return revoke_enrollment_challenge(
                    session,
                    enrollment_id=issued.challenge.enrollment_id,
                    now=self.now + timedelta(seconds=1),
                )
            except Exception as exc:
                return exc
            finally:
                session.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda operation: operation(), (consume, revoke)))
        successes = [result for result in results if isinstance(result, EnrollmentChallenge)]
        self.assertEqual(len(successes), 1)
        with self.Session() as session:
            stored = session.scalar(
                select(EnrollmentChallenge).where(
                    EnrollmentChallenge.enrollment_id == issued.challenge.enrollment_id
                )
            )
        self.assertIn(stored.state, ("consumed", "revoked"))
        self.assertEqual(stored.state, successes[0].state)

    def test_failed_challenge_insert_rolls_back_new_identity(self):
        from sqlalchemy import event as sqlalchemy_event

        def reject_challenge(_mapper, _connection, _target):
            raise IntegrityError("forced enrollment failure", {}, RuntimeError("test failure"))

        sqlalchemy_event.listen(EnrollmentChallenge, "before_insert", reject_challenge)
        try:
            with self.assertRaises(EnrollmentConflict):
                self.issue(expected_agent_id="agent-rollback", workload_identity_uri="spiffe://lab/agent/agent-rollback")
        finally:
            sqlalchemy_event.remove(EnrollmentChallenge, "before_insert", reject_challenge)
        self.assertIsNone(self.db.get(AgentIdentity, "agent-rollback"))
        self.assertEqual(self.db.scalars(select(EnrollmentChallenge)).all(), [])


if __name__ == "__main__":
    unittest.main()
