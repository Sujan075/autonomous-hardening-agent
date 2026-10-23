from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.audit.service import AuditError, append_event, verify_chain
from app.db.models import Base, SecurityAuditEvent


class AuditServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = create_engine(
            f"sqlite:///{Path(self.temp.name) / 'audit.sqlite'}",
            connect_args={"check_same_thread": False, "timeout": 10},
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def tearDown(self):
        self.engine.dispose()
        self.temp.cleanup()

    def test_append_orders_events_and_verifies_hash_chain(self):
        with self.Session() as session:
            first = append_event(session, event_type="test.first", metadata={"value": 1})
            session.commit()
            second = append_event(session, event_type="test.second", metadata={"value": 2})
            session.commit()
            self.assertEqual((first.sequence, second.sequence), (1, 2))
            self.assertEqual(second.previous_digest, first.event_digest)
            self.assertTrue(verify_chain(session).valid)

    def test_concurrent_appends_are_serialized_into_one_chain(self):
        def append(index):
            with self.Session() as session:
                row = append_event(session, event_type="test.concurrent", metadata={"index": index})
                session.commit()
                return row.sequence

        with ThreadPoolExecutor(max_workers=8) as pool:
            sequences = list(pool.map(append, range(24)))
        self.assertEqual(sorted(sequences), list(range(1, 25)))
        with self.Session() as session:
            result = verify_chain(session)
        self.assertTrue(result.valid, result.error)
        self.assertEqual(result.event_count, 24)

    def test_chain_verification_detects_tampered_content_and_removed_event(self):
        with self.Session() as session:
            append_event(session, event_type="test.one", metadata={"value": "original"})
            session.commit()
        with self.engine.begin() as connection:
            connection.execute(text("DROP TRIGGER security_audit_events_no_update"))
            connection.execute(text("UPDATE security_audit_events SET metadata_json='{}' WHERE sequence=1"))
        with self.Session() as session:
            self.assertFalse(verify_chain(session).valid)
        with self.engine.begin() as connection:
            connection.execute(text("DROP TRIGGER security_audit_events_no_delete"))
            connection.execute(text("DELETE FROM security_audit_events WHERE sequence=1"))
        with self.Session() as session:
            result = verify_chain(session)
        self.assertFalse(result.valid)

    def test_business_rollback_also_rolls_back_audit_event_and_head(self):
        with self.Session() as session:
            append_event(session, event_type="target.registered", target_id="target-1")
            session.rollback()
        with self.Session() as session:
            self.assertEqual(session.scalars(select(SecurityAuditEvent)).all(), [])
            self.assertTrue(verify_chain(session).valid)
            row = append_event(session, event_type="target.registered", target_id="target-2")
            session.commit()
            self.assertEqual(row.sequence, 1)

    def test_sensitive_metadata_is_rejected_before_persistence(self):
        with self.Session() as session:
            with self.assertRaises(AuditError):
                append_event(
                    session,
                    event_type="test.secret",
                    metadata={"nested": {"bootstrap_token": "should-not-persist"}},
                )
            session.rollback()
        with self.Session() as session:
            self.assertEqual(session.scalars(select(SecurityAuditEvent)).all(), [])
            self.assertTrue(verify_chain(session).valid)

    def test_malformed_metadata_is_rejected_and_oversized_corruption_fails_closed(self):
        with self.Session() as session:
            with self.assertRaises(AuditError):
                append_event(session, event_type="test.invalid", metadata=["not", "an", "object"])
            append_event(session, event_type="test.valid", metadata={"ok": True})
            session.commit()
        with self.engine.begin() as connection:
            connection.execute(text("DROP TRIGGER security_audit_events_no_update"))
            connection.execute(
                text("UPDATE security_audit_events SET metadata_json=:metadata WHERE sequence=1"),
                {"metadata": "x" * 17000},
            )
        with self.Session() as session:
            result = verify_chain(session)
        self.assertFalse(result.valid)


if __name__ == "__main__":
    unittest.main()
