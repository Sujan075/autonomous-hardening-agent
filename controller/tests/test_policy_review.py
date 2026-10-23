from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.audit.service import AuditError
from app.auth.oidc import Principal
from app.db.models import Base, PolicyCatalogDefinition, PolicyReviewRecord, SecurityAuditEvent
from app.policies.registry import RegistryError, canonical_definition, register_definition
from app.policies.review import (
    PolicyReviewError,
    review_policy_definition,
    revoke_policy_definition,
    set_policy_enabled,
)
from app.policies.trust import PolicyTrustPin


class PolicyReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.temp.name) / 'policy.sqlite'}")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db = self.Session()
        self.original_pins = os.environ.get("POLICY_REVIEW_TRUST_PINS_JSON")
        os.environ.pop("POLICY_REVIEW_TRUST_PINS_JSON", None)
        self.reviewer = Principal("https://idp.test", "reviewer-1", frozenset({"policy-reviewer"}))
        self.now = datetime(2026, 10, 23, tzinfo=timezone.utc)

    def tearDown(self):
        if self.original_pins is None:
            os.environ.pop("POLICY_REVIEW_TRUST_PINS_JSON", None)
        else:
            os.environ["POLICY_REVIEW_TRUST_PINS_JSON"] = self.original_pins
        self.db.close()
        self.engine.dispose()
        self.temp.cleanup()

    def make_definition(self, *, platform="ubuntu", policy="p1", catalog="c1", source="fixture:source"):
        return register_definition(
            self.db,
            platform=platform,
            policy_version=policy,
            catalog_version=catalog,
            definition={"controls": ["SSH-1"]},
            provenance_reference=source,
        )

    def pin_for(self, row, *, source_digest=None, definition_digest=None, platform=None, policy=None, catalog=None):
        return PolicyTrustPin(
            provenance_reference=row.provenance_reference,
            source_evidence_sha256=source_digest or "sha256:" + "a" * 64,
            definition_sha256=definition_digest or row.definition_sha256,
            platform=platform or row.platform,
            policy_version=policy or row.policy_version,
            catalog_version=catalog or row.catalog_version,
            applicability_confirmed=True,
        )

    def configure_pin(self, pin):
        os.environ["POLICY_REVIEW_TRUST_PINS_JSON"] = json.dumps([{
            "provenance_reference": pin.provenance_reference,
            "source_evidence_sha256": pin.source_evidence_sha256,
            "definition_sha256": pin.definition_sha256,
            "platform": pin.platform,
            "policy_version": pin.policy_version,
            "catalog_version": pin.catalog_version,
            "applicability_confirmed": pin.applicability_confirmed,
        }])

    def approve(self, row, pin=None):
        pin = pin or self.pin_for(row)
        self.configure_pin(pin)
        return review_policy_definition(
            self.db,
            definition_id=row.id,
            decision="approved",
            rationale="verified against pinned source and applicability record",
            source_evidence_sha256=pin.source_evidence_sha256,
            reviewer=self.reviewer,
            trust_pins=(pin,),
            now=self.now,
        )

    def test_missing_or_mismatched_provenance_leaves_definition_disabled(self):
        row = self.make_definition()
        with self.assertRaises(PolicyReviewError):
            review_policy_definition(
                self.db,
                definition_id=row.id,
                decision="approved",
                rationale="attempt without evidence",
                source_evidence_sha256=None,
                reviewer=self.reviewer,
                trust_pins=(),
                now=self.now,
            )
        self.db.refresh(row)
        self.assertFalse(row.enabled)
        self.assertEqual(row.verification_status, "unverified")
        self.assertEqual(self.db.scalars(select(PolicyReviewRecord)).all(), [])

        with self.assertRaises(PolicyReviewError):
            self.approve(row, self.pin_for(row, definition_digest="sha256:" + "f" * 64))
        self.db.refresh(row)
        self.assertFalse(row.enabled)

    def test_unsupported_platform_and_policy_or_catalog_version_are_not_approvable(self):
        row = self.make_definition(platform="unsupported-os")
        with self.assertRaises(PolicyReviewError):
            self.approve(row, self.pin_for(row, platform="ubuntu"))
        with self.assertRaises(PolicyReviewError):
            self.approve(row, self.pin_for(row, policy="p2"))
        with self.assertRaises(PolicyReviewError):
            self.approve(row, self.pin_for(row, catalog="c2"))
        self.assertFalse(row.enabled)

    def test_success_requires_exact_configured_provenance_and_records_authenticated_reviewer(self):
        row = self.make_definition()
        pin = self.pin_for(row)
        review = self.approve(row, pin)
        self.assertEqual(review.reviewer_issuer, self.reviewer.issuer)
        self.assertEqual(review.reviewer_subject, self.reviewer.subject)
        self.assertEqual(review.reviewed_definition_sha256, row.definition_sha256)
        self.assertEqual(review.reviewed_source_evidence_sha256, pin.source_evidence_sha256)
        self.assertEqual((row.verification_status, row.applicability_status, row.enabled), ("verified", "confirmed", True))
        event = self.db.scalar(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "policy.review.approved"))
        self.assertIsNotNone(event)
        self.assertEqual(event.actor_subject, self.reviewer.subject)
        self.assertTrue(event.event_digest.startswith("sha256:"))

    def test_rejection_disable_and_revocation_are_audited_and_fail_closed(self):
        row = self.make_definition()
        review_policy_definition(
            self.db,
            definition_id=row.id,
            decision="rejected",
            rationale="source could not be verified",
            source_evidence_sha256=None,
            reviewer=self.reviewer,
            trust_pins=(),
            now=self.now,
        )
        self.assertFalse(row.enabled)
        pin = self.pin_for(row)
        self.approve(row, pin)
        set_policy_enabled(
            self.db,
            definition_id=row.id,
            enabled=False,
            rationale="temporarily disabled",
            reviewer=self.reviewer,
            trust_pins=(pin,),
            now=self.now,
        )
        self.assertFalse(row.enabled)
        review_policy_definition(
            self.db,
            definition_id=row.id,
            decision="rejected",
            rationale="withdraw approval",
            source_evidence_sha256=None,
            reviewer=self.reviewer,
            trust_pins=(),
            now=self.now,
        )
        revoke_policy_definition(
            self.db,
            definition_id=row.id,
            rationale="retire this catalog record",
            reviewer=self.reviewer,
            trust_pins=(),
            now=self.now,
        )
        self.assertFalse(row.enabled)
        self.assertEqual(row.verification_status, "revoked")
        event_types = self.db.scalars(select(SecurityAuditEvent.event_type)).all()
        self.assertIn("policy.review.rejected", event_types)
        self.assertIn("policy.definition.disabled", event_types)
        self.assertIn("policy.review.revoked", event_types)

    def test_review_becomes_stale_when_definition_changes_and_cannot_be_reenabled(self):
        row = self.make_definition()
        self.approve(row)
        updated_json, updated_digest = canonical_definition({"controls": ["SSH-1", "SSH-2"]})
        row.definition_json = updated_json
        row.definition_sha256 = updated_digest
        self.db.commit()
        with self.assertRaises(RegistryError):
            set_policy_enabled(
                self.db,
                definition_id=row.id,
                enabled=True,
                rationale="stale review must fail",
                reviewer=self.reviewer,
                trust_pins=(self.pin_for(row),),
                now=self.now,
            )

    def test_audit_failure_rolls_back_approval_and_state_transition(self):
        row = self.make_definition()
        pin = self.pin_for(row)
        self.configure_pin(pin)
        with patch("app.policies.review.append_event", side_effect=AuditError("unavailable")):
            with self.assertRaises(AuditError):
                review_policy_definition(
                    self.db,
                    definition_id=row.id,
                    decision="approved",
                    rationale="test audit failure",
                    source_evidence_sha256=pin.source_evidence_sha256,
                    reviewer=self.reviewer,
                    trust_pins=(pin,),
                    now=self.now,
                )
        self.db.expire_all()
        row = self.db.get(PolicyCatalogDefinition, row.id)
        self.assertFalse(row.enabled)
        self.assertEqual(row.verification_status, "unverified")
        self.assertEqual(self.db.scalars(select(PolicyReviewRecord)).all(), [])


if __name__ == "__main__":
    unittest.main()
