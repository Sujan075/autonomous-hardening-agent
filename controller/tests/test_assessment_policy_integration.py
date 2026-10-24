from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.agents.identity import (
    activate_agent, activate_credential, add_pending_credential,
    bind_target_to_agent, create_pending_agent,
)
from app.assessments.policy import (
    ASSESSMENT_POLICY_SCHEMA, AssessmentPolicyError, evaluate_assessment, resolve_assessment_policy,
    validate_assessment_matches_policy,
)
from app.auth.oidc import Principal, require_target_read
from app.audit.service import AuditError
from app.db.database import get_db
from app.db.models import (
    AssessmentObservation, Base, SecurityAuditEvent, Target,
    TargetAgentBinding, TargetPolicyAssignment,
)
from app.main import app
from app.policies.registry import canonical_definition, register_definition
from app.policies.review import review_policy_definition
from app.policies.trust import PolicyTrustPin


NOW = datetime.now(timezone.utc)
OS_VERSION = "Ubuntu 24.04.5 LTS"
ASSESSMENT = {
    "platform": "ubuntu",
    "findings": [{
        "control_id": "TEST-SSH-1", "title": "Test SSH control", "status": "PASS",
        "applicability": "APPLICABLE", "severity": "INFO", "current_value": "no",
        "expected_value": "no", "message": "test fixture", "source": "test-only",
        "evidence": [{"name": "TestSetting", "value": "no", "source": "test-only"}],
    }],
}
DISCOVERY = {
    "hostname": "test-agent", "os": "linux", "os_version": OS_VERSION,
    "kernel": "test-kernel", "architecture": "arm64", "primary_ip": "127.0.0.1",
}


class AssessmentPolicyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.temp.name) / 'assessment.sqlite'}")

        @event.listens_for(self.engine, "connect")
        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db = self.Session()
        self.target = Target(
            id="target-policy-test", name="policy-test-target", platform="ubuntu",
            address="127.0.0.1", status="REGISTERED",
        )
        self.db.add(self.target)
        self.db.commit()
        self.original_pins = os.environ.get("POLICY_REVIEW_TRUST_PINS_JSON")
        os.environ.pop("POLICY_REVIEW_TRUST_PINS_JSON", None)
        app.dependency_overrides[get_db] = lambda: self.db
        app.dependency_overrides[require_target_read] = lambda: Principal(
            "https://identity.example.test", "assessment-requester", frozenset({"target-reader"})
        )
        self.client = TestClient(app)
        self.credential = self.add_agent()

    def tearDown(self):
        app.dependency_overrides.clear()
        if self.original_pins is None:
            os.environ.pop("POLICY_REVIEW_TRUST_PINS_JSON", None)
        else:
            os.environ["POLICY_REVIEW_TRUST_PINS_JSON"] = self.original_pins
        self.db.close()
        self.engine.dispose()
        self.temp.cleanup()

    def add_agent(self):
        agent_id = "agent-policy-test"
        uri = f"spiffe://test/agent/{agent_id}"
        create_pending_agent(self.db, agent_id=agent_id, workload_identity_uri=uri)
        credential = add_pending_credential(
            self.db, agent_id=agent_id, fingerprint_sha256="sha256:" + "c" * 64,
            identity_uri=uri, not_before=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(days=1),
        )
        activate_agent(self.db, agent_id)
        activate_credential(self.db, credential.id, now=NOW)
        bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id=agent_id,
            credential_id=credential.id, now=NOW,
        )
        return credential

    def make_policy(self, *, version="test-policy-v1", os_version=OS_VERSION, reviewed=True, assigned=True):
        definition = {
            "schema": ASSESSMENT_POLICY_SCHEMA,
            "platform": "ubuntu",
            "os_version": os_version,
            "architecture": "arm64",
            "controls": [{"control_id": "TEST-SSH-1", "expected_value": "no"}],
        }
        row = register_definition(
            self.db, platform="ubuntu", policy_version=version,
            catalog_version="test-catalog-v1", definition=definition,
            provenance_reference="test-only:assessment-policy-fixture",
        )
        pin = PolicyTrustPin(
            provenance_reference=row.provenance_reference,
            source_evidence_sha256="sha256:" + "9" * 64,
            definition_sha256=row.definition_sha256,
            platform=row.platform, policy_version=row.policy_version,
            catalog_version=row.catalog_version, applicability_confirmed=True,
        )
        os.environ["POLICY_REVIEW_TRUST_PINS_JSON"] = json.dumps([{
            "provenance_reference": pin.provenance_reference,
            "source_evidence_sha256": pin.source_evidence_sha256,
            "definition_sha256": pin.definition_sha256,
            "platform": pin.platform, "policy_version": pin.policy_version,
            "catalog_version": pin.catalog_version, "applicability_confirmed": True,
        }])
        if reviewed:
            review_policy_definition(
                self.db, definition_id=row.id, decision="approved",
                rationale="test fixture; not authoritative benchmark evidence",
                source_evidence_sha256=pin.source_evidence_sha256,
                reviewer=Principal("https://reviewer.example.test", "fixture-reviewer", frozenset({"policy-reviewer"})),
                trust_pins=(pin,), now=NOW,
            )
        if assigned:
            from app.policies.registry import assign_policy_to_target
            assign_policy_to_target(self.db, target_id=self.target.id, definition_id=row.id)
        return row

    def agent_transport(self, assessment=ASSESSMENT, discovery=DISCOVERY):
        responses = [
            httpx.Response(200, json=discovery, request=httpx.Request("GET", "http://127.0.0.1:19000/discovery")),
            httpx.Response(200, json=assessment, request=httpx.Request("GET", "http://127.0.0.1:19000/assessment")),
        ]
        stream_patch = patch("app.api.agent_status.target_agent_transport", return_value=nullcontext(None))
        stream_patch.start()
        self.addCleanup(stream_patch.stop)
        http_patch = patch("app.agents.client.httpx.stream", side_effect=[nullcontext(r) for r in responses])
        http_patch.start()
        self.addCleanup(http_patch.stop)

    def test_reviewed_test_policy_matches_target_and_assessment_and_is_audited(self):
        row = self.make_policy()
        self.agent_transport()
        response = self.client.get(f"/api/targets/{self.target.id}/assessment")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["assessment"], ASSESSMENT)
        self.assertEqual(result["policy_status"], "reviewed_assignment_matched_to_agent_reported_result")
        self.assertEqual(result["policy_evaluation"]["decision"], "COMPLIANT")
        self.assertEqual(result["policy_evaluation"]["controls"][0]["observed_value"], "no")
        self.assertEqual(result["policy"]["definition_digest"], row.definition_sha256)
        self.assertEqual(result["policy"]["os_version"], OS_VERSION)
        self.assertFalse(result["policy"]["agent_channel_authenticated"])
        self.assertEqual(result["policy"]["planning_recommendations"], "available_separately_at_plan_endpoint")
        observation = self.db.scalar(select(AssessmentObservation))
        self.assertEqual(observation.policy_version, row.policy_version)
        self.assertEqual(observation.catalog_version, row.catalog_version)
        self.assertEqual(observation.trust_status, "controller_observed_unauthenticated")
        event_row = self.db.scalar(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "assessment.collected"))
        self.assertIsNotNone(event_row)
        self.assertEqual(event_row.actor_subject, "assessment-requester")
        self.assertEqual(event_row.policy_definition_id, row.id)
        self.assertNotIn("token", event_row.metadata_json.lower())
        self.assertNotIn("credential", event_row.metadata_json.lower())

    def test_missing_assignment_fails_before_agent_request(self):
        response = self.client.get(f"/api/targets/{self.target.id}/assessment")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.db.scalars(select(AssessmentObservation)).all(), [])
        self.assertEqual(self.db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "assessment.collected")).all(), [])
        self.assertEqual(len(self.db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "assessment.failed")).all()), 1)

    def test_unreviewed_policy_is_rejected(self):
        row = self.make_policy(reviewed=False, assigned=False)
        binding = self.db.scalar(select(TargetAgentBinding).where(TargetAgentBinding.target_id == self.target.id))
        self.db.add(TargetPolicyAssignment(
            target_id=self.target.id, definition_id=row.id,
            binding_generation=binding.generation, state="active",
        ))
        self.db.commit()
        with self.assertRaises(AssessmentPolicyError):
            resolve_assessment_policy(self.db, target=self.target)

    def test_disabled_policy_is_rejected(self):
        row = self.make_policy()
        row.enabled = False
        self.db.commit()
        with self.assertRaises(AssessmentPolicyError):
            resolve_assessment_policy(self.db, target=self.target)

    def test_stale_definition_review_is_rejected(self):
        row = self.make_policy()
        row.definition_json, row.definition_sha256 = canonical_definition({
            "schema": ASSESSMENT_POLICY_SCHEMA, "platform": "ubuntu",
            "os_version": OS_VERSION, "architecture": "arm64",
            "controls": [{"control_id": "TEST-SSH-1", "expected_value": "yes"}],
        })
        self.db.commit()
        with self.assertRaises(AssessmentPolicyError):
            resolve_assessment_policy(self.db, target=self.target)

    def test_revoked_policy_is_rejected(self):
        row = self.make_policy()
        row.verification_status = "revoked"
        row.enabled = False
        self.db.commit()
        with self.assertRaises(AssessmentPolicyError):
            resolve_assessment_policy(self.db, target=self.target)

    def test_target_agent_binding_and_credential_must_be_current(self):
        row = self.make_policy()
        self.credential.state = "revoked"
        self.credential.revoked_at = NOW
        self.db.commit()
        with self.assertRaises(AssessmentPolicyError):
            resolve_assessment_policy(self.db, target=self.target)

    def test_stale_target_binding_generation_invalidates_assignment(self):
        self.make_policy()
        assignment = self.db.get(TargetPolicyAssignment, self.target.id)
        assignment.binding_generation = "stale-generation"
        self.db.commit()
        with self.assertRaises(AssessmentPolicyError):
            resolve_assessment_policy(self.db, target=self.target)

    def test_missing_active_target_agent_binding_is_rejected(self):
        self.make_policy()
        binding = self.db.scalar(select(TargetAgentBinding).where(TargetAgentBinding.target_id == self.target.id))
        binding.state = "revoked"
        self.db.commit()
        with self.assertRaises(AssessmentPolicyError):
            resolve_assessment_policy(self.db, target=self.target)

    def test_incompatible_reported_os_version_is_rejected(self):
        row = self.make_policy(os_version="Ubuntu 22.04 LTS")
        policy = resolve_assessment_policy(self.db, target=self.target)
        with self.assertRaises(AssessmentPolicyError):
            validate_assessment_matches_policy(policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(ASSESSMENT))

    def test_assessment_parameters_must_match_exact_ordered_policy_contract(self):
        row = self.make_policy()
        policy = resolve_assessment_policy(self.db, target=self.target)
        mutated = json.loads(json.dumps(ASSESSMENT))
        mutated["findings"][0]["expected_value"] = "yes"
        with self.assertRaises(AssessmentPolicyError):
            validate_assessment_matches_policy(policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(mutated))
        missing = {"platform": "ubuntu", "findings": []}
        with self.assertRaises(AssessmentPolicyError):
            validate_assessment_matches_policy(policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(missing))
        unexpected = json.loads(json.dumps(ASSESSMENT))
        unexpected["findings"].append({**unexpected["findings"][0], "control_id": "UNEXPECTED"})
        with self.assertRaises(AssessmentPolicyError):
            validate_assessment_matches_policy(policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(unexpected))
        with self.assertRaises(AssessmentPolicyError):
            validate_assessment_matches_policy(policy, target=self.target, discovery={**DISCOVERY, "architecture": "amd64"}, raw_assessment=json.dumps(ASSESSMENT))

    def test_policy_evaluation_distinguishes_noncompliant_and_uncertain_findings(self):
        self.make_policy()
        policy = resolve_assessment_policy(self.db, target=self.target)

        failing = json.loads(json.dumps(ASSESSMENT))
        finding = failing["findings"][0]
        finding.update(status="FAIL", current_value="yes")
        finding["evidence"][0]["value"] = "yes"
        assessment = validate_assessment_matches_policy(
            policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(failing)
        )
        decision = evaluate_assessment(policy, assessment)
        self.assertEqual(decision.decision, "NON_COMPLIANT")

        unknown = json.loads(json.dumps(ASSESSMENT))
        unknown["findings"][0]["status"] = "UNKNOWN"
        assessment = validate_assessment_matches_policy(
            policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(unknown)
        )
        decision = evaluate_assessment(policy, assessment)
        self.assertEqual(decision.decision, "INDETERMINATE")
        self.assertTrue(any("unknown status" in reason for reason in decision.reasons))

        errored = json.loads(json.dumps(ASSESSMENT))
        errored["findings"][0].update(status="ERROR", error={
            "code": "COLLECTION_FAILED", "message": "fixture failure", "source": "test-only",
        })
        assessment = validate_assessment_matches_policy(
            policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(errored)
        )
        self.assertEqual(evaluate_assessment(policy, assessment).decision, "INDETERMINATE")

    def test_policy_evaluation_rejects_unsubstantiated_or_contradictory_evidence(self):
        self.make_policy()
        policy = resolve_assessment_policy(self.db, target=self.target)

        malformed = json.loads(json.dumps(ASSESSMENT))
        malformed["findings"][0]["evidence"][0]["value"] = "yes"
        assessment = validate_assessment_matches_policy(
            policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(malformed)
        )
        self.assertEqual(evaluate_assessment(policy, assessment).decision, "INDETERMINATE")

        duplicate_evidence = json.loads(json.dumps(ASSESSMENT))
        duplicate_evidence["findings"][0]["evidence"].append(
            duplicate_evidence["findings"][0]["evidence"][0]
        )
        assessment = validate_assessment_matches_policy(
            policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(duplicate_evidence)
        )
        self.assertEqual(evaluate_assessment(policy, assessment).decision, "INDETERMINATE")

        contradictory = json.loads(json.dumps(ASSESSMENT))
        contradictory["findings"][0]["current_value"] = "yes"
        contradictory["findings"][0]["evidence"][0]["value"] = "yes"
        assessment = validate_assessment_matches_policy(
            policy, target=self.target, discovery=DISCOVERY, raw_assessment=json.dumps(contradictory)
        )
        self.assertEqual(evaluate_assessment(policy, assessment).decision, "INDETERMINATE")

    def test_agent_failure_or_malformed_result_creates_no_success_audit_or_observation(self):
        self.make_policy()
        with patch("app.api.agent_status.target_agent_transport", return_value=nullcontext(None)):
            with patch("app.agents.client.httpx.stream", side_effect=httpx.ConnectError("offline")):
                failed = self.client.get(f"/api/targets/{self.target.id}/assessment")
        self.assertEqual(failed.status_code, 502)
        self.assertEqual(self.db.scalars(select(AssessmentObservation)).all(), [])
        self.assertEqual(self.db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "assessment.collected")).all(), [])
        self.assertEqual(len(self.db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "assessment.failed")).all()), 1)

        responses = [
            httpx.Response(200, json=DISCOVERY, request=httpx.Request("GET", "http://127.0.0.1/discovery")),
            httpx.Response(200, content=b"not-json", request=httpx.Request("GET", "http://127.0.0.1/assessment")),
        ]
        with patch("app.api.agent_status.target_agent_transport", return_value=nullcontext(None)):
            with patch("app.agents.client.httpx.stream", side_effect=[nullcontext(r) for r in responses]):
                malformed = self.client.get(f"/api/targets/{self.target.id}/assessment")
        self.assertEqual(malformed.status_code, 502)
        self.assertEqual(self.db.scalars(select(AssessmentObservation)).all(), [])
        self.assertEqual(self.db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "assessment.collected")).all(), [])
        self.assertEqual(len(self.db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == "assessment.failed")).all()), 2)

    def test_audit_failure_rolls_back_observation_and_never_reports_success(self):
        self.make_policy()
        responses = [
            httpx.Response(200, json=DISCOVERY, request=httpx.Request("GET", "http://127.0.0.1/discovery")),
            httpx.Response(200, json=ASSESSMENT, request=httpx.Request("GET", "http://127.0.0.1/assessment")),
        ]
        with patch("app.api.agent_status.target_agent_transport", return_value=nullcontext(None)):
            with patch("app.agents.client.httpx.stream", side_effect=[nullcontext(r) for r in responses]):
                with patch("app.api.agent_status.append_event", side_effect=AuditError("audit unavailable")):
                    response = self.client.get(f"/api/targets/{self.target.id}/assessment")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.db.scalars(select(AssessmentObservation)).all(), [])


if __name__ == "__main__":
    unittest.main()
