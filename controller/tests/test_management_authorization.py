from datetime import datetime, timedelta, timezone
import time
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.auth.oidc import OIDCAuthenticator, OIDCSettings
from app.db.database import get_db
from app.audit.service import AuditError, append_event, verify_chain
from app.db.models import AgentIdentity, Base, DemoDecoyEvent, EnrollmentChallenge, SandboxRemediationRun, SecurityAuditEvent, Target
from app.main import app


ISSUER = "https://idp.example.test/issuer"
AUDIENCE = "hardening-controller"
ROLE_SETTINGS = {
    "OIDC_ISSUER": ISSUER,
    "OIDC_AUDIENCE": AUDIENCE,
    "OIDC_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
    "OIDC_ROLE_CLAIM": "roles",
    "OIDC_TARGET_READ_ROLE": "target-reader",
    "OIDC_TARGET_ADMIN_ROLE": "target-admin",
    "OIDC_ENROLLMENT_ADMIN_ROLE": "enrollment-admin",
}


class ManagementAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key(), as_dict=True)
        jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
        cls.jwks = {"keys": [jwk]}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = create_engine(
            f"sqlite:///{Path(self.temp.name) / 'management.sqlite'}",
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(self.engine, "connect")
        def foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

        def override_db():
            session = self.Session()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_db
        self.client = TestClient(app)
        self.env_patch = patch.dict("os.environ", ROLE_SETTINGS, clear=True)
        self.env_patch.start()
        settings = OIDCSettings(**{
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_url": ROLE_SETTINGS["OIDC_JWKS_URL"],
            "role_claim": "roles",
            "target_read_role": "target-reader",
            "target_admin_role": "target-admin",
            "enrollment_admin_role": "enrollment-admin",
        })
        self.auth_patch = patch(
            "app.auth.oidc._configured_authenticator",
            return_value=OIDCAuthenticator(settings, jwks_fetcher=lambda _url: self.jwks),
        )
        self.auth_patch.start()

    def tearDown(self):
        self.auth_patch.stop()
        self.env_patch.stop()
        app.dependency_overrides.clear()
        self.engine.dispose()
        self.temp.cleanup()

    def token(self, roles):
        now = int(time.time())
        return jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": "human-operator-42",
                "iat": now,
                "exp": now + 300,
                "roles": roles,
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": "test-key", "typ": "at+jwt"},
        )

    def bearer(self, roles):
        return {"Authorization": f"Bearer {self.token(roles)}"}

    def test_missing_oidc_configuration_denies_management_and_target_reads(self):
        with patch.dict("os.environ", {}, clear=True):
            self.auth_patch.stop()
            try:
                response = self.client.get("/api/targets")
                self.assertEqual(response.status_code, 503)
                self.assertEqual(self.client.post("/api/targets", json={
                    "name": "must-not-create", "platform": "ubuntu",
                }).status_code, 503)
                self.assertEqual(self.client.get("/api/targets/example/plan").status_code, 503)
                self.assertEqual(self.client.get("/api/targets/example/discovery").status_code, 503)
            finally:
                self.auth_patch.start()
        with self.Session() as session:
            self.assertEqual(session.scalars(select(Target)).all(), [])

    def test_target_routes_require_bearer_and_configured_roles(self):
        no_token = self.client.post("/api/targets", json={
            "name": "no-token", "platform": "ubuntu",
        })
        self.assertEqual(no_token.status_code, 401)

        wrong_role = self.client.post(
            "/api/targets",
            json={"name": "reader-cannot-create", "platform": "ubuntu"},
            headers=self.bearer(["target-reader"]),
        )
        self.assertEqual(wrong_role.status_code, 403)

        created = self.client.post(
            "/api/targets",
            json={"name": "authorized-target", "platform": "ubuntu"},
            headers=self.bearer(["target-admin"]),
        )
        self.assertEqual(created.status_code, 201)
        with self.Session() as session:
            events = session.scalars(select(SecurityAuditEvent)).all()
            self.assertEqual([event.event_type for event in events], ["target.registered"])
            self.assertEqual(events[0].actor_subject, "human-operator-42")
            self.assertTrue(verify_chain(session).valid)
        self.assertEqual(
            self.client.get("/api/targets", headers=self.bearer(["target-reader"])).status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/targets", headers=self.bearer(["target-admin"])).status_code,
            403,
        )

    def test_target_registration_rolls_back_when_audit_storage_fails(self):
        with patch("app.api.targets.append_event", side_effect=AuditError("audit unavailable")):
            response = self.client.post(
                "/api/targets",
                json={"name": "audit-failure-target", "platform": "ubuntu"},
                headers=self.bearer(["target-admin"]),
            )
        self.assertEqual(response.status_code, 503)
        with self.Session() as session:
            self.assertIsNone(session.scalar(select(Target).where(Target.name == "audit-failure-target")))
            self.assertEqual(session.scalars(select(SecurityAuditEvent)).all(), [])

    def test_enrollment_requires_role_and_discloses_token_once(self):
        target = self.client.post(
            "/api/targets",
            json={"name": "enrollment-target", "platform": "ubuntu"},
            headers=self.bearer(["target-admin"]),
        ).json()
        request = {
            "target_id": target["id"],
            "expected_agent_id": "pending-agent-1",
            "workload_identity_uri": "spiffe://lab/agent/pending-agent-1",
        }
        denied = self.client.post(
            "/api/enrollments", json=request, headers=self.bearer(["target-reader"])
        )
        self.assertEqual(denied.status_code, 403)
        self.assertIsNone(self._agent("pending-agent-1"))

        issued = self.client.post(
            "/api/enrollments", json=request, headers=self.bearer(["enrollment-admin"])
        )
        self.assertEqual(issued.status_code, 201)
        self.assertIn("no-store", issued.headers["cache-control"])
        self.assertIn("bootstrap_token", issued.json())
        token = issued.json()["bootstrap_token"]
        enrollment_id = issued.json()["enrollment_id"]
        self.assertTrue(token)
        self.assertEqual(self._agent("pending-agent-1").state, "pending")
        with self.Session() as session:
            events = session.scalars(select(SecurityAuditEvent)).all()
            issue_event = next(event for event in events if event.event_type == "enrollment.challenge.created")
            self.assertEqual(issue_event.actor_subject, "human-operator-42")
            self.assertNotIn(token, issue_event.metadata_json)
            self.assertNotIn(token, "".join(event.metadata_json for event in events))
            self.assertTrue(verify_chain(session).valid)

        inspected = self.client.get(
            f"/api/enrollments/{enrollment_id}", headers=self.bearer(["enrollment-admin"])
        )
        self.assertEqual(inspected.status_code, 200)
        self.assertNotIn("bootstrap_token", inspected.json())
        self.assertNotIn(token, inspected.text)

        duplicate = self.client.post(
            "/api/enrollments", json=request, headers=self.bearer(["enrollment-admin"])
        )
        self.assertEqual(duplicate.status_code, 409)

        revoked = self.client.delete(
            f"/api/enrollments/{enrollment_id}", headers=self.bearer(["enrollment-admin"])
        )
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(revoked.json()["state"], "revoked")
        self.assertNotIn(token, revoked.text)
        with self.Session() as session:
            event_types = session.scalars(select(SecurityAuditEvent.event_type)).all()
            self.assertIn("enrollment.challenge.revoked", event_types)

    def test_policy_review_route_exists_but_execution_and_identity_activation_do_not(self):
        self.assertEqual(self.client.post("/api/targets/target-1/execute", json={}).status_code, 404)
        self.assertEqual(self.client.post("/api/targets/target-1/rollback", json={}).status_code, 404)
        self.assertEqual(self.client.post("/api/agents/agent-1/activate", json={}).status_code, 404)
        self.assertEqual(self.client.get("/api/policies/1/review").status_code, 405)

    def test_policy_review_fails_closed_without_separate_role_configuration(self):
        response = self.client.post(
            "/api/policies/1/review",
            json={"decision": "approved", "rationale": "review"},
            headers=self.bearer(["target-admin", "enrollment-admin"]),
        )
        self.assertEqual(response.status_code, 503)

    def test_policy_review_requires_its_separate_role(self):
        with patch.dict("os.environ", {"OIDC_POLICY_REVIEW_ROLE": "policy-reviewer"}):
            response = self.client.post(
                "/api/policies/1/review",
                json={"decision": "approved", "rationale": "review"},
                headers=self.bearer(["target-admin", "enrollment-admin"]),
            )
        self.assertEqual(response.status_code, 403)

    def test_demo_and_audit_apis_are_read_only_role_gated_and_feature_gated(self):
        with self.Session() as session:
            append_event(session, event_type="decoy.simulated_batch_created", metadata={"mode": "SIMULATED"})
            session.add(DemoDecoyEvent(
                event_id="00000000-0000-0000-0000-000000000001", batch_id="00000000-0000-0000-0000-000000000002",
                decoy_id="loopback-decoy-simulator", occurred_at=datetime.now(timezone.utc),
                category="connection_attempt", source_address="198.51.100.10",
                source_classification="RFC5737_DOCUMENTATION_RANGE_SIMULATED",
                correlation_id="00000000-0000-0000-0000-000000000002:01",
                outcome="simulated_event_recorded", simulation_mode="SIMULATED",
            ))
            session.add(SandboxRemediationRun(
                run_id="run-demo-1", target_id="sandbox-local-demo", platform="ubuntu-sandbox-fixture",
                scenario="roundtrip", status="ROLLED_BACK", result_json='{"sandbox_only":true}',
            ))
            session.commit()

        disabled = self.client.get("/api/demo/decoy-events", headers=self.bearer(["target-reader"]))
        self.assertEqual(disabled.status_code, 404)
        self.assertEqual(self.client.get("/api/audit/events", headers=self.bearer(["target-reader"])).status_code, 503)
        with patch.dict("os.environ", {"AHA_ENABLE_DEMO_READ_API": "1", "OIDC_AUDIT_READ_ROLE": "audit-reader"}):
            self.assertEqual(self.client.get("/api/demo/decoy-events").status_code, 401)
            self.assertEqual(self.client.get("/api/demo/decoy-events", headers=self.bearer(["target-admin"])).status_code, 403)
            decoys = self.client.get("/api/demo/decoy-events", headers=self.bearer(["target-reader"]))
            runs = self.client.get("/api/demo/remediation-runs", headers=self.bearer(["target-reader"]))
            denied_audit = self.client.get("/api/audit/events", headers=self.bearer(["target-reader"]))
            audit = self.client.get("/api/audit/events", headers=self.bearer(["audit-reader"]))
            self.assertEqual(decoys.status_code, 200)
            self.assertEqual(decoys.json()["classification"], "SIMULATED")
            self.assertFalse(decoys.json()["decoys"][0]["executor_connected"])
            self.assertEqual(decoys.json()["events"][0]["simulation_mode"], "SIMULATED")
            self.assertEqual(runs.status_code, 200)
            self.assertTrue(runs.json()["runs"][0]["test_only_trust"])
            self.assertEqual(denied_audit.status_code, 403)
            self.assertEqual(audit.status_code, 200)
            self.assertEqual(audit.json()["integrity"]["status"], "VALID")
            self.assertEqual(self.client.post("/api/demo/decoy-events", headers=self.bearer(["target-reader"])).status_code, 405)
            self.assertEqual(self.client.get("/api/demo/decoy-events?limit=501", headers=self.bearer(["target-reader"])).status_code, 422)

    def _agent(self, agent_id):
        with self.Session() as session:
            return session.get(AgentIdentity, agent_id)


if __name__ == "__main__":
    unittest.main()
