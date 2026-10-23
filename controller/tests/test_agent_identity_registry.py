from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.agents.identity import (
    IdentityLifecycleError, activate_agent, activate_credential,
    add_pending_credential, bind_target_to_agent, create_pending_agent,
    replace_agent_identity, revoke_agent,
)
from app.db.models import AgentIdentity, Base, Target, TargetPolicyAssignment
from app.assessments.provenance import (
    ObservationRejected, SupportedBindingVersions,
    resolve_assessment_observation, resolve_assigned_assessment_observation,
    store_assessment_observation,
)
from app.policies.registry import (
    RegistryError, assign_policy_to_target, canonical_definition,
    register_definition, resolve_target_assignment, revoke_definition,
)

NOW = datetime.now(timezone.utc)
FINGERPRINT = "sha256:" + "a" * 64


class IdentityRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        path = Path(self.tempdir.name) / "ephemeral.sqlite"
        self.engine = create_engine(f"sqlite:///{path}")

        @event.listens_for(self.engine, "connect")
        def fk(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)
        self.db: Session = sessionmaker(bind=self.engine, expire_on_commit=False)()
        self.target = Target(
            id="target-1", name="target", platform="ubuntu",
            address="127.0.0.1", status="REGISTERED"
        )
        self.db.add(self.target)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()
        self.tempdir.cleanup()

    def add_agent(self, agent_id, fingerprint=FINGERPRINT):
        create_pending_agent(
            self.db, agent_id=agent_id, workload_identity_uri=f"spiffe://lab/agent/{agent_id}"
        )
        credential = add_pending_credential(
            self.db, agent_id=agent_id, fingerprint_sha256=fingerprint,
            identity_uri=f"spiffe://lab/agent/{agent_id}",
            not_before=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(days=1),
        )
        activate_agent(self.db, agent_id)
        activate_credential(self.db, credential.id, now=NOW)
        return credential

    def test_agent_id_and_credential_fingerprint_are_unique(self):
        create_pending_agent(self.db, agent_id="agent-one", workload_identity_uri="spiffe://lab/agent/agent-one")
        with self.assertRaises(IdentityLifecycleError):
            create_pending_agent(self.db, agent_id="agent-one", workload_identity_uri="spiffe://lab/agent/agent-one")
        credential = add_pending_credential(
            self.db, agent_id="agent-one", fingerprint_sha256=FINGERPRINT,
            identity_uri="spiffe://lab/agent/agent-one",
            not_before=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(hours=1),
        )
        activate_agent(self.db, "agent-one")
        activate_credential(self.db, credential.id, now=NOW)
        create_pending_agent(self.db, agent_id="agent-two", workload_identity_uri="spiffe://lab/agent/agent-two")
        with self.assertRaises(IdentityLifecycleError):
            add_pending_credential(
                self.db, agent_id="agent-two", fingerprint_sha256=FINGERPRINT,
                identity_uri="spiffe://lab/agent/agent-two",
                not_before=NOW, expires_at=NOW + timedelta(hours=1),
            )

    def test_binding_generation_replacement_invalidates_policy_assignment(self):
        first_credential = self.add_agent("agent-one")
        first_binding = bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-one",
            credential_id=first_credential.id, now=NOW
        )
        row = register_definition(
            self.db, platform="ubuntu", policy_version="p1", catalog_version="c1",
            definition={"controls": ["SSH-1"]}, provenance_reference="prototype:local",
        )
        row.verification_status = "verified"
        row.applicability_status = "confirmed"
        row.enabled = True
        self.db.commit()
        assignment = assign_policy_to_target(
            self.db, target_id=self.target.id, definition_id=row.id
        )
        self.assertEqual(
            resolve_target_assignment(self.db, target_id=self.target.id).binding_generation,
            first_binding.generation,
        )

        second_credential = self.add_agent("agent-two", "sha256:" + "b" * 64)
        second_binding = bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-two",
            credential_id=second_credential.id, now=NOW
        )
        self.db.refresh(assignment)
        self.assertNotEqual(first_binding.generation, second_binding.generation)
        self.assertEqual(assignment.state, "stale")
        with self.assertRaises(RegistryError):
            resolve_target_assignment(self.db, target_id=self.target.id)

    def test_binding_replacement_invalidates_prior_assessment_context(self):
        first = self.add_agent("agent-evidence-one")
        bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-evidence-one",
            credential_id=first.id, now=NOW,
        )
        assessment = b'{"platform":"ubuntu","findings":[]}'
        row = store_assessment_observation(
            self.db, target=self.target, raw_payload=assessment,
            policy_version="policy-v1", catalog_version="catalog-v1", collected_at=NOW,
        )
        second = self.add_agent("agent-evidence-two", "sha256:" + "e" * 64)
        bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-evidence-two",
            credential_id=second.id, now=NOW + timedelta(seconds=1),
        )
        with self.assertRaises(ObservationRejected):
            resolve_assessment_observation(
                self.db, observation_id=row.observation_id, target=self.target,
                now=NOW + timedelta(seconds=2), max_age=timedelta(minutes=5),
                versions=SupportedBindingVersions(frozenset({"policy-v1"}), frozenset({"catalog-v1"})),
                expected_policy_version="policy-v1", expected_catalog_version="catalog-v1",
            )

    def test_revocation_replacement_and_expiry_fail_closed(self):
        credential = self.add_agent("agent-one")
        binding = bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-one",
            credential_id=credential.id, now=NOW
        )
        replacement = replace_agent_identity(
            self.db, old_agent_id="agent-one", replacement_agent_id="agent-new",
            replacement_identity_uri="spiffe://lab/agent/agent-new", now=NOW
        )
        self.assertEqual(replacement.state, "pending")
        self.db.refresh(binding)
        self.db.refresh(credential)
        self.assertEqual(binding.state, "replaced")
        self.assertEqual(credential.state, "replaced")
        self.assertEqual(self.db.get(AgentIdentity, "agent-one").state, "replaced")

        pending = add_pending_credential(
            self.db, agent_id="agent-new", fingerprint_sha256="sha256:" + "c" * 64,
            identity_uri="spiffe://lab/agent/agent-new",
            not_before=NOW - timedelta(days=2), expires_at=NOW - timedelta(days=1),
        )
        activate_agent(self.db, "agent-new")
        with self.assertRaises(IdentityLifecycleError):
            activate_credential(self.db, pending.id, now=NOW)
        revoke_agent(self.db, "agent-new", now=NOW)
        self.assertEqual(self.db.get(AgentIdentity, "agent-new").state, "revoked")

    def test_credential_rotation_replaces_old_binding_and_requires_new_generation(self):
        old = self.add_agent("agent-rotation")
        old_binding = bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-rotation",
            credential_id=old.id, now=NOW,
        )
        new = add_pending_credential(
            self.db, agent_id="agent-rotation", fingerprint_sha256="sha256:" + "d" * 64,
            identity_uri="spiffe://lab/agent/agent-rotation",
            not_before=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(days=2),
        )
        activate_credential(self.db, new.id, now=NOW)
        self.db.refresh(old)
        self.db.refresh(old_binding)
        self.assertEqual(old.state, "replaced")
        self.assertEqual(old_binding.state, "replaced")
        new_binding = bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-rotation",
            credential_id=new.id, now=NOW,
        )
        self.assertNotEqual(old_binding.generation, new_binding.generation)

    def test_policy_registry_defaults_unverified_and_detects_digest_tampering(self):
        definition = {"controls": ["SSH-1"], "version": 1}
        canonical, digest = canonical_definition(definition)
        self.assertEqual(canonical, '{"controls":["SSH-1"],"version":1}')
        self.assertTrue(digest.startswith("sha256:"))
        row = register_definition(
            self.db, platform="ubuntu", policy_version="p1", catalog_version="c1",
            definition=definition, provenance_reference="prototype:four-ssh-controls",
        )
        self.assertEqual(row.verification_status, "unverified")
        self.assertFalse(row.enabled)
        with self.assertRaises(RegistryError):
            assign_policy_to_target(self.db, target_id=self.target.id, definition_id=row.id)
        self.db.execute(
            text("UPDATE policy_catalog_definitions SET definition_sha256 = :digest WHERE id = :id"),
            {"digest": "sha256:" + "f" * 64, "id": row.id},
        )
        self.db.commit()
        with self.assertRaises(RegistryError):
            assign_policy_to_target(self.db, target_id=self.target.id, definition_id=row.id)

    def test_verified_policy_cannot_be_assigned_to_unsupported_platform(self):
        credential = self.add_agent("agent-one")
        bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-one",
            credential_id=credential.id, now=NOW
        )
        row = register_definition(
            self.db, platform="windows", policy_version="p1", catalog_version="c1",
            definition={"controls": []}, provenance_reference="fixture:test-only",
        )
        row.verification_status = "verified"
        row.applicability_status = "confirmed"
        row.enabled = True
        self.db.commit()
        with self.assertRaises(RegistryError):
            assign_policy_to_target(self.db, target_id=self.target.id, definition_id=row.id)

    def test_revoking_assigned_policy_invalidates_target_assignment(self):
        credential = self.add_agent("agent-policy-revoke")
        bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-policy-revoke",
            credential_id=credential.id, now=NOW,
        )
        row = register_definition(
            self.db, platform="ubuntu", policy_version="p1", catalog_version="c1",
            definition={"controls": ["SSH-1"]}, provenance_reference="fixture:reviewed",
        )
        row.verification_status = "verified"
        row.applicability_status = "confirmed"
        row.enabled = True
        self.db.commit()
        assign_policy_to_target(self.db, target_id=self.target.id, definition_id=row.id)
        revoke_definition(self.db, definition_id=row.id)
        self.assertEqual(self.db.get(TargetPolicyAssignment, self.target.id).state, "stale")
        with self.assertRaises(RegistryError):
            resolve_target_assignment(self.db, target_id=self.target.id)

    def test_assessment_resolver_uses_controller_assignment_not_agent_versions(self):
        credential = self.add_agent("agent-policy")
        bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="agent-policy",
            credential_id=credential.id, now=NOW,
        )
        definition = register_definition(
            self.db, platform="ubuntu", policy_version="policy-v1",
            catalog_version="catalog-v1", definition={"controls": ["SSH-1"]},
            provenance_reference="fixture:verified-source",
        )
        # The fixture simulates an external review outcome. Production entry
        # creation itself always starts disabled, unverified and unconfirmed.
        definition.verification_status = "verified"
        definition.applicability_status = "confirmed"
        definition.enabled = True
        self.db.commit()
        assign_policy_to_target(self.db, target_id=self.target.id, definition_id=definition.id)
        row = store_assessment_observation(
            self.db, target=self.target,
            raw_payload=b'{"platform":"ubuntu","findings":[]}',
            policy_version="policy-v1", catalog_version="catalog-v1", collected_at=NOW,
        )
        resolved = resolve_assigned_assessment_observation(
            self.db, observation_id=row.observation_id, target=self.target,
            now=NOW + timedelta(seconds=1), max_age=timedelta(minutes=5),
        )
        self.assertIsNotNone(resolved.evidence_digest)
        self.assertIsNone(resolved.approval_context)
        self.assertEqual(resolved.approval_state.value, "unresolved_untrusted")


if __name__ == "__main__":
    unittest.main()
