"""Controller production binding contracts and Go interoperability vectors."""

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest
from types import SimpleNamespace

from app.approvals.bindings import (
    Action,
    Assessment,
    AssessmentRecord,
    BindingValidationError,
    ControllerTargetContext,
    EvidenceItem,
    EvidenceOrigin,
    Finding,
    MAX_ASSESSMENT_JSON_BYTES,
    NormalizedError,
    Plan,
    RecoveryFileState,
    RecoveryManifest,
    RecoveryState,
    Timestamp,
    action_digest,
    build_evidence_record,
    canonical_action_bytes,
    canonical_evidence_bytes,
    canonical_plan_binding_bytes,
    canonical_recovery_manifest_bytes,
    evidence_digest,
    parse_assessment_json,
    plan_binding_digest,
    recovery_manifest_digest,
)


VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "agent"
    / "internal"
    / "approval"
    / "testdata"
    / "action_digest_v1.json"
)
BINDING_VECTOR_PATH = VECTOR_PATH.with_name("approval_bindings_v1.json")


def vector_action() -> Action:
    return Action(
        action_id="ACT-TEST-1",
        control_id="CTL-01",
        title="Disable “root” login",
        action_type="set_sshd_option",
        current_value="yes",
        desired_value="no",
        risk_score=3.5,
        execution_mode="APPROVAL",
        reason="Test vector: café",
    )


def sample_action(action_id: str = "ACT-SSH-5.1.20", control_id: str = "SSH-5.1.20") -> Action:
    return Action(
        action_id=action_id,
        control_id=control_id,
        title="Disable SSH root login",
        action_type="set_sshd_option",
        current_value="yes",
        desired_value="no",
        risk_score=3.5,
        execution_mode="APPROVAL",
        reason="Root login is currently enabled.",
    )


def sample_assessment() -> Assessment:
    return Assessment(
        platform="ubuntu",
        findings=(
            Finding(
                control_id="SSH-1",
                title="SSH setting one",
                status="FAIL",
                applicability="APPLICABLE",
                severity="HIGH",
                current_value="yes",
                expected_value="no",
                message="must be disabled",
                source="sshd",
                evidence=(EvidenceItem("PermitRootLogin", "yes", "sshd -T"),),
            ),
            Finding(
                control_id="SSH-2",
                title="SSH setting two",
                status="PASS",
                applicability="APPLICABLE",
                severity="LOW",
                current_value="no",
                expected_value="no",
                message="compliant",
                source="sshd",
            ),
        ),
    )


def target_context(
    target_id: str = "target-1",
    *,
    generation: str | None = "generation-1",
    agent_id: str | None = "agent-1",
) -> ControllerTargetContext:
    return ControllerTargetContext(target_id, "ubuntu", generation, agent_id)


def evidence_record(
    target: ControllerTargetContext | None = None,
    *,
    assessment_id: str = "assessment-1",
    source: str = "agent-assessment",
    catalog_version: str = "catalog-v1",
    collected_at: Timestamp = Timestamp(1792756800, 123456789),
    assessment: Assessment | None = None,
    origin: EvidenceOrigin = EvidenceOrigin.CONTROLLER_CAPTURED_UNAUTHENTICATED,
    binding_generation: str | None = None,
    agent_id: str | None = None,
    verification_reference: str | None = None,
) -> AssessmentRecord:
    target = target or target_context()
    return build_evidence_record(
        target=target,
        assessment_id=assessment_id,
        source=source,
        catalog_version=catalog_version,
        collected_at=collected_at,
        origin=origin,
        assessment=assessment or sample_assessment(),
        binding_generation=binding_generation,
        agent_id=agent_id,
        verification_reference=verification_reference,
    )


def sample_plan() -> Plan:
    return Plan(
        status="READY",
        platform="ubuntu",
        actions=(sample_action(), sample_action("ACT-SSH-SECOND", "SSH-SECOND")),
    )


def plan_digest(
    *,
    target: ControllerTargetContext | None = None,
    evidence: AssessmentRecord | None = None,
    plan: Plan | None = None,
    policy_version: str = "policy-v1",
    catalog_version: str = "catalog-v1",
) -> str:
    return plan_binding_digest(
        target or target_context(),
        "execute",
        policy_version,
        catalog_version,
        plan or sample_plan(),
        evidence or evidence_record(),
        now=Timestamp(1792756801),
        max_evidence_age_seconds=3600,
    ).digest


def recovery_manifest() -> RecoveryManifest:
    content = b"PermitRootLogin yes\n"
    captured = Timestamp(1792756860)
    return RecoveryManifest(
        target_id="target-1",
        agent_id="agent-1",
        binding_generation="generation-1",
        execution_id="execution-1",
        action=sample_action(),
        state=RecoveryState(
            action_id="ACT-SSH-5.1.20",
            previous_effective_value="yes",
            captured_at=captured,
            file=RecoveryFileState(
                path="/etc/ssh/sshd_config.d/99-agent.conf",
                exists=True,
                mode=0o600,
                content_sha256="e7be8a5b180550215af6a66239c484957fea9f7f8102b15185b0361b53c30657",
                content=content,
                captured_at=captured,
            ),
        ),
    )


class ControllerApprovalBindingTests(unittest.TestCase):
    def test_production_action_contract_matches_go_golden_vector(self) -> None:
        vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        canonical = canonical_action_bytes(vector_action())
        self.assertEqual(vector["version"], "planner-action/v1")
        self.assertEqual(canonical.hex(), vector["canonical_hex"])
        self.assertEqual(action_digest(vector_action()), "sha256:" + vector["sha256"])

    def test_production_composite_contracts_match_go_golden_vectors(self) -> None:
        vectors = json.loads(BINDING_VECTOR_PATH.read_text(encoding="utf-8"))
        record = evidence_record()
        evidence_bytes = canonical_evidence_bytes(record.provenance, record.assessment)
        plan_bytes = canonical_plan_binding_bytes(
            target_context(), "execute", "policy-v1", "catalog-v1", sample_plan(), record,
            now=Timestamp(1792756801), max_evidence_age_seconds=3600,
        )
        recovery_bytes = canonical_recovery_manifest_bytes(recovery_manifest(), target_context())
        for name, canonical, version in (
            ("evidence", evidence_bytes, "assessment-evidence/v1"),
            ("plan", plan_bytes, "plan-binding/v1"),
            ("recovery", recovery_bytes, "recovery-manifest/v1"),
        ):
            with self.subTest(binding=name):
                self.assertEqual(vectors[name]["version"], version)
                self.assertEqual(canonical.hex(), vectors[name]["canonical_hex"])
                digest = {
                    "evidence": evidence_digest(record.provenance, record.assessment),
                    "plan": plan_digest(),
                    "recovery": recovery_manifest_digest(recovery_manifest(), target_context()).digest,
                }[name]
                self.assertEqual(digest, "sha256:" + vectors[name]["sha256"])

    def test_plan_digest_changes_for_target_order_parameters_and_policy(self) -> None:
        baseline = plan_digest()
        new_target = target_context("target-2")
        changed_target_evidence = evidence_record(new_target)
        changed_target = plan_digest(target=new_target, evidence=changed_target_evidence)
        changed_order = plan_digest(plan=replace(sample_plan(), actions=tuple(reversed(sample_plan().actions))))
        changed_action = sample_plan()
        changed_action = replace(changed_action, actions=(replace(changed_action.actions[0], desired_value="yes"), *changed_action.actions[1:]))
        changed_parameter = plan_digest(plan=changed_action)
        changed_policy = plan_digest(policy_version="policy-v2")
        changed_source_record = evidence_record(source="controller-read-only-observation")
        changed_source = plan_digest(evidence=changed_source_record)
        changed_catalog_record = evidence_record(catalog_version="catalog-v2")
        changed_catalog = plan_digest(evidence=changed_catalog_record, catalog_version="catalog-v2")
        changed_assessment_record = evidence_record(
            assessment=replace(
                sample_assessment(),
                findings=(replace(sample_assessment().findings[0], message="changed"), sample_assessment().findings[1]),
            )
        )
        changed_evidence = plan_digest(evidence=changed_assessment_record)
        for label, changed in (
            ("target", changed_target),
            ("ordered actions", changed_order),
            ("action parameters", changed_parameter),
            ("policy version", changed_policy),
            ("evidence source", changed_source),
            ("catalog version", changed_catalog),
            ("assessment content", changed_evidence),
        ):
            with self.subTest(binding=label):
                self.assertNotEqual(baseline, changed)

    def test_evidence_digest_changes_for_source_catalog_reference_and_content(self) -> None:
        baseline = evidence_digest(evidence_record().provenance, sample_assessment())
        variants = (
            evidence_record(source="controller-read-only-observation"),
            evidence_record(catalog_version="catalog-v2"),
            evidence_record(assessment_id="assessment-2"),
            evidence_record(assessment=replace(sample_assessment(), findings=(
                replace(sample_assessment().findings[0], current_value="no"),
                sample_assessment().findings[1],
            ))),
        )
        for record in variants:
            with self.subTest(source=record.provenance.source, catalog=record.provenance.catalog_version):
                self.assertNotEqual(baseline, evidence_digest(record.provenance, record.assessment))

    def test_missing_mismatched_stale_replaced_and_untrusted_provenance_fails_closed(self) -> None:
        target = target_context()
        now = Timestamp(1792756801)
        base = evidence_record()
        bad_records = (
            replace(base, provenance=replace(base.provenance, assessment_id="")),
            replace(base, provenance=replace(base.provenance, target_id="other-target")),
            replace(base, provenance=replace(base.provenance, binding_generation="generation-0")),
            replace(base, provenance=replace(base.provenance, collected_at=Timestamp(1792756800 - 3601))),
            replace(base, provenance=replace(base.provenance, collected_at=Timestamp(1792756802))),
        )
        for record in bad_records:
            with self.subTest(provenance=record.provenance):
                with self.assertRaises(BindingValidationError):
                    plan_digest(target=target, evidence=record)

        with self.assertRaises(BindingValidationError):
            plan_binding_digest(
                target,
                "execute",
                "policy-v1",
                "catalog-v1",
                sample_plan(),
                base,
                now=now,
                max_evidence_age_seconds=3600,
                require_authenticated_context=True,
            )
        with self.assertRaises(BindingValidationError):
            plan_binding_digest(
                target_context(generation=None, agent_id=None),
                "execute",
                "policy-v1",
                "catalog-v1",
                sample_plan(),
                evidence_record(target_context(generation=None, agent_id=None)),
                now=now,
                max_evidence_age_seconds=3600,
                require_authenticated_context=True,
            )
        asserted_only = evidence_record(
            origin=EvidenceOrigin.UPSTREAM_ASSERTED,
            binding_generation="generation-1",
            agent_id="agent-1",
            verification_reference="unverified-reference",
        )
        with self.assertRaises(BindingValidationError):
            plan_binding_digest(
                target,
                "execute",
                "policy-v1",
                "catalog-v1",
                sample_plan(),
                asserted_only,
                now=now,
                max_evidence_age_seconds=3600,
                require_authenticated_context=True,
            )

    def test_catalog_inconsistency_and_invalid_policy_fail_closed(self) -> None:
        with self.assertRaises(BindingValidationError):
            plan_digest(catalog_version="catalog-v2")
        with self.assertRaises(BindingValidationError):
            plan_digest(policy_version=" ")

    def test_controller_target_identity_cannot_be_overridden_by_agent_payload(self) -> None:
        controller_target = ControllerTargetContext.from_target(
            SimpleNamespace(id="controller-target", name="display-name", platform="ubuntu")
        )
        self.assertEqual(controller_target.target_id, "controller-target")
        payload = {
            "platform": "ubuntu",
            "findings": [],
            "target_id": "agent-selected-target",
            "agent_id": "agent-selected-id",
            "digest": "sha256:attacker-selected",
        }
        with self.assertRaises(BindingValidationError):
            Assessment.from_agent_payload(payload)
        with self.assertRaises(BindingValidationError):
            parse_assessment_json(json.dumps(payload))

    def test_invalid_json_duplicate_keys_and_corrupt_recovery_fail_closed(self) -> None:
        with self.assertRaises(BindingValidationError):
            parse_assessment_json('{"platform":"ubuntu","platform":"other","findings":[]}')
        with self.assertRaises(BindingValidationError):
            parse_assessment_json('{"platform":NaN,"findings":[]}')
        with self.assertRaises(BindingValidationError):
            parse_assessment_json(b" " * (MAX_ASSESSMENT_JSON_BYTES + 1))
        with self.assertRaises(BindingValidationError):
            parse_assessment_json(b"\xff")
        corrupted = recovery_manifest()
        bad_file = replace(corrupted.state.file, content_sha256="0" * 64)
        with self.assertRaises(BindingValidationError):
            recovery_manifest_digest(
                replace(corrupted, state=replace(corrupted.state, file=bad_file)), target_context()
            )

    def test_recovery_manifest_identity_must_match_controller_owned_target(self) -> None:
        manifest = recovery_manifest()
        for target in (
            target_context("another-target"),
            target_context(agent_id="another-agent"),
            target_context(generation="another-generation"),
        ):
            with self.subTest(target=target):
                with self.assertRaises(BindingValidationError):
                    recovery_manifest_digest(manifest, target)

        result = recovery_manifest_digest(manifest, target_context())
        self.assertEqual(result.target_id, "target-1")
        self.assertIsNone(result.evidence_origin)

    def test_invalid_types_and_timestamp_values_fail_closed(self) -> None:
        with self.assertRaises(BindingValidationError):
            Action.from_mapping({
                "action_id": "a", "control_id": "c", "title": "t", "action_type": "x",
                "current_value": "", "desired_value": "d", "risk_score": True,
                "execution_mode": "APPROVAL", "reason": "r",
            })
        with self.assertRaises(BindingValidationError):
            Timestamp(True, 0)
        with self.assertRaises(BindingValidationError):
            Timestamp.from_datetime(datetime(1970, 1, 1))

    def test_datetime_conversion_preserves_pre_epoch_seconds_and_nanos(self) -> None:
        converted = Timestamp.from_datetime(datetime(1969, 12, 31, 23, 59, 59, 500_000, timezone.utc))
        self.assertEqual(converted, Timestamp(-1, 500_000_000))

    def test_digest_is_not_dispatch_authorization_and_routes_remain_read_only(self) -> None:
        result = plan_binding_digest(
            target_context(), "execute", "policy-v1", "catalog-v1", sample_plan(), evidence_record(),
            now=Timestamp(1792756801), max_evidence_age_seconds=3600,
        )
        self.assertFalse(hasattr(result, "dispatch_ready"))

        from app.main import app

        route_paths = {route.path for route in app.routes if hasattr(route, "path")}
        self.assertFalse(any("execute" in path.lower() or "rollback" in path.lower() for path in route_paths))


if __name__ == "__main__":
    unittest.main()
