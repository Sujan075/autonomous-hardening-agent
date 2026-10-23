"""Fail-closed resolution of the policy used by read-only agent assessments.

The v1 definition contract here is deliberately narrow. It binds the local
agent's reported OS release/architecture and the exact ordered finding IDs and
expected values. It does not attest the agent binary or make plaintext HTTP
observations trustworthy.
"""

from dataclasses import dataclass
import json

from sqlalchemy.orm import Session

from app.approvals.bindings import Assessment, BindingValidationError, parse_assessment_json
from app.db.models import PolicyCatalogDefinition, Target, TargetPolicyAssignment
from app.policies.registry import RegistryError, ResolvedPolicyAssignment, resolve_target_assignment


MAX_POLICY_CONTROLS = 256
ASSESSMENT_POLICY_SCHEMA = "aha-agent-assessment-policy/v1"


class AssessmentPolicyError(ValueError):
    """The target has no policy that can be matched to the assessment."""


@dataclass(frozen=True)
class ResolvedAssessmentPolicy:
    assignment: ResolvedPolicyAssignment
    definition_id: int
    os_version: str
    architecture: str
    controls: tuple[tuple[str, str], ...]


def resolve_assessment_policy(db: Session, *, target: Target) -> ResolvedAssessmentPolicy:
    """Resolve current reviewed assignment and parse its explicit evaluator scope."""
    if not isinstance(target, Target):
        raise AssessmentPolicyError("target context must be Controller-owned")
    try:
        assignment = resolve_target_assignment(db, target_id=target.id)
    except RegistryError as exc:
        raise AssessmentPolicyError("target policy assignment is unavailable or untrusted") from exc

    row_assignment = db.get(TargetPolicyAssignment, target.id)
    if row_assignment is None or row_assignment.state != "active":
        raise AssessmentPolicyError("target policy assignment is unavailable")
    definition = db.get(PolicyCatalogDefinition, row_assignment.definition_id)
    if definition is None or definition.id != row_assignment.definition_id:
        raise AssessmentPolicyError("assigned policy definition is unavailable")
    try:
        contract = json.loads(definition.definition_json)
    except (TypeError, ValueError) as exc:
        raise AssessmentPolicyError("assigned policy definition is malformed") from exc
    if not isinstance(contract, dict) or set(contract) != {
        "schema", "platform", "os_version", "architecture", "controls"
    }:
        raise AssessmentPolicyError("assigned policy does not declare a supported assessment contract")
    if contract["schema"] != ASSESSMENT_POLICY_SCHEMA:
        raise AssessmentPolicyError("assigned policy assessment contract version is unsupported")
    if contract["platform"] != assignment.platform:
        raise AssessmentPolicyError("policy platform applicability is inconsistent")
    os_version = _bounded_text(contract["os_version"], "policy OS version", 128)
    architecture = _bounded_text(contract["architecture"], "policy architecture", 32)
    raw_controls = contract["controls"]
    if not isinstance(raw_controls, list) or not 1 <= len(raw_controls) <= MAX_POLICY_CONTROLS:
        raise AssessmentPolicyError("policy controls must be a non-empty bounded list")
    controls: list[tuple[str, str]] = []
    seen: set[str] = set()
    for control in raw_controls:
        if not isinstance(control, dict) or set(control) != {"control_id", "expected_value"}:
            raise AssessmentPolicyError("policy control is malformed")
        control_id = _bounded_text(control["control_id"], "control ID", 128)
        expected = _bounded_text(control["expected_value"], "expected value", 4096)
        if control_id in seen:
            raise AssessmentPolicyError("policy control IDs must be unique")
        seen.add(control_id)
        controls.append((control_id, expected))
    return ResolvedAssessmentPolicy(
        assignment=assignment,
        definition_id=definition.id,
        os_version=os_version,
        architecture=architecture,
        controls=tuple(controls),
    )


def validate_assessment_matches_policy(
    policy: ResolvedAssessmentPolicy,
    *,
    target: Target,
    discovery: object,
    raw_assessment: str | bytes,
) -> Assessment:
    """Validate discovery applicability and exact ordered policy findings."""
    if not isinstance(discovery, dict) or set(discovery) != {
        "hostname", "os", "os_version", "kernel", "architecture", "primary_ip"
    }:
        raise AssessmentPolicyError("agent discovery response is malformed")
    if (
        discovery["os"] != "linux"
        or not isinstance(discovery["os_version"], str)
        or discovery["os_version"] != policy.os_version
        or discovery["architecture"] != policy.architecture
        or target.platform != policy.assignment.platform
    ):
        raise AssessmentPolicyError("target platform/version is incompatible with assigned policy")
    try:
        assessment = parse_assessment_json(raw_assessment)
    except BindingValidationError as exc:
        raise AssessmentPolicyError("agent assessment is malformed") from exc
    if assessment.platform != policy.assignment.platform:
        raise AssessmentPolicyError("agent assessment platform does not match assigned policy")
    actual = tuple((finding.control_id, finding.expected_value) for finding in assessment.findings)
    if actual != policy.controls:
        raise AssessmentPolicyError("agent assessment controls do not match assigned policy")
    return assessment


def _bounded_text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value.encode("utf-8")) > maximum:
        raise AssessmentPolicyError(f"{label} is invalid")
    return value
