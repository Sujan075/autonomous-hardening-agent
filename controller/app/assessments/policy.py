"""Fail-closed resolution of the policy used by read-only agent assessments.

The v1 definition contract here is deliberately narrow. It binds the local
agent's reported OS release/architecture and the exact ordered finding IDs and
expected values. It does not attest the agent binary or make plaintext HTTP
observations trustworthy.
"""

from dataclasses import dataclass
import json

from sqlalchemy.orm import Session

from app.agents.mtls import AuthenticatedAgentPeer, is_verified_agent_peer
from app.approvals.bindings import Assessment, BindingValidationError, parse_assessment_json
from app.db.models import PolicyCatalogDefinition, Target, TargetPolicyAssignment
from app.policies.registry import RegistryError, ResolvedPolicyAssignment, resolve_target_assignment


MAX_POLICY_CONTROLS = 256
ASSESSMENT_POLICY_SCHEMA = "aha-agent-assessment-policy/v1"


class AssessmentPolicyError(ValueError):
    """The target has no policy that can be matched to the assessment."""


@dataclass(frozen=True)
class PolicyEvaluation:
    """Deterministic result for one exact, reviewed policy/assessment match.

    A collection can be valid while its findings are incomplete or uncertain.
    Those cases are represented as INDETERMINATE and can never imply
    compliance.
    """

    decision: str
    reported_decision: str
    identity_status: str
    reasons: tuple[str, ...]
    controls: tuple[dict[str, str], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "reported_decision": self.reported_decision,
            "identity_status": self.identity_status,
            "reasons": list(self.reasons),
            "controls": [dict(control) for control in self.controls],
        }


@dataclass(frozen=True)
class ResolvedAssessmentPolicy:
    assignment: ResolvedPolicyAssignment
    definition_id: int
    os_version: str
    architecture: str
    controls: tuple[tuple[str, str], ...]
    control_details: tuple[tuple[str, str, str], ...]
    evidence_expectations: tuple[tuple[str, tuple[tuple[str, str, str], ...]], ...]
    classification: str | None


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
    base_fields = {"schema", "platform", "os_version", "architecture", "controls"}
    supported_contracts = {
        frozenset(base_fields),
        frozenset(base_fields | {"classification"}),
    }
    if not isinstance(contract, dict) or frozenset(contract) not in supported_contracts:
        raise AssessmentPolicyError("assigned policy does not declare a supported assessment contract")
    if contract["schema"] != ASSESSMENT_POLICY_SCHEMA:
        raise AssessmentPolicyError("assigned policy assessment contract version is unsupported")
    if contract["platform"] != assignment.platform:
        raise AssessmentPolicyError("policy platform applicability is inconsistent")
    classification = contract.get("classification")
    if classification is not None and classification not in {"PROJECT_DEFINED_BASELINE"}:
        raise AssessmentPolicyError("policy classification is unsupported")
    os_version = _bounded_text(contract["os_version"], "policy OS version", 128)
    architecture = _bounded_text(contract["architecture"], "policy architecture", 32)
    raw_controls = contract["controls"]
    if not isinstance(raw_controls, list) or not 1 <= len(raw_controls) <= MAX_POLICY_CONTROLS:
        raise AssessmentPolicyError("policy controls must be a non-empty bounded list")
    controls: list[tuple[str, str]] = []
    control_details: list[tuple[str, str, str]] = []
    evidence_expectations: list[tuple[str, tuple[tuple[str, str, str], ...]]] = []
    seen: set[str] = set()
    for control in raw_controls:
        if not isinstance(control, dict):
            raise AssessmentPolicyError("policy control is malformed")
        required_keys = {"control_id", "expected_value"}
        optional_keys = {"title", "severity", "evidence"}
        if not required_keys <= set(control) or set(control) - required_keys - optional_keys:
            raise AssessmentPolicyError("policy control is malformed")
        optional_present = {"title", "severity", "evidence"} & set(control)
        optional_required = {"title", "severity", "evidence"}
        if optional_present and not optional_required <= set(control):
            raise AssessmentPolicyError(
                "policy control definition must declare title, severity, and evidence together"
            )
        control_id = _bounded_text(control["control_id"], "control ID", 128)
        expected = _bounded_text(control["expected_value"], "expected value", 4096)
        if control_id in seen:
            raise AssessmentPolicyError("policy control IDs must be unique")
        seen.add(control_id)
        controls.append((control_id, expected))
        if "evidence" in control:
            title = _bounded_text(control["title"], "control title", 256)
            severity = _bounded_text(control["severity"], "control severity", 32)
            raw_evidence = control["evidence"]
            if not isinstance(raw_evidence, list) or not 1 <= len(raw_evidence) <= 32:
                raise AssessmentPolicyError("policy evidence expectations must be a non-empty bounded list")
            control_details.append((control_id, title, severity))
            expectations: list[tuple[str, str, str]] = []
            evidence_seen: set[tuple[str, str]] = set()
            for item in raw_evidence:
                if not isinstance(item, dict) or set(item) != {"name", "source", "method"}:
                    raise AssessmentPolicyError("policy evidence expectation is malformed")
                name = _bounded_text(item["name"], "evidence name", 128)
                source = _bounded_text(item["source"], "evidence source", 128)
                method = _bounded_text(item["method"], "evidence method", 256)
                if (name, source) in evidence_seen:
                    raise AssessmentPolicyError("policy evidence expectations must be unique")
                evidence_seen.add((name, source))
                expectations.append((name, source, method))
            evidence_expectations.append((control_id, tuple(expectations)))
    if evidence_expectations and len(evidence_expectations) != len(controls):
        raise AssessmentPolicyError("policy evidence expectations must cover every control")
    if classification and not evidence_expectations:
        raise AssessmentPolicyError("classified project policies must define evidence expectations for every control")
    return ResolvedAssessmentPolicy(
        assignment=assignment,
        definition_id=definition.id,
        os_version=os_version,
        architecture=architecture,
        controls=tuple(controls),
        control_details=tuple(control_details),
        evidence_expectations=tuple(evidence_expectations),
        classification=classification,
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
        target.id != policy.assignment.target_id
        or discovery["os"] != "linux"
        or not isinstance(discovery["os_version"], str)
        or discovery["os_version"] != policy.os_version
        or discovery["architecture"] != policy.architecture
        or target.platform != policy.assignment.platform
    ):
        raise AssessmentPolicyError("target identity/platform/version is incompatible with assigned policy")
    try:
        assessment = parse_assessment_json(raw_assessment)
    except BindingValidationError as exc:
        raise AssessmentPolicyError("agent assessment is malformed") from exc
    if assessment.platform != policy.assignment.platform:
        raise AssessmentPolicyError("agent assessment platform does not match assigned policy")
    actual = tuple((finding.control_id, finding.expected_value) for finding in assessment.findings)
    if actual != policy.controls:
        raise AssessmentPolicyError("agent assessment controls do not match assigned policy")
    expected_details = {control_id: (title, severity) for control_id, title, severity in policy.control_details}
    if any(
        finding.control_id in expected_details
        and (finding.title, finding.severity) != expected_details[finding.control_id]
        for finding in assessment.findings
    ):
        raise AssessmentPolicyError("agent assessment control definitions do not match assigned policy")
    return assessment


def evaluate_assessment(
    policy: ResolvedAssessmentPolicy,
    assessment: Assessment,
    *,
    authenticated_peer: AuthenticatedAgentPeer | None = None,
) -> PolicyEvaluation:
    """Evaluate findings only after exact policy matching and fail closed.

    The agent's finding status is cross-checked against the observed and
    expected values. Evidence must identify the same source and observed
    value. ERROR, UNKNOWN, malformed or incomplete evidence is reported as
    INDETERMINATE rather than compliant.
    """
    if assessment.platform != policy.assignment.platform:
        raise AssessmentPolicyError("assessment platform does not match resolved policy")
    actual = tuple((finding.control_id, finding.expected_value) for finding in assessment.findings)
    if actual != policy.controls:
        raise AssessmentPolicyError("assessment controls do not match resolved policy")

    rows: list[dict[str, str]] = []
    reasons: list[str] = []
    has_failure = False
    indeterminate = False
    evidence_expectations = dict(policy.evidence_expectations)
    for finding in assessment.findings:
        issue = ""
        if finding.error is not None or finding.status in {"ERROR", "UNKNOWN"}:
            issue = "finding collection returned an error or unknown status"
        elif finding.applicability != "APPLICABLE":
            issue = "finding applicability is not confirmed as applicable"
        elif not finding.current_value or not finding.expected_value or not finding.source:
            issue = "finding is missing observed, expected, or source data"
        elif not _evidence_supports_finding(finding, evidence_expectations.get(finding.control_id, ())):
            issue = "finding evidence does not substantiate its observed value and source"
        elif finding.status == "PASS" and finding.current_value != finding.expected_value:
            issue = "PASS status conflicts with observed and expected values"
        elif finding.status == "FAIL" and finding.current_value == finding.expected_value:
            issue = "FAIL status conflicts with observed and expected values"
        elif finding.status not in {"PASS", "FAIL"}:
            issue = "finding status is unsupported"

        if issue:
            indeterminate = True
            reasons.append(f"{finding.control_id}: {issue}")
        elif finding.status == "FAIL":
            has_failure = True
            reasons.append(f"{finding.control_id}: observed value differs from policy")
        else:
            reasons.append(f"{finding.control_id}: observed value matches policy")
        rows.append({
            "control_id": finding.control_id,
            "status": finding.status,
            "observed_value": finding.current_value,
            "expected_value": finding.expected_value,
            "source": finding.source,
        })

    reported_decision = "INDETERMINATE" if indeterminate else "NON_COMPLIANT" if has_failure else "COMPLIANT"
    peer_matches_binding = (
        is_verified_agent_peer(authenticated_peer)
        and authenticated_peer.target_id == policy.assignment.target_id
        and authenticated_peer.agent_id == policy.assignment.agent_id
        and authenticated_peer.binding_generation == policy.assignment.binding_generation
    )
    identity_status = "authenticated_agent_target_bound" if peer_matches_binding else "unauthenticated_or_unbound"
    if not policy.evidence_expectations:
        reasons.append("policy has no reviewed evidence-name/source expectations")
    if not peer_matches_binding:
        reasons.append("agent identity is not authenticated and bound to the assigned target generation")
    elif reported_decision != "INDETERMINATE":
        reasons.append("authenticated transport does not independently attest assessment collection provenance")
    # There is currently no independent assessment-provenance verifier. Keep
    # the trusted decision indeterminate even when the channel identity is
    # bound; expose the internally consistent agent-reported result separately.
    return PolicyEvaluation(
        decision="INDETERMINATE",
        reported_decision=reported_decision,
        identity_status=identity_status,
        reasons=tuple(reasons),
        controls=tuple(rows),
    )


def _evidence_supports_finding(
    finding: object,
    expected: tuple[tuple[str, str, str], ...],
) -> bool:
    evidence = getattr(finding, "evidence", ())
    if not evidence or not expected or len(evidence) != len(expected):
        return False
    seen: set[tuple[str, str]] = set()
    matched_observation = False
    for item, (expected_name, expected_source, _method) in zip(evidence, expected, strict=True):
        name = getattr(item, "name", "")
        value = getattr(item, "value", "")
        source = getattr(item, "source", "")
        if not name or not value or not source or name != expected_name or source != expected_source:
            return False
        key = (name, source)
        if key in seen:
            return False
        seen.add(key)
        if source == finding.source and value == finding.current_value:
            matched_observation = True
    return matched_observation


def _bounded_text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value.encode("utf-8")) > maximum:
        raise AssessmentPolicyError(f"{label} is invalid")
    return value
