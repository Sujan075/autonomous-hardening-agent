"""Cross-language contract test for the Go planner action digest vector."""

import hashlib
import json
import struct
import unittest
from pathlib import Path


VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "agent"
    / "internal"
    / "approval"
    / "testdata"
    / "action_digest_v1.json"
)
BINDING_VECTOR_PATH = VECTOR_PATH.with_name("approval_bindings_v1.json")
PREFIX = b"AHA-PLANNER-ACTION-DIGEST\x00planner-action/v1\x00"
STRING_FIELDS = (
    "action_id",
    "control_id",
    "title",
    "action_type",
    "current_value",
    "desired_value",
)


def canonical_action_bytes(action: dict[str, object]) -> bytes:
    result = bytearray(PREFIX)
    for name in STRING_FIELDS:
        value = action[name]
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        encoded = value.encode("utf-8", errors="strict")
        result.extend(struct.pack(">I", len(encoded)))
        result.extend(encoded)

    risk_score = action["risk_score"]
    if isinstance(risk_score, bool) or not isinstance(risk_score, (float, int)):
        raise TypeError("risk_score must be numeric")
    result.extend(struct.pack(">d", float(risk_score)))

    for name in ("execution_mode", "reason"):
        value = action[name]
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        encoded = value.encode("utf-8", errors="strict")
        result.extend(struct.pack(">I", len(encoded)))
        result.extend(encoded)

    return bytes(result)


def text(value: str) -> bytes:
    encoded = value.encode("utf-8", errors="strict")
    return struct.pack(">I", len(encoded)) + encoded


def timestamp(seconds: int, nanos: int = 0) -> bytes:
    return struct.pack(">qI", seconds, nanos)


def test_action(action_id: str = "ACT-SSH-5.1.20", control_id: str = "SSH-5.1.20") -> dict[str, object]:
    return {
        "action_id": action_id,
        "control_id": control_id,
        "title": "Disable SSH root login",
        "action_type": "set_sshd_option",
        "current_value": "yes",
        "desired_value": "no",
        "risk_score": 3.5,
        "execution_mode": "APPROVAL",
        "reason": "Root login is currently enabled.",
    }


def test_evidence_bytes() -> bytes:
    result = bytearray(b"AHA-ASSESSMENT-EVIDENCE\x00assessment-evidence/v1\x00")
    for value in ("assessment-1", "target-1", "agent-assessment", "catalog-v1", "ubuntu"):
        result.extend(text(value))
    result.extend(timestamp(1792756800, 123456789))
    result.extend(struct.pack(">I", 2))
    findings = (
        ("SSH-1", "SSH setting one", "FAIL", "APPLICABLE", "HIGH", "yes", "no", "must be disabled", "sshd", (("PermitRootLogin", "yes", "sshd -T"),), None),
        ("SSH-2", "SSH setting two", "PASS", "APPLICABLE", "LOW", "no", "no", "compliant", "sshd", (), None),
    )
    for finding in findings:
        for value in finding[:9]:
            result.extend(text(value))
        result.extend(struct.pack(">I", len(finding[9])))
        for item in finding[9]:
            for value in item:
                result.extend(text(value))
        result.append(0 if finding[10] is None else 1)
        if finding[10] is not None:
            for value in finding[10]:
                result.extend(text(value))
    return bytes(result)


def test_plan_bytes(evidence_digest: bytes) -> bytes:
    action1 = test_action()
    action2 = test_action("ACT-SSH-SECOND", "SSH-SECOND")
    result = bytearray(b"AHA-PLAN-BINDING\x00plan-binding/v1\x00")
    for value in ("target-1", "execute", "policy-v1", "catalog-v1", "READY", "ubuntu"):
        result.extend(text(value))
    result.extend(evidence_digest)
    result.extend(struct.pack(">I", 2))
    for action in (action1, action2):
        canonical = canonical_action_bytes(action)
        result.extend(hashlib.sha256(canonical).digest())
    return bytes(result)


def test_recovery_bytes(action: dict[str, object]) -> bytes:
    content = b"PermitRootLogin yes\n"
    file_digest = hashlib.sha256(content).digest()
    result = bytearray(b"AHA-RECOVERY-MANIFEST\x00recovery-manifest/v1\x00")
    for value in ("target-1", "agent-1", "generation-1", "execution-1", "ACT-SSH-5.1.20"):
        result.extend(text(value))
    result.extend(hashlib.sha256(canonical_action_bytes(action)).digest())
    result.extend(timestamp(1792756860))
    result.extend(text("yes"))
    result.extend(text("/etc/ssh/sshd_config.d/99-agent.conf"))
    result.append(1)
    result.extend(struct.pack(">I", 0o600))
    result.extend(timestamp(1792756860))
    result.extend(file_digest)
    result.extend(struct.pack(">Q", len(content)))
    return bytes(result)


class ApprovalDigestContractTests(unittest.TestCase):
    def test_python_matches_shared_golden_bytes_and_digest(self) -> None:
        vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        self.assertEqual(vector["version"], "planner-action/v1")

        canonical = canonical_action_bytes(vector["action"])
        self.assertEqual(canonical.hex(), vector["canonical_hex"])
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), vector["sha256"])

    def test_python_matches_plan_evidence_and_recovery_golden_vectors(self) -> None:
        vectors = json.loads(BINDING_VECTOR_PATH.read_text(encoding="utf-8"))
        evidence = test_evidence_bytes()
        plan = test_plan_bytes(hashlib.sha256(evidence).digest())
        recovery = test_recovery_bytes(test_action())
        for name, canonical in (("evidence", evidence), ("plan", plan), ("recovery", recovery)):
            with self.subTest(binding=name):
                self.assertEqual(vectors[name]["version"], {
                    "evidence": "assessment-evidence/v1",
                    "plan": "plan-binding/v1",
                    "recovery": "recovery-manifest/v1",
                }[name])
                self.assertEqual(canonical.hex(), vectors[name]["canonical_hex"])
                self.assertEqual(hashlib.sha256(canonical).hexdigest(), vectors[name]["sha256"])


if __name__ == "__main__":
    unittest.main()
