"""Project-defined CentOS Stream 9 ARM64 SSH baseline contract.

This definition is data for the existing reviewed-policy registry. It is not
installed or trusted by default; a Controller operator must review its exact
digest and applicability through the existing trust-pin workflow.
"""

from copy import deepcopy


PROJECT_DEFINED_BASELINE = "PROJECT_DEFINED_BASELINE"
CENTOS_STREAM9_PLATFORM = "centos-stream"
CENTOS_STREAM9_OS_VERSION = "CentOS Stream 9"
CENTOS_STREAM9_ARCHITECTURE = "arm64"
CENTOS_STREAM9_POLICY_VERSION = "centos-stream9-ssh-baseline-v1"
CENTOS_STREAM9_CATALOG_VERSION = "centos-stream9-ssh-controls-v1"
EFFECTIVE_SSH_SOURCE = "ssh.effective_config"
EFFECTIVE_SSH_METHOD = "sshd -T effective configuration"

_DEFINITION = {
    "schema": "aha-agent-assessment-policy/v1",
    "platform": CENTOS_STREAM9_PLATFORM,
    "os_version": CENTOS_STREAM9_OS_VERSION,
    "architecture": CENTOS_STREAM9_ARCHITECTURE,
    "classification": PROJECT_DEFINED_BASELINE,
    "controls": [
        {
            "control_id": "CSTS9-SSH-001",
            "title": "Disable SSH empty passwords",
            "severity": "MEDIUM",
            "expected_value": "no",
            "evidence": [{
                "name": "PermitEmptyPasswords",
                "source": EFFECTIVE_SSH_SOURCE,
                "method": EFFECTIVE_SSH_METHOD,
            }],
        },
        {
            "control_id": "CSTS9-SSH-002",
            "title": "Disable SSH root login",
            "severity": "HIGH",
            "expected_value": "no",
            "evidence": [{
                "name": "PermitRootLogin",
                "source": EFFECTIVE_SSH_SOURCE,
                "method": EFFECTIVE_SSH_METHOD,
            }],
        },
        {
            "control_id": "CSTS9-SSH-003",
            "title": "Disable SSH user environment",
            "severity": "MEDIUM",
            "expected_value": "no",
            "evidence": [{
                "name": "PermitUserEnvironment",
                "source": EFFECTIVE_SSH_SOURCE,
                "method": EFFECTIVE_SSH_METHOD,
            }],
        },
        {
            "control_id": "CSTS9-SSH-004",
            "title": "Enable SSH PAM",
            "severity": "MEDIUM",
            "expected_value": "yes",
            "evidence": [{
                "name": "UsePAM",
                "source": EFFECTIVE_SSH_SOURCE,
                "method": EFFECTIVE_SSH_METHOD,
            }],
        },
    ],
}


def centos_stream9_policy_definition() -> dict:
    """Return a fresh policy object suitable for explicit registry review."""
    return deepcopy(_DEFINITION)
