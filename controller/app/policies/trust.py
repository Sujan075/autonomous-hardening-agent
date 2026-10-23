"""Operator-provisioned pins for externally reviewed policy provenance."""

from dataclasses import dataclass
import json
import os
import re


MAX_POLICY_TRUST_CONFIG_BYTES = 64 * 1024
MAX_POLICY_TRUST_PINS = 100
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class PolicyTrustConfigurationError(ValueError):
    """Trusted-source verification pins are missing or invalid."""


@dataclass(frozen=True)
class PolicyTrustPin:
    provenance_reference: str
    source_evidence_sha256: str
    definition_sha256: str
    platform: str
    policy_version: str
    catalog_version: str
    applicability_confirmed: bool


def load_policy_trust_pins() -> tuple[PolicyTrustPin, ...]:
    configured = os.environ.get("POLICY_REVIEW_TRUST_PINS_JSON", "")
    if not configured:
        raise PolicyTrustConfigurationError("policy trusted-source verification is not configured")
    try:
        encoded_config = configured.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PolicyTrustConfigurationError("policy trust configuration is malformed") from exc
    if len(encoded_config) > MAX_POLICY_TRUST_CONFIG_BYTES:
        raise PolicyTrustConfigurationError("policy trust configuration exceeds the size limit")
    try:
        values = json.loads(configured, object_pairs_hook=_unique_object)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise PolicyTrustConfigurationError("policy trust configuration is malformed") from exc
    if not isinstance(values, list) or not values or len(values) > MAX_POLICY_TRUST_PINS:
        raise PolicyTrustConfigurationError("policy trust configuration must contain bounded pins")
    pins = []
    references = set()
    required = {
        "provenance_reference",
        "source_evidence_sha256",
        "definition_sha256",
        "platform",
        "policy_version",
        "catalog_version",
        "applicability_confirmed",
    }
    for value in values:
        if not isinstance(value, dict) or set(value) != required:
            raise PolicyTrustConfigurationError("policy trust pin fields are invalid")
        for key, limit in (
            ("provenance_reference", 512),
            ("platform", 50),
            ("policy_version", 128),
            ("catalog_version", 128),
        ):
            item = value[key]
            if not isinstance(item, str) or not item.strip() or len(item) > limit:
                raise PolicyTrustConfigurationError("policy trust pin scope is invalid")
        if value["provenance_reference"] in references:
            raise PolicyTrustConfigurationError("policy trust source references must be unique")
        references.add(value["provenance_reference"])
        if not isinstance(value["source_evidence_sha256"], str) or not _SHA256.fullmatch(value["source_evidence_sha256"]):
            raise PolicyTrustConfigurationError("source evidence digest is invalid")
        if not isinstance(value["definition_sha256"], str) or not _SHA256.fullmatch(value["definition_sha256"]):
            raise PolicyTrustConfigurationError("definition digest is invalid")
        if value["applicability_confirmed"] is not True:
            raise PolicyTrustConfigurationError("policy applicability is not explicitly confirmed")
        pins.append(PolicyTrustPin(**value))
    return tuple(pins)


def matching_policy_pin(
    pins: tuple[PolicyTrustPin, ...],
    *,
    provenance_reference: str,
    source_evidence_sha256: str,
    definition_sha256: str,
    platform: str,
    policy_version: str,
    catalog_version: str,
) -> PolicyTrustPin | None:
    for pin in pins:
        if (
            pin.provenance_reference == provenance_reference
            and pin.source_evidence_sha256 == source_evidence_sha256
            and pin.definition_sha256 == definition_sha256
            and pin.platform == platform
            and pin.policy_version == policy_version
            and pin.catalog_version == catalog_version
            and pin.applicability_confirmed
        ):
            return pin
    return None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration member")
        result[key] = value
    return result
