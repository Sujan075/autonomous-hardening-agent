from dataclasses import dataclass
import ipaddress
import json
import os
from contextlib import contextmanager
from urllib.parse import urlsplit

import httpx

from app.approvals.bindings import MAX_ASSESSMENT_JSON_BYTES
from app.agents.mtls import AgentTransportError, VerifiedAgentClient, make_verified_agent_client
from app.db.models import Target
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class AgentStatus:
    reachable: bool
    agent_id: str | None = None
    status: str | None = None
    error: str | None = None


class AgentStatusURLConfigurationError(ValueError):
    """Raised when the read-only status URL override setting is unsafe/invalid."""


def _validate_status_url(target_id: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AgentStatusURLConfigurationError(
            f"invalid agent status URL override for target {target_id}"
        )

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        # Accessing .port also validates malformed ports.
        parsed.port
    except ValueError as exc:
        raise AgentStatusURLConfigurationError(
            f"invalid agent status URL override for target {target_id}"
        ) from exc

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "?" in value
        or "#" in value
    ):
        raise AgentStatusURLConfigurationError(
            f"invalid agent status URL override for target {target_id}"
        )

    if parsed.scheme == "http":
        host = hostname.lower()
        if host not in {"localhost", "127.0.0.1", "::1"}:
            raise AgentStatusURLConfigurationError(
                f"plain HTTP agent status overrides must use loopback for target {target_id}"
            )
        # Keep the allowlist exact while rejecting malformed numeric spellings.
        if host != "localhost":
            try:
                if not ipaddress.ip_address(host).is_loopback:
                    raise AgentStatusURLConfigurationError(
                        f"plain HTTP agent status overrides must use loopback for target {target_id}"
                    )
            except ValueError as exc:
                raise AgentStatusURLConfigurationError(
                    f"invalid agent status URL override for target {target_id}"
                ) from exc

    return value


def resolve_agent_status_url(
    target_id: str,
    address: str,
    overrides_json: str | None = None,
) -> str:
    """Resolve an agent base URL; legacy remote HTTP is unsuitable for privileged operations."""
    raw = os.environ.get("AGENT_STATUS_URL_OVERRIDES") if overrides_json is None else overrides_json
    if raw is None:
        try:
            if ipaddress.ip_address(address).is_loopback:
                return f"http://{address}:9000"
        except ValueError:
            if address.lower() == "localhost":
                return f"http://{address}:9000"
        raise AgentStatusURLConfigurationError(
            "non-loopback agents require an explicit HTTPS mTLS URL"
        )

    try:
        overrides = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise AgentStatusURLConfigurationError(
            "AGENT_STATUS_URL_OVERRIDES must be a JSON object"
        ) from exc

    if not isinstance(overrides, dict) or any(not isinstance(key, str) for key in overrides):
        raise AgentStatusURLConfigurationError(
            "AGENT_STATUS_URL_OVERRIDES must be a JSON object mapping target IDs to URLs"
        )

    validated_overrides = {
        key: _validate_status_url(key, value) for key, value in overrides.items()
    }
    if target_id not in validated_overrides:
        try:
            if ipaddress.ip_address(address).is_loopback:
                return f"http://{address}:9000"
        except ValueError:
            if address.lower() == "localhost":
                return f"http://{address}:9000"
        raise AgentStatusURLConfigurationError(
            "non-loopback agents require an explicit HTTPS mTLS URL"
        )
    return validated_overrides[target_id]


@contextmanager
def target_agent_transport(db: Session, target: Target, base_url: str):
    transport = make_verified_agent_client(db, target=target, base_url=base_url)
    try:
        yield transport
    finally:
        if transport is not None:
            transport.close()


def get_agent_status(
    base_url: str, timeout: float = 5.0, transport: VerifiedAgentClient | None = None
) -> AgentStatus:
    """Read /status only using bounded JSON and an optional verified mTLS client."""

    try:
        payload = get_agent_read_only_payload(
            base_url, "status", timeout=timeout, transport=transport
        )
        if not isinstance(payload, dict):
            raise ValueError("agent status response must be an object")

        return AgentStatus(
            reachable=True,
            agent_id=payload.get("agent_id"),
            status=payload.get("status"),
        )

    except AgentTransportError:
        raise

    except httpx.HTTPError as exc:
        return AgentStatus(
            reachable=False,
            error=str(exc),
        )

    except ValueError as exc:
        return AgentStatus(
            reachable=False,
            error=f"invalid agent response: {exc}",
        )


def get_agent_read_only_payload(
    base_url: str,
    endpoint: str,
    timeout: float = 5.0,
    transport: VerifiedAgentClient | None = None,
) -> object:
    """Fetch JSON from a read-only agent endpoint using a finite timeout."""
    raw = get_agent_read_only_bytes(base_url, endpoint, timeout, transport)
    try:
        return json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("agent response is not valid UTF-8 JSON") from exc


def get_agent_read_only_bytes(
    base_url: str,
    endpoint: str,
    timeout: float = 5.0,
    transport: VerifiedAgentClient | None = None,
) -> bytes:
    """Fetch the exact UTF-8 response body for validation and provenance storage."""
    url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    body = bytearray()
    stream = transport.stream if transport else httpx.stream
    with stream("GET", url, timeout=timeout) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > MAX_ASSESSMENT_JSON_BYTES:
                raise ValueError("Agent response exceeds maximum supported size")
            body.extend(chunk)
    return bytes(body)
