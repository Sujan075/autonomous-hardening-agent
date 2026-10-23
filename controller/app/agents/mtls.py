"""Verified mTLS client for read-only agent requests."""

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    AgentCredential,
    AgentCredentialState,
    AgentIdentity,
    AgentIdentityState,
    Target,
    TargetAgentBinding,
)


class AgentTransportError(ValueError):
    """Transport identity/configuration did not meet the target binding."""


@dataclass(frozen=True)
class TLSSettings:
    ca_file: str
    cert_file: str
    key_file: str
    controller_identity_uri: str

    @classmethod
    def from_env(cls) -> "TLSSettings | None":
        names = (
            "CONTROLLER_AGENT_CA_FILE",
            "CONTROLLER_AGENT_CERT_FILE",
            "CONTROLLER_AGENT_KEY_FILE",
            "CONTROLLER_WORKLOAD_IDENTITY",
        )
        values = [os.environ.get(name, "").strip() for name in names]
        if not any(values):
            return None
        if not all(values):
            raise AgentTransportError("Controller mTLS configuration is incomplete")
        settings = cls(*values)
        identity = urlsplit(settings.controller_identity_uri)
        if not identity.scheme or not identity.netloc or identity.query or identity.fragment:
            raise AgentTransportError("Controller workload identity must be an absolute URI")
        return settings


@dataclass(frozen=True)
class AuthenticatedAgentPeer:
    target_id: str
    agent_id: str
    binding_generation: str
    credential_id: int
    certificate_fingerprint: str
    identity_uri: str
    _verification_seal: object | None = field(default=None, repr=False, compare=False)


_PEER_VERIFICATION_SEAL = object()


def is_verified_agent_peer(peer: object) -> bool:
    """Check that the peer receipt was minted by this process's TLS verifier."""
    return (
        isinstance(peer, AuthenticatedAgentPeer)
        and peer._verification_seal is _PEER_VERIFICATION_SEAL
    )


class VerifiedAgentClient:
    def __init__(self, client: httpx.Client, db: Session, target_id: str):
        self._client = client
        self._db = db
        self._target_id = target_id
        self.authenticated_peer: AuthenticatedAgentPeer | None = None
        binding = db.scalar(
            select(TargetAgentBinding).where(
                TargetAgentBinding.target_id == target_id,
                TargetAgentBinding.state == "active",
            )
        )
        if binding is None:
            client.close()
            raise AgentTransportError("target has no active agent binding")
        self._binding = binding

    def get(self, url: str, *, timeout: float) -> httpx.Response:
        self.authenticated_peer = None
        with self._client.stream("GET", url, timeout=timeout) as response:
            self.verify_peer(response)
            body = response.read()
            return httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                content=body,
                request=response.request,
            )

    @contextmanager
    def stream(self, method: str, url: str, *, timeout: float):
        self.authenticated_peer = None
        with self._client.stream(method, url, timeout=timeout) as response:
            self.verify_peer(response)
            yield response

    def verify_peer(self, response: httpx.Response) -> None:
        self.authenticated_peer = None
        current_binding = self._db.scalar(
            select(TargetAgentBinding).where(
                TargetAgentBinding.target_id == self._target_id,
                TargetAgentBinding.state == "active",
            )
        )
        if (
            current_binding is None
            or current_binding.id != self._binding.id
            or current_binding.generation != self._binding.generation
            or current_binding.agent_id != self._binding.agent_id
            or current_binding.credential_id != self._binding.credential_id
        ):
            raise AgentTransportError("target agent binding changed during the request")
        network_stream = response.extensions.get("network_stream")
        ssl_object = network_stream.get_extra_info("ssl_object") if network_stream else None
        if ssl_object is None:
            raise AgentTransportError("agent response was not received over verified TLS")
        der = ssl_object.getpeercert(True)
        if not der:
            raise AgentTransportError("agent TLS peer certificate is missing")
        fingerprint = "sha256:" + hashlib.sha256(der).hexdigest()
        credential = self._db.scalar(
            select(AgentCredential).where(
                AgentCredential.fingerprint_sha256 == fingerprint,
                AgentCredential.agent_id == self._binding.agent_id,
                AgentCredential.state == AgentCredentialState.ACTIVE.value,
            )
        )
        identity = self._db.get(AgentIdentity, self._binding.agent_id)
        now = datetime.now(timezone.utc)
        if (
            identity is None
            or identity.state != AgentIdentityState.ACTIVE.value
            or credential is None
            or self._binding.credential_id != credential.id
            or now < _utc(credential.not_before)
            or now >= _utc(credential.expires_at)
            or credential.revoked_at is not None
        ):
            raise AgentTransportError("agent certificate is not active for this target binding")
        cert = x509.load_der_x509_certificate(der)
        public_key_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        public_key_fingerprint = "sha256:" + hashlib.sha256(public_key_der).hexdigest()
        if (
            credential.public_key_sha256 is not None
            and credential.public_key_sha256 != public_key_fingerprint
        ):
            raise AgentTransportError("agent certificate public key does not match its registered credential")
        try:
            uri_names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
        except x509.ExtensionNotFound as exc:
            raise AgentTransportError("agent certificate has no workload identity URI") from exc
        if credential.identity_uri not in uri_names:
            raise AgentTransportError("agent certificate identity does not match its registered credential")
        self.authenticated_peer = AuthenticatedAgentPeer(
            target_id=self._target_id,
            agent_id=current_binding.agent_id,
            binding_generation=current_binding.generation,
            credential_id=credential.id,
            certificate_fingerprint=fingerprint,
            identity_uri=credential.identity_uri,
            _verification_seal=_PEER_VERIFICATION_SEAL,
        )

    def close(self) -> None:
        self._client.close()


def make_verified_agent_client(
    db: Session,
    *,
    target: Target,
    base_url: str,
) -> VerifiedAgentClient | None:
    """Create mTLS client for HTTPS, or allow loopback-only unauthenticated lab HTTP."""
    settings = TLSSettings.from_env()
    if base_url.startswith("http://"):
        if settings is not None:
            raise AgentTransportError("plaintext transport conflicts with configured mTLS")
        host = urlsplit(base_url).hostname or ""
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host.lower() == "localhost"
        if not loopback:
            raise AgentTransportError("plaintext HTTP is permitted only for loopback lab tunnels")
        return None
    if not base_url.startswith("https://"):
        raise AgentTransportError("agent transport must use HTTPS or loopback lab HTTP")
    if settings is None:
        raise AgentTransportError("HTTPS requires explicit Controller mTLS trust configuration")
    binding = db.scalar(
        select(TargetAgentBinding).where(
            TargetAgentBinding.target_id == target.id,
            TargetAgentBinding.state == "active",
        )
    )
    if binding is None:
        raise AgentTransportError("target has no active agent binding")
    # Refuse a client certificate whose URI does not match the workload identity
    # the agent listener is configured to require.
    try:
        cert = x509.load_pem_x509_certificate(Path(settings.cert_file).read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if settings.controller_identity_uri not in san.get_values_for_type(x509.UniformResourceIdentifier):
            raise AgentTransportError("Controller certificate identity does not match configured workload")
        context = ssl.create_default_context(cafile=settings.ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(settings.cert_file, settings.key_file)
    except AgentTransportError:
        raise
    except (OSError, ValueError, ssl.SSLError, x509.ExtensionNotFound) as exc:
        raise AgentTransportError("Controller mTLS certificate configuration is invalid") from exc
    client = httpx.Client(verify=context, follow_redirects=False, trust_env=False)
    return VerifiedAgentClient(client, db, target.id)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
