from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.agents.identity import (
    activate_agent, activate_credential, add_pending_credential,
    bind_target_to_agent, create_pending_agent,
)
from app.agents.mtls import AgentTransportError, TLSSettings, make_verified_agent_client
from app.auth.oidc import Principal, require_target_read
from app.assessments.provenance import (
    ObservationTrustState,
    SupportedBindingVersions,
    resolve_assessment_observation,
    store_assessment_observation,
)
from app.db.database import get_db
from app.db.models import AssessmentObservation, AssessmentObservationTrust, Base, SecurityAuditEvent, Target, TargetAgentBinding
from app.main import app
from app.policies.registry import assign_policy_to_target, register_definition
from app.policies.review import review_policy_definition
from app.policies.trust import PolicyTrustPin


def issue_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "temporary test CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None,
        ), critical=True).sign(key, hashes.SHA256())
    )
    return cert, key


def issue_leaf(ca, ca_key, uri, *, dns=(), client=False, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=3) if expired else now - timedelta(minutes=5)
    end = now - timedelta(days=2) if expired else now + timedelta(days=3)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uri.rsplit("/", 1)[-1])]))
        .issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(uri),
            *[x509.DNSName(name) for name in dns],
        ]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        ]), critical=False).sign(ca_key, hashes.SHA256())
    )
    return cert, key


def write_pair(root, stem, cert, key):
    cert_path, key_path = root / f"{stem}.pem", root / f"{stem}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    return cert_path, key_path


class AgentMTLSTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.engine = create_engine(f"sqlite:///{self.root / 'isolated.sqlite'}")

        @event.listens_for(self.engine, "connect")
        def fk(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine, expire_on_commit=False)()
        self.target = Target(
            id="tls-target", name="TLS target", platform="ubuntu",
            address="localhost", status="REGISTERED"
        )
        self.db.add(self.target)
        self.db.commit()
        self.ca, self.ca_key = issue_ca()
        self.agent_uri = "spiffe://lab/agent/tls-agent"
        self.controller_uri = "spiffe://lab/controller/test"
        self.agent_cert, self.agent_key = issue_leaf(
            self.ca, self.ca_key, self.agent_uri, dns=("localhost",)
        )
        self.controller_cert, self.controller_key = issue_leaf(
            self.ca, self.ca_key, self.controller_uri, client=True
        )
        wrong_controller, wrong_controller_key = issue_leaf(
            self.ca, self.ca_key, "spiffe://lab/controller/wrong", client=True
        )
        self.ca_path = self.root / "ca.pem"
        self.ca_path.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        self.server_pair = write_pair(self.root, "agent", self.agent_cert, self.agent_key)
        self.client_pair = write_pair(self.root, "controller", self.controller_cert, self.controller_key)
        self.wrong_client_pair = write_pair(self.root, "wrong-controller", wrong_controller, wrong_controller_key)
        create_pending_agent(
            self.db, agent_id="tls-agent", workload_identity_uri=self.agent_uri
        )
        fingerprint = "sha256:" + hashlib.sha256(
            self.agent_cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        public_key_fingerprint = "sha256:" + hashlib.sha256(
            self.agent_cert.public_key().public_bytes(
                serialization.Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        self.credential = add_pending_credential(
            self.db, agent_id="tls-agent", fingerprint_sha256=fingerprint,
            public_key_sha256=public_key_fingerprint,
            identity_uri=self.agent_uri, not_before=datetime.now(timezone.utc) - timedelta(minutes=1),
            expires_at=datetime.now(timezone.utc) + timedelta(days=2),
        )
        activate_agent(self.db, "tls-agent")
        activate_credential(self.db, self.credential.id, now=datetime.now(timezone.utc))
        bind_target_to_agent(
            self.db, target_id=self.target.id, agent_id="tls-agent",
            credential_id=self.credential.id,
        )

    def tearDown(self):
        self.db.close()
        self.engine.dispose()
        self.temp.cleanup()

    def settings(self, *, ca=None, controller_uri=None, client_pair=None):
        client_pair = client_pair or self.client_pair
        return patch.dict("os.environ", {
            "CONTROLLER_AGENT_CA_FILE": str(ca or self.ca_path),
            "CONTROLLER_AGENT_CERT_FILE": str(client_pair[0]),
            "CONTROLLER_AGENT_KEY_FILE": str(client_pair[1]),
            "CONTROLLER_WORKLOAD_IDENTITY": controller_uri or self.controller_uri,
        }, clear=True)

    def serve(self, cert_pair=None, ca_path=None, body=b'{"status":"online"}', delay=0):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if delay:
                    time.sleep(delay)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except BrokenPipeError:
                    pass

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*(cert_pair or self.server_pair))
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_path or self.ca_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=2), server.server_close()))
        return f"https://localhost:{server.server_port}"

    def test_ephemeral_local_mtls_request_is_verified_and_bound_to_target(self):
        with self.settings():
            url = self.serve()
            client = make_verified_agent_client(self.db, target=self.target, base_url=url)
            self.addCleanup(client.close)
            response = client.get(url + "/status", timeout=3)
            self.assertEqual(response.json(), {"status": "online"})

    def test_mtls_assessment_records_channel_identity_without_approval_trust(self):
        body = (
            b'{"platform":"ubuntu","findings":[{"control_id":"SSH-1",'
            b'"title":"SSH","status":"FAIL","severity":"HIGH",'
            b'"current_value":"yes","expected_value":"no","message":"disable",'
            b'"source":"sshd","evidence":[]}]}'
        )
        with self.settings():
            url = self.serve(body=body)
            client = make_verified_agent_client(self.db, target=self.target, base_url=url)
            self.addCleanup(client.close)
            response = client.get(url + "/assessment", timeout=3)
            peer = client.authenticated_peer
            self.assertIsNotNone(peer)
            row = store_assessment_observation(
                self.db,
                target=self.target,
                raw_payload=response.content,
                authenticated_peer=peer,
            )
            self.assertEqual(
                row.trust_status,
                AssessmentObservationTrust.AUTHENTICATED_AGENT_TARGET_BOUND.value,
            )
            self.assertEqual(row.authenticated_agent_id, "tls-agent")
            resolved = resolve_assessment_observation(
                self.db,
                observation_id=row.observation_id,
                target=self.target,
                now=datetime.now(timezone.utc) + timedelta(seconds=1),
                max_age=timedelta(minutes=1),
                versions=SupportedBindingVersions(),
                expected_policy_version=None,
                expected_catalog_version=None,
            )
            self.assertEqual(
                resolved.observation_state,
                ObservationTrustState.AUTHENTICATED_AGENT_TARGET_BOUND,
            )
            self.assertEqual(resolved.approval_state, ObservationTrustState.UNRESOLVED_UNTRUSTED)
            self.assertIsNone(resolved.approval_context)

    def test_caller_cannot_forge_authenticated_peer_metadata(self):
        from app.agents.mtls import AuthenticatedAgentPeer

        forged = AuthenticatedAgentPeer(
            target_id=self.target.id,
            agent_id="tls-agent",
            binding_generation=self.db.scalar(
                select(TargetAgentBinding).where(TargetAgentBinding.target_id == self.target.id)
            ).generation,
            credential_id=self.credential.id,
            certificate_fingerprint=self.credential.fingerprint_sha256,
            identity_uri=self.agent_uri,
        )
        with self.assertRaises(ValueError):
            store_assessment_observation(
                self.db,
                target=self.target,
                raw_payload=(
                    b'{"platform":"ubuntu","findings":[]}'
                ),
                authenticated_peer=forged,
            )

    def test_bad_ca_wrong_hostname_expired_and_wrong_agent_certificate_fail(self):
        rogue_ca, _ = issue_ca()
        rogue_ca_path = self.root / "rogue-ca.pem"
        rogue_ca_path.write_bytes(rogue_ca.public_bytes(serialization.Encoding.PEM))
        with self.settings(ca=rogue_ca_path):
            url = self.serve()
            client = make_verified_agent_client(self.db, target=self.target, base_url=url)
            self.addCleanup(client.close)
            with self.assertRaises(httpx.HTTPError):
                client.get(url + "/status", timeout=3)

        with self.settings():
            url = self.serve()
            client = make_verified_agent_client(self.db, target=self.target, base_url=url)
            self.addCleanup(client.close)
            with self.assertRaises(httpx.HTTPError):
                client.get(url.replace("localhost", "127.0.0.1") + "/status", timeout=3)

            expired, expired_key = issue_leaf(
                self.ca, self.ca_key, self.agent_uri, dns=("localhost",), expired=True
            )
            expired_pair = write_pair(self.root, "expired", expired, expired_key)
            with self.assertRaises(httpx.HTTPError):
                client.get(self.serve(expired_pair) + "/status", timeout=3)

            other, other_key = issue_leaf(
                self.ca, self.ca_key, "spiffe://lab/agent/other", dns=("localhost",)
            )
            other_pair = write_pair(self.root, "other", other, other_key)
            with self.assertRaises(AgentTransportError):
                client.get(self.serve(other_pair) + "/status", timeout=3)

    def test_wrong_controller_identity_revoked_binding_and_downgrade_fail(self):
        with self.settings(client_pair=self.wrong_client_pair):
            with self.assertRaises(AgentTransportError):
                make_verified_agent_client(
                    self.db, target=self.target, base_url="https://localhost:9000"
                )

        with self.settings():
            with self.assertRaises(AgentTransportError):
                make_verified_agent_client(
                    self.db, target=self.target, base_url="http://192.0.2.50:9000"
                )
            binding = self.db.query(TargetAgentBinding).first()
            binding.state = "revoked"
            self.db.commit()
            with self.assertRaises(AgentTransportError):
                make_verified_agent_client(
                    self.db, target=self.target, base_url="https://localhost:9000"
                )

            self.db.rollback()
            # Revocation after client construction is checked against current
            # Controller state before the response body is read or stored.
            binding = self.db.scalar(select(TargetAgentBinding).where(TargetAgentBinding.target_id == self.target.id))
            binding.state = "active"
            self.credential.state = "active"
            self.db.commit()
            client = make_verified_agent_client(
                self.db, target=self.target, base_url="https://localhost:9000"
            )
            self.addCleanup(client.close)
            url = self.serve()
            self.credential.state = "revoked"
            self.credential.revoked_at = datetime.now(timezone.utc)
            self.db.commit()
            with self.assertRaises(AgentTransportError):
                client.get(url + "/status", timeout=3)
            self.assertEqual(self.db.scalar(select(AssessmentObservation)), None)

    def test_expired_registered_agent_credential_fails_after_tls_verification(self):
        with self.settings():
            url = self.serve()
            client = make_verified_agent_client(self.db, target=self.target, base_url=url)
            self.addCleanup(client.close)
            self.credential.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            self.db.commit()
            with self.assertRaises(AgentTransportError):
                client.get(url + "/status", timeout=3)

    def test_binding_replacement_during_request_rejects_old_peer_before_body_use(self):
        with self.settings():
            url = self.serve()
            client = make_verified_agent_client(self.db, target=self.target, base_url=url)
            self.addCleanup(client.close)
            create_pending_agent(
                self.db, agent_id="replacement-agent",
                workload_identity_uri="spiffe://lab/agent/replacement-agent",
            )
            credential = add_pending_credential(
                self.db, agent_id="replacement-agent",
                fingerprint_sha256="sha256:" + "f" * 64,
                identity_uri="spiffe://lab/agent/replacement-agent",
                not_before=datetime.now(timezone.utc) - timedelta(minutes=1),
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
            activate_agent(self.db, "replacement-agent")
            activate_credential(self.db, credential.id, now=datetime.now(timezone.utc))
            bind_target_to_agent(
                self.db, target_id=self.target.id, agent_id="replacement-agent",
                credential_id=credential.id,
            )
            with self.assertRaises(AgentTransportError):
                client.get(url + "/assessment", timeout=3)
            self.assertEqual(self.db.scalar(select(AssessmentObservation)), None)

    def test_incomplete_tls_configuration_fails_closed(self):
        with patch.dict("os.environ", {"CONTROLLER_AGENT_CA_FILE": "only-ca.pem"}, clear=True):
            with self.assertRaises(AgentTransportError):
                TLSSettings.from_env()

    def test_verified_https_timeout_fails_without_downgrade(self):
        with self.settings():
            url = self.serve(delay=0.5)
            client = make_verified_agent_client(self.db, target=self.target, base_url=url)
            self.addCleanup(client.close)
            with self.assertRaises(httpx.ReadTimeout):
                client.get(url + "/status", timeout=0.1)

    def test_actual_go_agent_process_mtls_and_unsupported_host_assessment_denial(self):
        repository = Path(__file__).resolve().parents[2]
        executable = self.root / "agent-process"
        built = subprocess.run(
            ["go", "build", "-o", str(executable), "./cmd/agent"],
            cwd=repository / "agent",
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(built.returncode, 0, built.stderr)

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        environment = os.environ.copy()
        environment.pop("AGENT_EXECUTION_TOKEN", None)
        environment.update({
            "AGENT_ID": "tls-agent",
            "AGENT_HOST": "127.0.0.1",
            "AGENT_PORT": str(port),
            "AGENT_TLS_CERT_FILE": str(self.server_pair[0]),
            "AGENT_TLS_KEY_FILE": str(self.server_pair[1]),
            "AGENT_TLS_CLIENT_CA_FILE": str(self.ca_path),
            "AGENT_TLS_CONTROLLER_IDENTITY": self.controller_uri,
        })
        process = subprocess.Popen(
            [str(executable)], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.addCleanup(self._stop_process, process)
        base_url = f"https://localhost:{port}"

        with self.settings():
            client = make_verified_agent_client(self.db, target=self.target, base_url=base_url)
            self.addCleanup(client.close)
            deadline = time.monotonic() + 10
            while True:
                try:
                    status = client.get(base_url + "/status", timeout=1)
                    break
                except httpx.ConnectError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        self.fail("actual Go agent did not start its mTLS listener")
                    time.sleep(0.05)
            self.assertEqual(status.json(), {"agent_id": "tls-agent", "status": "online"})
            self.assertIsNotNone(client.authenticated_peer)
            self.assertEqual(client.authenticated_peer.agent_id, "tls-agent")
            discovery_response = client.get(base_url + "/discovery", timeout=3)
            discovery = discovery_response.json()
            self.assertIn(discovery["os"], {"darwin", "linux", "windows", "freebsd", "openbsd", "netbsd"})
            self.assertTrue(discovery["architecture"])
            for route in ("execute", "rollback"):
                denied = client.get(base_url + f"/{route}", timeout=3)
                self.assertEqual(denied.status_code, 404)
                with client.stream("POST", base_url + f"/{route}", timeout=3) as denied_post:
                    self.assertEqual(denied_post.status_code, 404)

            # The real listener requires a trusted Controller client cert and
            # checks its workload URI, in addition to the Controller's own
            # normal server-chain/hostname and active binding checks.
            no_identity_context = ssl.create_default_context(cafile=str(self.ca_path))
            with httpx.Client(verify=no_identity_context, trust_env=False, timeout=3) as anonymous:
                with self.assertRaises(httpx.HTTPError):
                    anonymous.get(base_url + "/status")
            wrong_identity_context = ssl.create_default_context(cafile=str(self.ca_path))
            wrong_identity_context.load_cert_chain(*map(str, self.wrong_client_pair))
            with httpx.Client(verify=wrong_identity_context, trust_env=False, timeout=3) as wrong_identity:
                with self.assertRaises(httpx.HTTPError):
                    wrong_identity.get(base_url + "/status")
            rogue_ca, rogue_ca_key = issue_ca()
            rogue_controller, rogue_controller_key = issue_leaf(
                rogue_ca, rogue_ca_key, self.controller_uri, client=True
            )
            rogue_pair = write_pair(self.root, "rogue-controller", rogue_controller, rogue_controller_key)
            untrusted_context = ssl.create_default_context(cafile=str(self.ca_path))
            untrusted_context.load_cert_chain(*map(str, rogue_pair))
            with httpx.Client(verify=untrusted_context, trust_env=False, timeout=3) as untrusted:
                with self.assertRaises(httpx.HTTPError):
                    untrusted.get(base_url + "/status")

            # Use a test-only policy that is deliberately incompatible with
            # the agent's real host result. The route must emit a sanitized
            # denial rather than manufacture Ubuntu evidence.
            policy_definition = {
                "schema": "aha-agent-assessment-policy/v1",
                "platform": "ubuntu",
                "os_version": "Ubuntu 24.04.5 LTS",
                "architecture": "arm64",
                "controls": [{"control_id": "TEST-ONLY-NO-MATCH", "expected_value": "fixture"}],
            }
            policy = register_definition(
                self.db,
                platform="ubuntu",
                policy_version="process-test-v1",
                catalog_version="process-test-catalog-v1",
                definition=policy_definition,
                provenance_reference="test-only:actual-go-process",
            )
            pin = PolicyTrustPin(
                provenance_reference=policy.provenance_reference,
                source_evidence_sha256="sha256:" + "e" * 64,
                definition_sha256=policy.definition_sha256,
                platform=policy.platform,
                policy_version=policy.policy_version,
                catalog_version=policy.catalog_version,
                applicability_confirmed=True,
            )
            trust_pins = [{
                "provenance_reference": pin.provenance_reference,
                "source_evidence_sha256": pin.source_evidence_sha256,
                "definition_sha256": pin.definition_sha256,
                "platform": pin.platform,
                "policy_version": pin.policy_version,
                "catalog_version": pin.catalog_version,
                "applicability_confirmed": True,
            }]
            os.environ["POLICY_REVIEW_TRUST_PINS_JSON"] = json.dumps(trust_pins)
            reviewer = Principal("https://reviewer.example.test", "test-reviewer", frozenset({"policy-reviewer"}))
            review_policy_definition(
                self.db,
                definition_id=policy.id,
                decision="approved",
                rationale="process integration test fixture only",
                source_evidence_sha256=pin.source_evidence_sha256,
                reviewer=reviewer,
                trust_pins=(pin,),
            )
            assign_policy_to_target(self.db, target_id=self.target.id, definition_id=policy.id)

            requester = Principal("https://identity.example.test", "process-test-reader", frozenset({"target-reader"}))
            app.dependency_overrides[get_db] = lambda: self.db
            app.dependency_overrides[require_target_read] = lambda: requester
            self.addCleanup(app.dependency_overrides.clear)
            with patch.dict(os.environ, {
                "AGENT_STATUS_URL_OVERRIDES": json.dumps({self.target.id: base_url}),
                "POLICY_REVIEW_TRUST_PINS_JSON": json.dumps(trust_pins),
            }, clear=False):
                response = TestClient(app).get(
                    f"/api/targets/{self.target.id}/assessment"
                )
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(
                self.db.query(AssessmentObservation).count(), 0,
                "incompatible real host must not create an assessment observation",
            )
            failures = self.db.query(SecurityAuditEvent).filter_by(event_type="assessment.failed").all()
            self.assertEqual(len(failures), 1)
            metadata = json.loads(failures[0].metadata_json)
            self.assertEqual(metadata, {"outcome": "failed", "reason_code": "policy_or_result_rejected"})
            serialized_events = "".join(row.metadata_json for row in self.db.query(SecurityAuditEvent).all())
            for sensitive in ("private key", "bootstrap_token", "authorization", "credential"):
                self.assertNotIn(sensitive, serialized_events.lower())

    @staticmethod
    def _stop_process(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
