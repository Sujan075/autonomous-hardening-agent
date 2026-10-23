import json
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import httpx
from fastapi.testclient import TestClient

from app.db.database import get_db
from app.db.models import Target
from app.auth.oidc import Principal, require_target_read
from app.main import app
from app.assessments.provenance import (
    ObservationStorageUnavailable,
)
from app.approvals.bindings import parse_assessment_json
from app.approvals.bindings import MAX_ASSESSMENT_JSON_BYTES


TARGET_ID = "8865f49b-d545-4a8a-8511-766eaedea892"
TARGET = Target(
    id=TARGET_ID,
    name="Ubuntu lab",
    platform="ubuntu",
    address="192.0.2.10",
    status="REGISTERED",
)


class AgentReadOnlyProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = Mock()
        self.db.scalar.return_value = TARGET
        self.db.get.return_value = TARGET
        app.dependency_overrides[get_db] = lambda: self.db
        app.dependency_overrides[require_target_read] = lambda: Principal(
            issuer="https://identity.example.test", subject="test-reader",
            roles=frozenset({"target-reader"}),
        )
        self.policy = SimpleNamespace(
            assignment=SimpleNamespace(
                policy_version="policy-test-v1", catalog_version="catalog-test-v1",
                definition_digest="sha256:" + "a" * 64, platform="ubuntu",
            ),
            definition_id=1, os_version="Ubuntu 24.04.5 LTS", architecture="arm64",
            controls=(("CIS-1", "no"),),
        )
        self.policy_patch = patch(
            "app.api.agent_status.resolve_assessment_policy", return_value=self.policy
        )
        self.policy_patch.start()
        self.validation_patch = patch(
            "app.api.agent_status.validate_assessment_matches_policy",
            side_effect=lambda _policy, *, raw_assessment, **_kwargs: parse_assessment_json(raw_assessment),
        )
        self.validation_patch.start()
        self.audit_patch = patch("app.api.agent_status.append_event")
        self.audit_patch.start()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.audit_patch.stop()
        self.validation_patch.stop()
        self.policy_patch.stop()
        app.dependency_overrides.clear()

    def test_no_controller_execute_or_rollback_routes_exist(self) -> None:
        def collect(routes):
            paths = set()
            for route in routes:
                path = getattr(route, "path", None)
                if path is not None:
                    paths.add(path)
                nested = getattr(route, "routes", None)
                if nested:
                    paths.update(collect(nested))
            return paths

        paths = collect(app.routes)
        self.assertNotIn("/api/targets/{target_id}/execute", paths)
        self.assertNotIn("/api/targets/{target_id}/rollback", paths)

    @patch.dict("os.environ", {"AGENT_STATUS_URL_OVERRIDES": json.dumps({TARGET_ID: "http://127.0.0.1:19000"})})
    @patch("app.agents.client.httpx.stream")
    @patch("app.api.agent_status.store_assessment_observation")
    def test_assessment_uses_override_stores_raw_and_preserves_upstream_json(
        self, mock_store: Mock, mock_stream: Mock
    ) -> None:
        payload = {
            "platform": "ubuntu",
            "findings": [{
                "control_id": "CIS-1", "title": "SSH setting", "status": "FAIL",
                "severity": "high", "current_value": "yes", "expected_value": "no",
                "message": "disable root login", "source": "sshd",
            }],
        }
        upstream_response = httpx.Response(
            200,
            json=payload,
            request=httpx.Request("GET", "http://127.0.0.1:19000/assessment"),
        )
        mock_stream.return_value = nullcontext(upstream_response)
        mock_store.return_value = SimpleNamespace(
            observation_id="observation-controller-1",
            trust_status="controller_observed_unauthenticated",
            payload_sha256="sha256:" + "b" * 64,
        )

        response = self.client.get(f"/api/targets/{TARGET_ID}/assessment")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "target_id": TARGET_ID,
            "target_name": "Ubuntu lab",
            "assessment": payload,
            "assessment_observation_id": "observation-controller-1",
            "assessment_trust_status": "controller_observed_unauthenticated",
            "policy_status": "reviewed_assignment_matched_to_agent_reported_result",
            "policy": {
                "policy_version": "policy-test-v1",
                "catalog_version": "catalog-test-v1",
                "definition_digest": "sha256:" + "a" * 64,
                "platform": "ubuntu",
                "os_version": "Ubuntu 24.04.5 LTS",
                "architecture": "arm64",
                "agent_channel_authenticated": False,
                "planning_recommendations": "available_separately_at_plan_endpoint",
            },
        })
        self.assertEqual(mock_stream.call_args_list, [
            call("GET", "http://127.0.0.1:19000/discovery", timeout=5.0),
            call("GET", "http://127.0.0.1:19000/assessment", timeout=5.0),
        ])
        mock_store.assert_called_once()
        self.assertEqual(mock_store.call_args.kwargs["target"], TARGET)
        self.assertEqual(mock_store.call_args.kwargs["policy_version"], "policy-test-v1")
        self.assertEqual(mock_store.call_args.kwargs["catalog_version"], "catalog-test-v1")
        self.assertFalse(mock_store.call_args.kwargs["commit"])

    @patch.dict("os.environ", {"AGENT_STATUS_URL_OVERRIDES": json.dumps({TARGET_ID: "http://127.0.0.1:19000"})})
    @patch("app.agents.client.httpx.stream")
    @patch("app.api.agent_status.store_assessment_observation")
    def test_assessment_storage_failure_is_not_reported_as_success(
        self, mock_store: Mock, mock_stream: Mock
    ) -> None:
        upstream_response = httpx.Response(
            200,
            json={"platform": "ubuntu", "findings": []},
            request=httpx.Request("GET", "http://127.0.0.1:19000/assessment"),
        )
        mock_stream.return_value = nullcontext(upstream_response)
        mock_store.side_effect = ObservationStorageUnavailable("offline")

        response = self.client.get(f"/api/targets/{TARGET_ID}/assessment")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(mock_stream.call_count, 2)
        mock_store.assert_called_once()

    @patch.dict("os.environ", {"AGENT_STATUS_URL_OVERRIDES": json.dumps({TARGET_ID: "http://127.0.0.1:19000"})})
    @patch("app.agents.client.httpx.stream")
    @patch("app.api.agent_status.store_assessment_observation")
    def test_oversized_agent_assessment_is_rejected_before_storage(
        self, mock_store: Mock, mock_stream: Mock
    ) -> None:
        upstream_response = httpx.Response(
            200,
            content=b" " * (MAX_ASSESSMENT_JSON_BYTES + 1),
            request=httpx.Request("GET", "http://127.0.0.1:19000/assessment"),
        )
        mock_stream.return_value = nullcontext(upstream_response)

        response = self.client.get(f"/api/targets/{TARGET_ID}/assessment")

        self.assertEqual(response.status_code, 502)
        mock_store.assert_not_called()

    @patch.dict("os.environ", {"AGENT_STATUS_URL_OVERRIDES": json.dumps({TARGET_ID: "http://127.0.0.1:19000"})})
    @patch("app.agents.client.httpx.stream")
    def test_plan_uses_override_and_returns_named_payload(self, mock_stream: Mock) -> None:
        payload = {"steps": [{"action": "disable-service", "args": {"name": "telnet"}}]}
        mock_stream.return_value = nullcontext(httpx.Response(
            200,
            json=payload,
            request=httpx.Request("GET", "http://127.0.0.1:19000/plan"),
        ))

        response = self.client.get(f"/api/targets/{TARGET_ID}/plan")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "target_id": TARGET_ID,
            "target_name": "Ubuntu lab",
            "plan": payload,
        })
        mock_stream.assert_called_once_with("GET", "http://127.0.0.1:19000/plan", timeout=5.0)

    @patch("app.agents.client.httpx.stream")
    def test_unknown_target_returns_404_without_request(self, mock_stream: Mock) -> None:
        self.db.scalar.return_value = None

        response = self.client.get(f"/api/targets/{TARGET_ID}/assessment")

        self.assertEqual(response.status_code, 404)
        mock_stream.assert_not_called()

    @patch("app.agents.client.httpx.stream")
    def test_missing_agent_address_returns_400_without_request(self, mock_stream: Mock) -> None:
        self.db.scalar.return_value = SimpleNamespace(
            id=TARGET_ID, name="Ubuntu lab", address=None
        )

        response = self.client.get(f"/api/targets/{TARGET_ID}/plan")

        self.assertEqual(response.status_code, 400)
        mock_stream.assert_not_called()

    @patch.dict("os.environ", {"AGENT_STATUS_URL_OVERRIDES": "{"})
    @patch("app.agents.client.httpx.stream")
    def test_invalid_override_returns_error_without_request(self, mock_stream: Mock) -> None:
        response = self.client.get(f"/api/targets/{TARGET_ID}/plan")

        self.assertEqual(response.status_code, 500)
        mock_stream.assert_not_called()

    @patch.dict(
        "os.environ",
        {"AGENT_STATUS_URL_OVERRIDES": json.dumps({TARGET_ID: "http://127.0.0.1:19000"})},
        clear=True,
    )
    @patch("app.agents.client.httpx.stream")
    def test_upstream_connection_and_invalid_json_return_502(self, mock_stream: Mock) -> None:
        mock_stream.side_effect = httpx.ConnectTimeout("timed out")
        failed = self.client.get(f"/api/targets/{TARGET_ID}/assessment")
        self.assertEqual(failed.status_code, 502)
        mock_stream.assert_called_once_with("GET", "http://127.0.0.1:19000/discovery", timeout=5.0)

        mock_stream.reset_mock()
        mock_stream.return_value = nullcontext(httpx.Response(
            200,
            content=b"not-json",
            request=httpx.Request("GET", "http://127.0.0.1:19000/plan"),
        ))
        invalid_json = self.client.get(f"/api/targets/{TARGET_ID}/plan")
        self.assertEqual(invalid_json.status_code, 502)
        mock_stream.assert_called_once_with("GET", "http://127.0.0.1:19000/plan", timeout=5.0)


if __name__ == "__main__":
    unittest.main()
