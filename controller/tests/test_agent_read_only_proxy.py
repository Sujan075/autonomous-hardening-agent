import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
from fastapi.testclient import TestClient

from app.db.database import get_db
from app.main import app


TARGET_ID = "8865f49b-d545-4a8a-8511-766eaedea892"
TARGET = SimpleNamespace(id=TARGET_ID, name="Ubuntu lab", address="192.0.2.10")


class AgentReadOnlyProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = Mock()
        self.db.scalar.return_value = TARGET
        app.dependency_overrides[get_db] = lambda: self.db
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    @patch.dict("os.environ", {"AGENT_STATUS_URL_OVERRIDES": json.dumps({TARGET_ID: "http://127.0.0.1:19000"})})
    @patch("app.agents.client.httpx.get")
    def test_assessment_uses_override_and_preserves_upstream_json(self, mock_get: Mock) -> None:
        payload = {"items": [{"id": "CIS-1", "details": {"severity": "high"}}]}
        mock_get.return_value = httpx.Response(
            200,
            json=payload,
            request=httpx.Request("GET", "http://127.0.0.1:19000/assessment"),
        )

        response = self.client.get(f"/api/targets/{TARGET_ID}/assessment")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "target_id": TARGET_ID,
            "target_name": "Ubuntu lab",
            "assessment": payload,
        })
        mock_get.assert_called_once_with("http://127.0.0.1:19000/assessment", timeout=5.0)

    @patch.dict("os.environ", {"AGENT_STATUS_URL_OVERRIDES": json.dumps({TARGET_ID: "http://127.0.0.1:19000"})})
    @patch("app.agents.client.httpx.get")
    def test_plan_uses_override_and_returns_named_payload(self, mock_get: Mock) -> None:
        payload = {"steps": [{"action": "disable-service", "args": {"name": "telnet"}}]}
        mock_get.return_value = httpx.Response(
            200,
            json=payload,
            request=httpx.Request("GET", "http://127.0.0.1:19000/plan"),
        )

        response = self.client.get(f"/api/targets/{TARGET_ID}/plan")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "target_id": TARGET_ID,
            "target_name": "Ubuntu lab",
            "plan": payload,
        })
        mock_get.assert_called_once_with("http://127.0.0.1:19000/plan", timeout=5.0)

    @patch("app.agents.client.httpx.get")
    def test_unknown_target_returns_404_without_request(self, mock_get: Mock) -> None:
        self.db.scalar.return_value = None

        response = self.client.get(f"/api/targets/{TARGET_ID}/assessment")

        self.assertEqual(response.status_code, 404)
        mock_get.assert_not_called()

    @patch("app.agents.client.httpx.get")
    def test_missing_agent_address_returns_400_without_request(self, mock_get: Mock) -> None:
        self.db.scalar.return_value = SimpleNamespace(
            id=TARGET_ID, name="Ubuntu lab", address=None
        )

        response = self.client.get(f"/api/targets/{TARGET_ID}/plan")

        self.assertEqual(response.status_code, 400)
        mock_get.assert_not_called()

    @patch.dict("os.environ", {"AGENT_STATUS_URL_OVERRIDES": "{"})
    @patch("app.agents.client.httpx.get")
    def test_invalid_override_returns_error_without_request(self, mock_get: Mock) -> None:
        response = self.client.get(f"/api/targets/{TARGET_ID}/plan")

        self.assertEqual(response.status_code, 500)
        mock_get.assert_not_called()

    @patch.dict("os.environ", {}, clear=True)
    @patch("app.agents.client.httpx.get")
    def test_upstream_connection_and_invalid_json_return_502(self, mock_get: Mock) -> None:
        mock_get.side_effect = httpx.ConnectTimeout("timed out")
        failed = self.client.get(f"/api/targets/{TARGET_ID}/assessment")
        self.assertEqual(failed.status_code, 502)
        mock_get.assert_called_once_with("http://192.0.2.10:9000/assessment", timeout=5.0)

        mock_get.reset_mock()
        mock_get.return_value = httpx.Response(
            200,
            content=b"not-json",
            request=httpx.Request("GET", "http://192.0.2.10:9000/plan"),
        )
        invalid_json = self.client.get(f"/api/targets/{TARGET_ID}/plan")
        self.assertEqual(invalid_json.status_code, 502)
        mock_get.assert_called_once_with("http://192.0.2.10:9000/plan", timeout=5.0)


if __name__ == "__main__":
    unittest.main()
