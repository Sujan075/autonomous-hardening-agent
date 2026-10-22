import json
import unittest
from unittest.mock import Mock, patch

import httpx

from app.agents.client import (
    AgentStatusURLConfigurationError,
    get_agent_status,
    resolve_agent_status_url,
)


TARGET_ID = "8865f49b-d545-4a8a-8511-766eaedea892"


class AgentStatusURLTests(unittest.TestCase):
    @patch("app.agents.client.httpx.get")
    def test_valid_target_override_is_used_for_status_get(self, mock_get: Mock) -> None:
        mock_get.return_value = httpx.Response(
            200,
            json={"agent_id": "lab-agent", "status": "ready"},
            request=httpx.Request("GET", "http://127.0.0.1:19000/status"),
        )
        overrides = json.dumps({TARGET_ID: "http://127.0.0.1:19000"})

        url = resolve_agent_status_url(TARGET_ID, "192.0.2.10", overrides)
        status = get_agent_status(url)

        self.assertTrue(status.reachable)
        self.assertEqual(status.agent_id, "lab-agent")
        mock_get.assert_called_once_with("http://127.0.0.1:19000/status", timeout=5.0)

    @patch.dict("os.environ", {}, clear=True)
    @patch("app.agents.client.httpx.get")
    def test_target_without_override_uses_legacy_fallback(self, mock_get: Mock) -> None:
        mock_get.return_value = httpx.Response(
            200,
            json={"status": "ready"},
            request=httpx.Request("GET", "http://192.0.2.10:9000/status"),
        )

        url = resolve_agent_status_url(TARGET_ID, "192.0.2.10", "{}")
        status = get_agent_status(url)

        self.assertTrue(status.reachable)
        mock_get.assert_called_once_with("http://192.0.2.10:9000/status", timeout=5.0)

    @patch("app.agents.client.httpx.get")
    def test_malformed_json_and_override_configuration_fail_closed(self, mock_get: Mock) -> None:
        for raw in ("{", "[]", json.dumps({TARGET_ID: 42})):
            with self.subTest(raw=raw), self.assertRaises(AgentStatusURLConfigurationError):
                resolve_agent_status_url(TARGET_ID, "192.0.2.10", raw)

        mock_get.assert_not_called()

    @patch("app.agents.client.httpx.get")
    def test_non_loopback_http_override_is_rejected_without_request(self, mock_get: Mock) -> None:
        overrides = json.dumps({TARGET_ID: "http://192.0.2.10:19000"})

        with self.assertRaises(AgentStatusURLConfigurationError):
            resolve_agent_status_url(TARGET_ID, "192.0.2.10", overrides)

        mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
