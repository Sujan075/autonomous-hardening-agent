from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class AgentStatus:
    reachable: bool
    agent_id: str | None = None
    status: str | None = None
    error: str | None = None


def get_agent_status(base_url: str, timeout: float = 5.0) -> AgentStatus:
    url = f"{base_url.rstrip('/')}/status"

    try:
        response = httpx.get(url, timeout=timeout)
        response.raise_for_status()

        payload = response.json()

        return AgentStatus(
            reachable=True,
            agent_id=payload.get("agent_id"),
            status=payload.get("status"),
        )

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
