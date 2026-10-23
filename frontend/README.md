# Security Operations Dashboard

A standalone React, TypeScript, and Vite frontend for the Autonomous Multi-Platform Security Hardening Agent. It reads from the existing FastAPI Controller and does not perform remediation.

## Requirements

- Node.js 20.19+ or 22.12+
- npm
- The Controller running at a URL reachable from the browser (default `http://127.0.0.1:8000`)

## Install and run

```powershell
cd frontend
npm install
Copy-Item .env.example .env.local
npm run dev
```

Open the local URL printed by Vite (normally `http://localhost:5173`). Set `VITE_CONTROLLER_URL` in `.env.local` to change the Controller origin. For example:

```dotenv
VITE_CONTROLLER_URL=http://127.0.0.1:8000
```

The browser calls the Controller directly, so the Controller must allow the Vite origin through its CORS configuration. The current Controller does not configure CORS or expose a browser login flow. If target-read authorization is enabled, set a development bearer token in `.env.local` as `VITE_API_TOKEN=...` only for a trusted local environment; Vite exposes `VITE_` values to browser code, so do not put a production secret there. For production, use an authenticated same-origin gateway/session design.

## Data and safety

- `LIVE` marks values returned by the Controller. Inventory, agent status, assessment, and planning use only the Controller GET routes documented below.
- `FIXTURE` marks illustrative sandbox and decoy feed examples. They are not findings or activity from a real environment.
- Ubuntu is the only platform with live target evidence documented by the repository. Other environment cards show implementation/support state rather than implying enrolled targets.
- API errors stay visible as errors; demo fixtures never replace failed requests.
- The frontend does not call `/execute` or `/rollback` and cannot trigger privileged changes.
- The Controller currently has no audit-history, sandbox-run, or decoy-event read API. Those capabilities are explicitly unavailable or simulated in this UI.

## Controller GET routes used

- `GET /health`
- `GET /api/targets`
- `GET /api/targets/{target_id}/agent-status`
- `GET /api/targets/{target_id}/assessment`
- `GET /api/targets/{target_id}/plan`

Assessment collection is a GET that stores an observation and audit event in the Controller. The UI only makes this request after you select **Collect assessment**; each collection can create a new Controller observation.

## Checks

```powershell
npm run check
npm run build
```
