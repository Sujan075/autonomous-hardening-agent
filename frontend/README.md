# Security Operations Dashboard

The React/TypeScript dashboard reads the FastAPI Controller. It does not expose execute, rollback, decoy-generation, or reset actions.

## Local setup

Requirements: Node.js 20.19+ or 22.12+, npm, and the Controller reachable at `http://127.0.0.1:8000` by default.

```sh
cd /Users/jusujan/Projects/autonomous-hardening-agent/frontend
npm ci
cp .env.example .env.local
npm run dev
```

Vite binds to `127.0.0.1:5173`. Configure `VITE_CONTROLLER_URL` and, for a trusted local demo only, `VITE_API_TOKEN` in `.env.local`. `VITE_` values are visible to browser code; never use a production secret here. The Controller must have `AHA_DASHBOARD_CORS=1` for the two exact local Vite origins. CORS is read-only and does not allow credentials.

## Data and evidence levels

- Target inventory, agent status, discovery, assessment, plan, and audit history are fetched from Controller GET routes.
- Assessment collection is a user-triggered GET that stores an observation and audit event.
- The trusted Controller policy decision is displayed separately from the agent-reported decision. Missing or malformed API data stays an error/unknown state.
- Ubuntu and CentOS cards describe implemented read-only assessment scope. CentOS remediation remains blocked. Neither card implies complete CIS coverage.
- The remediation sandbox page displays persisted output from the fixed local OpenSSH fixture. Its execution, policy, and approval are explicitly sandbox-only/test-only.
- The decoy page displays persisted `SIMULATED` records from RFC 5737 documentation address ranges. No decoy listener is running and no event invokes remediation.
- Demo APIs are hidden unless `AHA_ENABLE_DEMO_READ_API=1`; all APIs require OIDC authorization. Audit history additionally requires the separately configured `OIDC_AUDIT_READ_ROLE`.
- API failures, authentication failures, loading states, and empty responses remain distinct. There are no hardcoded event or run records.

## Controller GET routes

- `GET /health`
- `GET /api/targets`
- `GET /api/targets/{target_id}/agent-status`
- `GET /api/targets/{target_id}/discovery`
- `GET /api/targets/{target_id}/assessment`
- `GET /api/targets/{target_id}/plan`
- `GET /api/demo/remediation-runs` (explicit demo-read flag)
- `GET /api/demo/decoy-events` (explicit demo-read flag)
- `GET /api/audit/events` (separate audit-read role)

## Checks

```sh
npm run check
npm test
npm run build
```

See [the integrated judge runbook](../docs/runbooks/INTEGRATED_DEMO.md) for Controller, dashboard, safe sandbox, and synthetic event setup.
