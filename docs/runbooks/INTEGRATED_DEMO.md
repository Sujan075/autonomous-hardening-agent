# Integrated SIH25237 local demonstration

This runbook connects the existing read-only target APIs, dashboard, local remediation fixture, synthetic decoy events, and Controller audit view. It does not mutate `AH-UBUNTU-01`, `AH-CENTOS-01`, or any registered target. The remediation runner only edits a temporary OpenSSH configuration tree under the local OS temp directory and deletes that tree before it returns. The decoy simulator opens no socket.

## Prerequisites and current limits

- macOS or Linux checkout at `/Users/jusujan/Projects/autonomous-hardening-agent`.
- Go compatible with `agent/go.mod`, Python dependencies from `controller/pyproject.toml` installed in `controller/.venv`, Node/npm installed, and `/usr/sbin/sshd` plus `ssh-keygen` available for the fixture.
- A locally configured OIDC issuer/JWKS and authorized development roles. The code requires `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `OIDC_ROLE_CLAIM`, `OIDC_TARGET_READ_ROLE`, `OIDC_TARGET_ADMIN_ROLE`, and `OIDC_ENROLLMENT_ADMIN_ROLE`. Use values provisioned for the local environment; this repository does not supply an IdP or tokens. Audit reads additionally require `OIDC_AUDIT_READ_ROLE` and that role on the browser token.
- Docker is installed in the inspected environment, but its daemon was unavailable. No disposable VM with a verified snapshot was available. This demo therefore uses a process/filesystem fixture and does not claim VM or production integration.

## A. Start the Controller on loopback

In Terminal 1, load the OIDC configuration from the operator's approved local secret/configuration source. Then enable only the local dashboard CORS and read-only demo APIs:

```sh
cd /Users/jusujan/Projects/autonomous-hardening-agent/controller
export AHA_DASHBOARD_CORS=1
export AHA_ENABLE_DEMO_READ_API=1
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The demo-read flag exposes only GET routes. CORS allows `http://127.0.0.1:5173` and `http://localhost:5173`, GET/OPTIONS, and no credential cookies. The SQLite database is the Controller's configured local database at `controller/hardening.db`; the demo tables are separate from targets and assessment observations.

In Terminal 2, confirm the process responds:

```sh
curl --fail --silent --show-error http://127.0.0.1:8000/health
```

Expected: `{"status":"ok"}`. If OIDC settings are absent or invalid, protected routes fail closed. Do not disable authorization to make the dashboard work.

## B. Start the dashboard

In Terminal 3:

```sh
cd /Users/jusujan/Projects/autonomous-hardening-agent/frontend
cp .env.example .env.local
npm ci
npm run dev
```

For authorized target/audit reads, set a short-lived **development** OIDC bearer token as `VITE_API_TOKEN` in `.env.local`, then restart Vite. Vite bundles this value into browser-accessible code; never place a production token there. Open `http://127.0.0.1:5173`.

## C. Show read-only target status and discovery

Choose a currently registered target in **Environments**. The page reads target inventory, agent connectivity, and `/discovery` through Controller-authenticated GET routes, and displays hostname, OS, OS version, kernel, architecture, and primary IP. Values are marked unavailable when the target cannot be reached. The repo records earlier read-only Ubuntu and CentOS evidence, but do not present that evidence as a new observation; collect a current assessment only if the authorized target is reachable.

Select **Collect assessment** to request the current four-control SSH assessment. The Controller validates the response against its reviewed policy assignment, stores the observation, and appends an audit event. In **Findings**, show each control's current/expected value and evidence source, followed by the separate trusted Controller decision and agent-reported decision. Where independent collection provenance is not established, the trusted decision remains `INDETERMINATE` even if the reported decision is `COMPLIANT` or `NON_COMPLIANT`.

The Ubuntu and CentOS judge runbooks contain exact historical target prerequisites and captured evidence:

- [Ubuntu 24.04.5 ARM64 read-only runbook](UBUNTU_24_04_ARM64_JUDGE_DEMO.md)
- [CentOS Stream 9 ARM64 read-only runbook](CENTOS_STREAM_9_ARM64_JUDGE_DEMO.md)

CentOS remains read-only; its planner returns `BLOCKED` with no actions. Neither four-control adapter establishes full CIS compliance.

The current Controller contract is read-only: `GET /api/targets/{target_id}/discovery`, `/assessment`, and `/plan`. Optional demo reads are `GET /api/demo/remediation-runs`, `GET /api/demo/decoy-events`, and `GET /api/audit/events`; they require their configured role and feature flags. There are no Controller execute/rollback or approval-issuance endpoints, and the running agent does not expose mutation routes. Browser-driven end-to-end validation is NOT RUN.

## D. Run the successful local remediation lifecycle

In Terminal 4, from `controller/`:

```sh
cd /Users/jusujan/Projects/autonomous-hardening-agent/controller
AHA_ENABLE_LOCAL_DEMO_CLI=1 .venv/bin/python -m app.demo remediation run --scenario roundtrip
```

Expected JSON includes `sandbox_only: true`, `test_only_trust: true`, `live_target_modified: false`, one fixed Ubuntu `ACT-SSH-5.1.20` plan action, `approval.status: APPROVED`, `execution.status: VERIFIED`, an independent `sshd -T -f` verification of `PermitRootLogin=no`, and a separately signed rollback with `recovery.status: ROLLED_BACK`. It also includes lifecycle and helper-audit records. The ephemeral P-256 signing key, approval token, replay journal, and temporary OpenSSH tree are removed from temporary storage when the command returns. The JSON does not expose a host filesystem state path.

Open **Validation sandbox** and refresh. It reads the persisted run through `GET /api/demo/remediation-runs`; it cannot start or approve a run. The dashboard shows the temporary pre-state, action result, independent verification, recovery, lifecycle states, and test-only labels. The Controller has no execute or rollback route.

## E. Demonstrate compliance and controlled verification failure/recovery

The compliant fixture confirms no action is issued:

```sh
AHA_ENABLE_LOCAL_DEMO_CLI=1 .venv/bin/python -m app.demo remediation run --scenario compliant
```

Expected: `status: COMPLIANT`, no action and no approval audit event.

The precedence-conflict fixture puts `PermitRootLogin yes` in an earlier `00-site-policy.conf`. OpenSSH's first-value behavior means the later candidate does not become effective. Run:

```sh
AHA_ENABLE_LOCAL_DEMO_CLI=1 .venv/bin/python -m app.demo remediation run --scenario precedence-conflict
```

Expected: the requested verification is `FAILED_AS_EXPECTED`; the existing executor removes its candidate drop-in, restores the prior effective value `yes`, and verifies that value independently. The run reports `ROLLED_BACK`; the helper audit outcome reports recovery required for the failed action. Refresh **Validation sandbox** to inspect the evidence.

List stored runs:

```sh
AHA_ENABLE_LOCAL_DEMO_CLI=1 .venv/bin/python -m app.demo remediation list
```

These scenarios are a test-only, same-process fixture lifecycle. They do not establish a privileged helper deployment, VM snapshot/recovery, human approval authorization, production trust, or live execution.

## F. Generate and reset safe synthetic decoy events

Generate ten deterministic, non-network events in a separate SQLite table:

```sh
AHA_ENABLE_LOCAL_DEMO_CLI=1 .venv/bin/python -m app.demo decoy generate
AHA_ENABLE_LOCAL_DEMO_CLI=1 .venv/bin/python -m app.demo decoy list
```

The event sources are RFC 5737 documentation ranges and are marked `SIMULATED`; each event has a timestamp, decoy ID, category, source classification, correlation ID, and outcome. No socket, exploit, login, scan, target association, executor call, or approval is involved. In the dashboard, open **Decoy monitor**, refresh, and filter by category.

Reset only synthetic decoy event rows:

```sh
AHA_ENABLE_LOCAL_DEMO_CLI=1 .venv/bin/python -m app.demo decoy reset
```

This deletes only rows in `demo_decoy_events` where `simulation_mode='SIMULATED'`. It preserves targets, assessment observations, remediation runs, and the audit chain; the reset itself is recorded in the audit chain. Refresh the dashboard to see the empty state.

## G. Inspect audit evidence

Open **Audit & evidence**. The page fetches `GET /api/audit/events`, requires the separate `OIDC_AUDIT_READ_ROLE`, and shows the chain verification result plus stored events. `VALID` means the local SQLite chain matches its stored sequence and digests; it is not independent immutability, external checkpointing, or proof of assessment provenance. Remediation helper events are persisted in the sandbox run JSON and the Controller adds a `sandbox.remediation_run_recorded` chain entry.

## H. Stop and clean up

- Stop Controller and Vite with `Ctrl-C` in their terminals.
- The Go runner removes its temporary OpenSSH fixture, replay files, local audit JSONL, and ephemeral signing material at process exit.
- Use the decoy reset command above if synthetic rows should be cleared.
- Remediation run rows and audit entries remain as evidence. Do not delete `hardening.db` to reset a demo; that would remove unrelated project data.
- Remove `frontend/.env.local` after the session if it contains a development token.

## Validation commands

```sh
cd /Users/jusujan/Projects/autonomous-hardening-agent/agent
go test -count=1 ./...
go vet ./...

cd /Users/jusujan/Projects/autonomous-hardening-agent/controller
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/python -m compileall -q app tests
.venv/bin/python -m tabnanny app tests

cd /Users/jusujan/Projects/autonomous-hardening-agent/frontend
npm run check
npm test
npm run build
```

For the detailed fixture and event scenarios, see [the integrated sandbox matrix](../test-matrix/INTEGRATED_SANDBOX_V1.md).
