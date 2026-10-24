# Integrated sandbox and dashboard acceptance matrix v1

**Revision:** local feature branch `feat/centos-stream9-assessment` (2026-10-24)

This matrix covers the safe process/filesystem sandbox and the independent synthetic decoy simulator. The remediation fixture exercises the real planner, ES256 verifier, durable replay reservation, privileged-helper contract, existing fixed SSH executor, actual OpenSSH `sshd -t`/`sshd -T`, independent verification, and signed rollback. Temporary directories are created by the sandbox itself; tests do not accept caller-supplied paths or commands. No live target is changed.

`Fixture/sandbox tested` means actual local OpenSSH parsing and/or a temporary SQLite database. `Integration tested` means Python CLI → Go runner → fixture and persisted Controller API behavior. No browser-driven end-to-end run was performed. Synthetic events are never represented as real attacks.

## Remediation lifecycle

| ID | Scenario | Expected / actual result | Automated evidence | Level | Result |
|---|---|---|---|---|---|
| RSB-01 | Compliant fixture | `COMPLIANT`, four PASS findings, no plan action or approval audit event | `TestFixedSandboxScenariosExerciseRealOpenSSHAndRecovery/compliant_no-op` | Fixture/sandbox | PASS |
| RSB-02 | One supported noncompliant control | Planner returns one fixed Ubuntu root-login action | `TestFixedSandboxScenariosExerciseRealOpenSSHAndRecovery/noncompliant_execute_independent_verify_and_signed_rollback` | Fixture/sandbox | PASS |
| RSB-03 | Test-only approval | ES256 signature and target/action/plan/evidence/policy/catalog context pass the real verifier | Same roundtrip test; `Run` result labels issuer/key/subject test-only | Fixture/sandbox | PASS |
| RSB-04 | Fixed execution | Helper invokes only `ACT-SSH-5.1.20`; effective config becomes `PermitRootLogin=no` | Same roundtrip test; Controller wrapper test | Fixture/sandbox + integration | PASS |
| RSB-05 | Independent post-change check | A second `sshd -T -f` call confirms `no` | Same roundtrip test asserts source `independent sshd -T -f temporary-config` | Fixture/sandbox | PASS |
| RSB-06 | Separately approved rollback | Rollback token binds the captured recovery manifest and unique JTI | Same roundtrip test; four `action.started`/`action.finished` records across execute/rollback | Fixture/sandbox | PASS |
| RSB-07 | Exact prior state restoration | Independent post-rollback `sshd -T` equals captured effective value `prohibit-password` | Same roundtrip test | Fixture/sandbox | PASS |
| RSB-08 | Earlier `00-site-policy.conf` takes precedence | Candidate does not become effective; action is not reported verified | `TestFixedSandboxScenariosExerciseRealOpenSSHAndRecovery/first-value_precedence_conflict_and_automatic_recovery` | Fixture/sandbox | PASS |
| RSB-09 | Verification failure recovery | Executor removes candidate drop-in, restores prior `yes`, and independently verifies it | Same precedence-conflict test | Fixture/sandbox | PASS |
| RSB-10 | Approval expiry and not-before boundary | Expired/future approvals rejected before operation | `TestComposedHelperRejectsMismatchedAndInvalidApprovalScenarios/{expired,not-yet-valid}` | Fixture/sandbox | PASS |
| RSB-11 | Approval issuer/audience/agent/target/binding mismatch | Each signed context mutation is rejected before operation | Same test: `issuer-mismatch`, `audience-mismatch`, `agent-mismatch`, `target-mismatch`, `binding-mismatch` | Fixture/sandbox | PASS |
| RSB-12 | Approval action/operation/digest/policy/catalog mismatch | Wrong operation/action/digest, plan, evidence, policy or catalog binding is rejected | Same test: operation, action, action-digest, plan, evidence, policy-version, catalog-version mismatch cases | Fixture/sandbox | PASS |
| RSB-13 | Missing/malformed token, missing or extra claim, bad signature, unknown key ID, request mismatch | All requests rejected; fixture remains unchanged | Same test: 23 named rejection subtests; operation count stays zero | Fixture/sandbox | PASS |
| RSB-14 | Replayed/duplicate execution request | Durable JTI reservation rejects the second call; operation runs once | `TestSandboxHelperRejectsReplayBeforeSecondOperation` | Fixture/sandbox | PASS |
| RSB-15 | Pre-operation audit failure | Helper does not invoke the executor when durable audit acknowledgment fails | `TestComposedHelperPreAuditFailurePreventsFixtureMutation` | Fixture/sandbox | PASS |
| RSB-16 | Missing evidence, UNKNOWN or ERROR finding | Planner returns BLOCKED and zero actions | `TestUncertainOrIncompleteSSHObservationBlocksPlan/{missing_evidence,unknown_finding,error_finding}` | Fixture/sandbox | PASS |
| RSB-17 | Unsupported CentOS action | CentOS stays `BLOCKED` with zero actions | `TestPlannerKeepsCentOSSandboxPlanBlocked`; existing planner suite | Unit | PASS |
| RSB-18 | Invalid lifecycle transition | Skipped and duplicate transitions rejected | `TestLifecycleMachineRejectsInvalidAndDuplicateTransitions` | Unit | PASS |
| RSB-19 | Temporary-tree reset | Fixture's owned directory is removed; second close is safe and closed fixture cannot be reused | `TestTemporarySSHFixtureOwnsOnlyTemporaryTreeAndCleansIt` | Fixture/sandbox | PASS |
| RSB-20 | Arbitrary fixture scenario/path/command | Unknown scenario rejected; API has no path or command parameter | `TestTemporarySSHFixtureRejectsUnknownScenario`; runner allowlist test | Unit | PASS |
| RSB-21 | Python-to-Go persistence boundary | Fixed CLI runs the actual Go lifecycle, validates sandbox labels, stores JSON and appends Controller audit | `DemoDataTests.test_python_controller_persists_actual_go_execute_verify_and_rollback_run` | Integration | PASS |

The existing executor matrix also retains partial-write, validation-command, service-reload, snapshot integrity, restore verification, and recovery-failure cases. Service reload is stubbed; those cases are not VM evidence. Approval-denial subtests exercise the composed helper/verifier against the real temporary OpenSSH fixture but intentionally do not mutate it.

## Decoy simulator

| ID | Scenario | Expected / actual result | Automated evidence | Level | Result |
|---|---|---|---|---|---|
| DEC-01 | Connection attempt sample | One timestamped `SIMULATED` record from an RFC 5737 address | `test_ten_decoy_event_scenarios_are_simulated_and_cannot_invoke_executor` subtest 1 | Unit / SQLite fixture | PASS |
| DEC-02 | Authentication probe sample | Simulated category and documentation-range classification retained | Same test, subtest 2 | Unit / SQLite fixture | PASS |
| DEC-03 | Path request sample | Simulated category is stored with correlation ID | Same test, subtest 3 | Unit / SQLite fixture | PASS |
| DEC-04 | Protocol banner probe sample | Simulated category is stored without network traffic | Same test, subtest 4 | Unit / SQLite fixture | PASS |
| DEC-05 | Repeated connection sample | Unique event/correlation IDs within a batch | Same test, subtest 5 | Unit / SQLite fixture | PASS |
| DEC-06 | Repeated authentication sample | Every row is marked `SIMULATED`; no credentials are collected | Same test, subtest 6 | Unit / SQLite fixture | PASS |
| DEC-07 | Invalid method sample | Outcome is only `simulated_event_recorded` | Same test, subtest 7 | Unit / SQLite fixture | PASS |
| DEC-08 | Repeated path sample | Category retrieval returns the recorded synthetic row | Same test, subtest 8 | Unit / SQLite fixture | PASS |
| DEC-09 | Repeated protocol sample | RFC 5737 classification is preserved | Same test, subtest 9 | Unit / SQLite fixture | PASS |
| DEC-10 | Third connection sample | Ten generated events have distinct correlations and no executor invocation | Same test, subtest 10; `subprocess.run` asserted not called | Unit / SQLite fixture | PASS |
| DEC-11 | Batch retrieval | `list_decoy_events` returns only stored batch entries | `test_decoy_batch_is_deterministic_simulated_and_retrievable` | Unit / SQLite fixture | PASS |
| DEC-12 | Reset scope | Reset deletes demo event rows only; target, remediation run and audit history remain | `test_reset_deletes_only_demo_events_and_keeps_project_records_and_audit` | Unit / SQLite fixture | PASS |
| DEC-13 | API disabled / role denied / role allowed | Explicit demo flag required; OIDC target-read role gates decoy/run GET; POST is absent | `test_demo_and_audit_apis_are_read_only_role_gated_and_feature_gated` | Controller API integration | PASS |
| DEC-14 | Dashboard category filter and empty state | UI filter is deterministic; missing category returns empty list | `frontend/tests/presentation.test.mjs` | UI contract | PASS |

No actual attacker traffic, listener, credential attempt, scan, or decoy service is implemented. The `loopback-decoy-simulator` identity describes simulator data; it is not a running host or service.

## Dashboard and API contract

| ID | Contract | Evidence | Level | Result |
|---|---|---|---|---|
| UI-01 | `ERROR` and `UNKNOWN` remain distinct; `BLOCKED`, `INDETERMINATE`, PASS and FAIL map separately | `frontend/tests/presentation.test.mjs` | Unit / UI contract | PASS |
| UI-02 | Loading, authorization, request error, empty, available and not-run states remain separate | Same test | Unit / UI contract | PASS |
| UI-03 | Sandbox and decoy pages consume Controller GET responses only; no hardcoded records | `getRemediationRuns`, `getDecoyEvents`; dashboard `npm run check` and build | API/type contract | PASS |
| UI-04 | Trusted policy decision and reported agent decision appear separately with identity and rationale | `getAssessment` requires `policy_evaluation`; type check/build | API/type contract | PASS |
| UI-05 | Target discovery route is read-only and protected by OIDC target-read authorization | `test_missing_oidc_configuration_denies_management_and_target_reads`; dashboard API validation/type check | Controller/API contract | PASS |
| UI-06 | Audit API verifies the chain and requires a separate audit-read role | `test_demo_and_audit_apis_are_read_only_role_gated_and_feature_gated` | Controller API integration | PASS |
| UI-07 | Browser/API end-to-end session with a deployed OIDC issuer | Not available in the local test setup | Browser integration | NOT RUN |

## Verification level summary

- **Unit tested:** planner fail-closed behavior, state-machine transitions, signing/binding rejection, decoy record service, and UI presentation contracts.
- **Fixture/sandbox tested:** successful `sshd -T` execution and rollback; first-value conflict and automatic recovery; generated-key cleanup; actual temporary SQLite storage.
- **Integration tested:** Go fixture lifecycle invoked by the Python CLI and persisted with the Controller audit chain; FastAPI reads persisted run/event/audit records under OIDC tests.
- **Live verified:** historical read-only Ubuntu and CentOS observations only, as recorded in their platform matrices. No sandbox run is live verification and no managed target was modified.

## Test commands

```sh
cd agent && go test -count=1 ./... && go vet ./...
cd controller && .venv/bin/python -m unittest discover -s tests -q
cd controller && .venv/bin/python -m compileall -q app tests && .venv/bin/python -m tabnanny app tests
cd frontend && npm run check && npm test && npm run build
git diff --check
```

The current full-suite results are recorded in [PROJECT_STATUS.md](../PROJECT_STATUS.md) and the main [judge runbook](../runbooks/INTEGRATED_DEMO.md).
