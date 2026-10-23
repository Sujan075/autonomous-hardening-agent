# SIH25237 Project Status

**Status date:** 2026-10-23

**Repository snapshot:** branch `infothon/rapid-integration`, based on pushed commit `571e886775e4c6721e8f17b397cbc61226f0b384` (`feat(security): add isolated approval binding verifier`). This checkpoint adds a typed Controller binding/provenance module and its tests; the base commit includes the isolated Go verifier and v1 contracts.
**Status vocabulary:** NOT STARTED · IN PROGRESS · IMPLEMENTED · UNIT-TESTED · INTEGRATION-TESTED · LIVE-VERIFIED · BLOCKED

This is the repository-backed status record for the full SIH25237 Autonomous Multi-Platform Security Hardening Agent project. Statuses refer only to the named scope and evidence level. A file, mock, unit test, build, or successful Ubuntu demonstration does not by itself establish integration, security readiness, or support on another platform. “BLOCKED” means work cannot safely advance until the stated dependency or evidence is resolved; it does not mean the overall project is abandoned.

## Executive status

The repository contains an early Ubuntu vertical slice: a Go target agent, a FastAPI Controller, a shared assessment envelope, a four-control Ubuntu SSH catalog, fail-closed assessment dispatch and planning, and a local SSH-tunnel path for read-only status, assessment, and plan requests. The only actual live target evidenced here is Ubuntu 24.04.5 ARM64. On V8, the live status, assessment, and plan requests succeeded; all four catalogued SSH findings passed and the plan was READY with zero actions.

The project is **not a complete hardening lifecycle**. The agent has guarded execution, state capture, verification, and rollback code with unit tests, but no live privileged execution or rollback has been tested. Focused handler tests cover method, token, approval/action, and JSON rejection paths and assert rejected requests do not invoke executor operations. The caller-provided `approved` boolean is not authenticated human approval. A standalone, feature-off approval-envelope verifier is implemented and unit-tested; it is disconnected from handlers and does not authorize execution. The detailed trust contract remains unimplemented end to end and is not security-reviewed or production-approved. Agent identity/enrollment, authenticated transport, replay protection, trusted approval issuance, and tamper-evident audit remain unimplemented. CentOS Stream is detected but deliberately has no assessment adapter or controls; the other named platform adapters are not established. The remediation-validation sandbox, separate Cowrie/OpenCanary decoy sandbox, event pipeline, audit/evidence history, full dashboard/reports, and broad integration/security test coverage remain outstanding.

No percentage complete, CI status, or total passing-test count is asserted in this tracker.

## Verified working slice

| Area | Current status | Evidence and limits |
|---|---|---|
| Agent build and placement | LIVE-VERIFIED | V5/V6/V7/V8 test candidates were launched on separate localhost ports. V7 and V8 were directly tested and tested through separate Controller instances. V7 candidate was built for Linux ARM64 and its binary checksum was verified on the Ubuntu VM. These are conversation-verified facts; this tracker does not claim a fresh rebuild or independent checksum re-run. |
| Ubuntu target | LIVE-VERIFIED | Ubuntu 24.04.5 ARM64 test VM is the only live platform environment evidenced. |
| Agent discovery | IMPLEMENTED | `/discovery` in `agent/cmd/agent/main.go` reports hostname, runtime OS/architecture, OS version, kernel, and primary IP. A live discovery result is not included in the verified endpoint evidence below. |
| Assessment contract and Ubuntu controls | LIVE-VERIFIED | Shared `platform`/`findings` envelope and four controls: 5.1.19–5.1.22. V8 live assessment returned HTTP 200 and four PASS findings through the Controller. Catalog mapping is corroborated by a secondary rendering; the official benchmark PDF was not directly verified, and formal ARM64 benchmark applicability is unconfirmed. |
| Planning | LIVE-VERIFIED | V8 live plan returned HTTP 200, READY, zero actions for a compliant target. Planner blocks incomplete/unknown/unsupported assessment input in automated tests. |
| Controller read-only connectivity | LIVE-VERIFIED | Controller status, assessment, and plan proxies were tested against the Ubuntu VM through a localhost SSH tunnel. For V8, each endpoint returned HTTP 200. This validates the tunnel/proxy path used in that session, not production network security or enrollment. |
| Remediation lifecycle | UNIT-TESTED | Guarded root-login remediation code includes explicit approval, state capture, validation, verification, and recovery/rollback logic with unit tests. No live privileged execution or live rollback was invoked or tested. |
| Transient SSH assessment issue | UNCONFIRMED | A `/run/sshd` assessment error occurred once and did not reproduce. Cause and preventive handling remain unconfirmed. |

### Live endpoint result (V8)

- Controller address during the verified session: `127.0.0.1:8001`.
- Target ID: `8865f49b-d545-4a8a-8511-766eaedea892`.
- SSH tunnel path: Mac `127.0.0.1:19000` forwarded to VM `127.0.0.1:9000`; the Ubuntu agent listens on loopback.
- `GET /api/targets/{target_id}/agent-status`: HTTP 200, `reachable=true`, `agent_id=agent-dev`, `status=online` (verified baseline).
- `GET /api/targets/{target_id}/assessment`: HTTP 200, four SSH findings PASS.
- `GET /api/targets/{target_id}/plan`: HTTP 200, READY, zero actions.
- No `/execute` or `/rollback` live request was made.

## Platform-by-platform matrix

| Platform / boundary | Status | Implemented scope | Evidence, limits, and remaining work |
|---|---|---|---|
| Ubuntu | LIVE-VERIFIED | Linux platform detection and dispatch; evaluator only runs inside the current catalog scope; four SSH controls; assessment and fail-closed plan; Controller read-only proxies. | Live-tested only on Ubuntu 24.04.5 ARM64. Catalog scope is narrow. Benchmark mapping has secondary-source corroboration; direct official-PDF verification and formal ARM64 applicability remain unconfirmed. No live execution/rollback. |
| CentOS Stream | IN PROGRESS | Platform detector recognizes CentOS Stream and returns an explicit UNKNOWN/error assessment; planning does not treat it as compliant or applicable. | Detection/dispatch behavior is unit-tested. No CentOS Stream VM, fixture from a real installation, control catalog, or read-only SSH adapter is established. Do not claim CentOS support. |
| Windows | NOT STARTED | No Windows-specific detector, catalog, adapter, or execution implementation established. | Requires Windows-specific control/applicability definitions, evidence collection, safe execution/recovery design, and Windows integration scenarios. |
| Docker | NOT STARTED | No container discovery, image/runtime adapter, catalog, or isolation model established. | Define host versus container scope, image/runtime assessment, safe change boundary, and container-specific verification before claiming support. |
| AWS guest systems | NOT STARTED | No guest OS adapter or AWS guest integration established. | Per-guest operating-system support must be scoped independently and must not be inferred from AWS account access. |
| AWS control plane | NOT STARTED | No control-plane adapter established. It is a separately scoped subsystem, not an extension of guest OS remediation. | Requires separate identity, least-privilege authorization, policy catalog, API evidence, approval, change controls, and recovery semantics. |
| ARM64 edge | IN PROGRESS | ARM64 Linux build and runtime were demonstrated on the Ubuntu VM; V7 artifact checksum was verified on that VM. | This is not a separate edge adapter or proof across edge devices. Device discovery, supported OS/device matrix, connectivity, resource constraints, and on-device integration tests remain. |

Unsupported platforms, versions, and control sets must remain explicit and fail closed. An unknown assessment is not NOT_APPLICABLE and is not a passing result.

## Component and workstream matrix

| Workstream | Status | Repository-backed state and open work |
|---|---|---|
| Shared Go agent and Controller | IN PROGRESS | Go agent under `agent/`; FastAPI Controller under `controller/`. Read-only status/assessment/plan proxy path exists. Shared, versioned cross-platform protocol and lifecycle orchestration are not complete. |
| Platform detection and dispatch | IMPLEMENTED | `agent/internal/assessment/platform.go` dispatches Ubuntu assessment only for its current supported identity; CentOS Stream and other unknown cases return UNKNOWN. Detection unit tests exist. Only Ubuntu has an evaluator. |
| Control catalog | IN PROGRESS | `agent/internal/catalog/catalog.go` contains four Ubuntu SSH controls only. No verified CentOS/Windows/Docker/AWS/edge control sets. |
| Policies and applicability | IN PROGRESS | Ubuntu scope, evidence expectations, severity, remediation metadata, and verification expectations are represented. Catalog benchmark mapping is secondary-source corroborated; official PDF verification and formal ARM64 benchmark applicability are unconfirmed. Policy versioning, profiles, broader platform applicability, and applicability governance remain. |
| Discovery | IMPLEMENTED | Agent `/discovery` reports local system information; Controller target records include platform/address fields. Cross-platform discovery, inventory lifecycle, authentication, and live discovery evidence are incomplete. |
| Assessment and evidence | LIVE-VERIFIED | Ubuntu assessment and finding evidence are exercised live through V8 and unit-tested. Shared contract includes applicability, UNKNOWN, evidence/source, and normalized errors. Evidence provenance/history and all non-Ubuntu assessors remain. |
| Risk, planning, and approval | LIVE-VERIFIED | Ubuntu planner validates complete findings and emits a READY empty plan for the compliant live target. Existing failing root-login case yields an approval-required action in unit tests. Cross-platform risk policy and Controller approval workflow are incomplete. |
| Trust and authorization design | IN PROGRESS | `docs/SECURITY_MODEL.md` contains the end-to-end trust contract, threat model, acceptance matrix, and phased gates. A separate Go approval-envelope verifier is implemented and package-tested, but it is not integrated with the Controller, handlers, executor, identity/enrollment, replay storage, or audit. No end-to-end trust or production security is claimed. |
| Isolated approval-envelope verifier and binding contracts | UNIT-TESTED | `agent/internal/approval` uses pinned jwx/v4 v4.5.0 and ES256 only. Its feature-off verifier validates explicit issuer/audience/agent/target/binding-generation/operation/action/policy/catalog context, expected `kid`/type, claims/signature/time; execute envelopes compare expected plan/evidence digests, rollback envelopes compare an expected recovery-manifest digest. Deterministic `assessment-evidence/v1`, `plan-binding/v1`, and `recovery-manifest/v1` contracts preserve `action-digest-v1`. Go tests exercise binding mutation and corruption behavior; the Python test independently reconstructs and checks the shared exact-byte/digest golden vectors. This is encoding and isolated-verifier evidence only: no approval issuer, authoritative provenance workflow, human-role authorization, replay consumption, audit integration, handler wiring, or execution authorization exists. |
| Controller typed binding and provenance module | UNIT-TESTED | `controller/app/approvals/bindings.py` implements production Python canonicalization/digests for the shared v1 action, assessment evidence, plan, and recovery contracts; it validates typed inputs, checks evidence freshness and target/catalog/generation consistency, and requires Controller target context for recovery-manifest identity checks. It rejects agent payload identity/digest extras. Authenticated-context validation requires a future external provenance-verifier callback; provenance labels/references alone do not pass that gate. Tests exercise Go golden vectors, binding mutations, malformed/oversized/stale/replaced/mismatched inputs, and route disconnection. This module does not authenticate assessment provenance, provide a trusted provenance service, persist immutable records, or authorize dispatch; the current Target model has no agent identity or binding generation. |
| State capture | UNIT-TESTED | Executor captures file state, digest, permissions, and execution state with tests. Durable multi-target evidence retention and live operation are not established. |
| Guarded execution | UNIT-TESTED | Agent `/execute` enforces POST, configured bearer token, `approved: true`, one action ID, valid single-value JSON, and tests rejected requests make zero executor calls. The boolean is caller asserted, not authenticated human approval. No live privileged action was invoked. Authentication/approval design and Controller-to-execution integration remain incomplete; see `docs/SECURITY_MODEL.md`. |
| Independent verification | UNIT-TESTED | Agent code rereads effective SSH configuration after its supported change and compares the result. No live remediation verification has been performed; independent verifier architecture is not established. |
| Rollback and recovery | UNIT-TESTED | Recovery state validation and file restoration/reload/verification logic have unit tests. Live rollback has not been tested; broader recovery and crash/interruption cases remain. |
| Secure identity and enrollment | NOT STARTED | No complete secure agent identity issuance, enrollment, rotation, revocation, or device trust lifecycle is established. `agent-dev` is development identity evidence, not production enrollment. Details and gates are in `docs/SECURITY_MODEL.md`. |
| Transport security and authorization | IN PROGRESS | Agent HTTP is plaintext and defaults to loopback; the lab path used SSH local forwarding. Agent execution has a shared bearer-token guard, but no token is configured by this task. The caller-supplied approval boolean is not trusted approval. A complete TLS/mTLS deployment, certificate lifecycle, Controller authorization model, threat review, and security acceptance are not established. Sample Controller config has `MTLS_ENABLED=false`; that setting alone does not establish mTLS support. Do not infer production security from the tunnel demo. |
| Remediation-validation sandbox | NOT STARTED | No isolated apply/verify/recovery validation sandbox is established. Must remain separate from real target execution and include resettable fixtures and safety boundaries. |
| Attacker/decoy sandbox | NOT STARTED | No Cowrie/OpenCanary decoy deployment or isolation is established. This sandbox is a separate environment and threat surface from remediation validation. |
| Event collection and normalization | NOT STARTED | No end-to-end event ingestion/normalization implementation is established. |
| Correlation and alerting | NOT STARTED | No event correlation, detection rules, alert lifecycle, or cross-source correlation is established. |
| Audit and evidence history | NOT STARTED | No complete tamper-evident audit/evidence history is established. Local executor recovery snapshots are not a project audit trail. |
| Dashboard and reports | NOT STARTED | No complete dashboard or reporting interface is established. The root README describes a desired Web Dashboard, not an implemented one. |
| Test infrastructure | IN PROGRESS | Go unit-test suites and Controller unittest tests exist. A shared scenario harness, platform runners/fixtures, integration/security suites, and CI evidence are not established. |
| Setup, operations, demo, deployment | IN PROGRESS | `agent/DEPLOYMENT.md` documents a limited Ubuntu setup and read-only SSH assessment permission. Repeatable secure multi-platform setup, operational runbooks, reproducible demo, and production deployment are not complete. |

## Evidence ledger

Evidence status reflects what has actually been reported or inspected. No CI run ID or current CI result is known.

| ID | Evidence | Level | Result and boundary |
|---|---|---|---|
| E-01 | Pushed baseline `571e886775e4c6721e8f17b397cbc61226f0b384` on `infothon/rapid-integration` | Repository | Starting HEAD for this checkpoint. The baseline includes the isolated Go verifier and canonical bindings; E-17 records the Controller Python implementation and its test evidence in this checkpoint. |
| E-02 | V5/V6/V7/V8 candidates launched on separate localhost ports | Direct test-session report | Candidate separation reported; this is not a claim that all four passed the same tests. |
| E-03 | V7 Linux ARM64 build and checksum checked on Ubuntu 24.04.5 ARM64 VM | Artifact/live-target report | V7 checksum verification reported. No hash value/run transcript is recorded here. |
| E-04 | V7 and V8 direct tests and separate Controller instances | Direct test-session report | Reported verified; exact individual command transcripts are not retained in this tracker. |
| E-05 | V8 Controller read-only status/assessment/plan results | LIVE-VERIFIED | HTTP 200 for all three. Four controls PASS; plan READY with zero actions. SSH tunnel used. |
| E-06 | Go test suite after platform-dispatch change | Codex-reported automated check | `cd agent && go test -count=1 ./...` reported passed. This is a historical report, not a new run or CI result. |
| E-07 | Go vet after platform-dispatch change | Codex-reported automated check | `cd agent && go vet ./...` reported passed. Historical report; not a new run or CI result. |
| E-08 | Formatting and whitespace checks after platform-dispatch change | Codex-reported automated check | `cd agent && gofmt -d internal/assessment/platform.go internal/assessment/platform_test.go internal/assessment/http.go internal/planner/http.go internal/planner/ssh_test.go` reported no differences; `git diff --check` reported passed. Historical reports. |
| E-09 | Controller unit tests | Codex-reported automated check | Last reported result: 10 tests passed. Exact command and run identifier are not retained; no current CI status is known. |
| E-10 | Ubuntu benchmark provenance | Source review | CIS Ubuntu 24.04 LTS Benchmark v2.0.0 identity and four mapping titles have secondary-source corroboration. Official benchmark PDF was not directly inspected; formal Ubuntu 24.04.5 ARM64 benchmark applicability remains unconfirmed. |
| E-11 | Executor/state/recovery and HTTP handler tests | Repository/test report | Existing injected-operation tests cover state/recovery. New handler tests cover rejected Execute and Rollback requests with zero operation calls, including unset token behavior through the exported handlers. Current Go suite and vet passed; exact commands are in E-13. No live privileged execution or rollback was invoked. |
| E-12 | `/run/sshd` assessment failure | Live observation | Occurred once, did not reproduce; root cause unconfirmed. |
| E-13 | Current agent Go checks and repository diff validation | Automated checks, 2026-10-23 | From `agent/`, `go test -count=1 ./...` passed and `go vet ./...` passed. `gofmt -d internal/executor/http.go internal/executor/http_test.go` produced no output. From repository root, `git diff --check` passed. These checks do not constitute live execution or security acceptance. |
| E-14 | End-to-end trust and authorization design | Design documentation, 2026-10-23 | `docs/SECURITY_MODEL.md` contains the proposed trust contract, threat model, acceptance matrix, and phased plan originally based on source snapshot `ae8c2bc`; the security design remains prospective, not implementation or security-review evidence. |
| E-15 | Isolated approval-envelope verifier and digest contract | Automated checks, 2026-10-23 | `agent/internal/approval` tests use ephemeral P-256 keys and cover signature/algorithm/key selection, claim and context validation, time bounds, and action-digest mutation. Go and Python independently match the shared v1 canonical-byte and SHA-256 vector. Full agent Go suite, Go vet, 11 Controller Python tests, changed-Go-file `gofmt -d`, and root `git diff --check` passed. The verifier is not integrated and this is not execution/security acceptance evidence. |
| E-16 | Composite approval binding contracts | Automated checks, 2026-10-23 | Commit `571e886775e4c6721e8f17b397cbc61226f0b384` contains deterministic `assessment-evidence/v1`, `plan-binding/v1`, and `recovery-manifest/v1`, preserves `action-digest-v1`, recomputes expected operation-specific digests from caller-supplied objects in the isolated Go verifier, and supplies shared Go/Python exact-byte vectors plus Go mutation/corruption tests. The recorded Go, Python, formatting, and diff checks passed at that checkpoint. No Controller issuance, runtime integration, privileged action, or live target test was claimed. |
| E-17 | Controller typed binding/provenance module | Automated checks, 2026-10-23 | This checkpoint adds isolated Python production implementations for the shared action/evidence/plan/recovery v1 digests and typed context/provenance validation. `cd agent && go test -count=1 ./...` passed; `cd agent && go vet ./...` passed; `cd controller && .venv/bin/python -m unittest discover -s tests` passed (22 tests; Starlette/httpx deprecation warning); `cd controller && .venv/bin/python -m tabnanny app/approvals/bindings.py tests/test_approval_digest_contract.py` passed with no output; root `git diff --check` passed. No Go files changed, so `gofmt` was not applicable. The tests confirm vector parity and tested fail-closed metadata/input cases, not authenticated provenance, integration, dispatch authorization, or production security. No live privileged action or target test was performed. |

## Test matrix

Keep these evidence levels separate: **defined** means a test/scenario is specified; **automated** means test code exists; **executed** means it was run; **passed** means its result was successful; **live-verified** means the behavior was observed on a real target/environment. A higher-level claim requires its own evidence.

| Test scope | Defined target | Automated in repository | Executed | Passed | Live-verified |
|---|---|---|---|---|---|
| Ubuntu assessment/catalog/planner | Yes | Yes: Go package tests | Go suite reported executed after dispatch change; see E-06 | Passed per E-06 | Yes, Ubuntu 24.04.5 ARM64, V8 four PASS and READY/zero-actions plan |
| Ubuntu executor/state/recovery and handler authorization | Yes | Yes: Go unit tests with injected operations/files; focused HTTP handler rejection tests | Current requested Go suite and vet run recorded for this snapshot; no live execution/rollback | See current E-13 result | No live execution or rollback |
| Platform detection/dispatch | Yes | Yes: injected OS-release and command runner tests | Included in reported Go suite; see E-06 | Suite passed per E-06 | Ubuntu dispatch live path observed; CentOS behavior not live-tested |
| CentOS Stream assessment | Not yet: requirements/control set absent | Detection/fail-closed dispatch unit scenarios only | Included in reported Go suite | Suite passed per E-06 | No CentOS Stream environment; no support claim |
| Windows, Docker, AWS guest, AWS control plane, ARM64 edge variants | Not yet | No representative platform suites established | No platform-specific runs established | No platform-specific passing results established | No; Ubuntu VM only |
| Controller status/assessment/plan proxies | Yes | Yes: Controller unittest suite | Yes: last reported run; exact command/run ID unavailable | Yes: 10 passed per E-09 | Yes, V8 over SSH tunnel |
| Execute/rollback HTTP rejection paths | Yes | Yes: focused Go handler tests; rejected calls assert zero executor invocations | Current requested Go suite recorded at E-13 | See current E-13 result | No live execution or rollback |
| Approval-envelope verifier and binding encodings | Yes | Yes: isolated Go verifier/binding tests plus Python shared golden-vector reconstruction | Full current suites recorded at E-16 | Passed per E-16 | No live or handler-integrated verification |
| Integration across lifecycle | Target must be defined | Partial endpoint integration exists; full lifecycle suite not established | Partial V7/V8 Controller sessions reported | No full lifecycle pass reported | Assessment/plan path only; no execute/rollback |
| Security, identity, transport, authorization, failure injection | Target must be defined | Partial authorization/executor/failure unit tests; full security suite absent | No complete security run reported | No complete security pass reported | No security acceptance review reported |
| Remediation-validation sandbox | Not yet | No | No | No | No |
| Cowrie/OpenCanary decoy sandbox and telemetry pipeline | Not yet | No | No | No | No |
| Broad project scenario target | Yes as a planning target: approximately 90 platform-specific scenarios plus common/integration/security/failure tests | Not established at that target | No completed scenario count reported | No completed scenario pass count reported | No |

The approximately 90 platform-specific scenarios are a target, not a current test count. Do not derive completed coverage from files or test names. CI configuration/status was not established by this inspection.

## Known risks and open questions

- **Control authority:** Ubuntu mappings are corroborated by a public secondary rendering, not directly verified against the official benchmark PDF. Confirm source/version/profile and control applicability before representing formal compliance.
- **Ubuntu scope:** Current catalog scope names Ubuntu 24.04.5 ARM64. Determine version normalization and applicability policy for other point releases/architectures before broadening it.
- **CentOS Stream:** Detector-only support state. Decide and verify authoritative control definitions, supported Stream releases, evidence commands, applicability, and safe adapter behavior before adding catalog entries or claiming support.
- **Execution safety:** Unit tests do not establish live safe execution. Live guarded execution and rollback need a dedicated, explicitly approved lab procedure after security review; they have not been performed.
- **Identity and transport:** Lab SSH tunneling is not a production trust design. Define enrollment, key/certificate issuance and rotation, TLS/mTLS verification, authorization, revocation, and threat model.
- **Agent exposure:** Preserve loopback binding for the lab agent unless a reviewed secure transport design explicitly changes it. Never treat tunnel connectivity as authorization.
- **Assessment transient:** `/run/sshd` failure cause remains unknown despite non-reproduction.
- **Controller persistence:** Current database/schema is prototype scope; audit retention, tenant isolation, evidence integrity, migrations, and access control require design and testing.
- **AWS boundary:** Guest OS hardening and AWS control-plane changes require separate adapters, permissions, policies, approvals, evidence, and recovery plans.
- **Sandbox isolation:** Remediation validation and attacker/decoy workloads must be separate isolated environments with explicit reset and containment controls.
- **Telemetry privacy and retention:** Collection, normalization, correlation, audit integrity, retention, and dashboard access policies are not yet defined end-to-end.
- **Live evidence traceability:** Preserve exact commands, artifact hashes, target identity/version, timestamps, and results for future test sessions; prior reports do not include all run transcripts or a CI run ID.

## Dependency-ordered roadmap

1. **Freeze contracts and evidence rules.** Version the shared agent/controller contracts, normalized error semantics, control/catalog provenance, applicability, and evidence/audit requirements. Keep unsupported platforms UNKNOWN and planner-blocked.
2. **Complete trust and authorization design.** Define agent identity/enrollment/rotation/revocation, authenticated transport with normal certificate verification, Controller-to-agent authorization, execution approval, audit actors, and threat model before broad remote operation.
3. **Build reusable test and lab infrastructure.** Add deterministic platform fixtures/runners and integration harness, capture artifacts and commands, define failure/security scenarios, and keep the approximate 90 platform-specific scenarios plus common, integration, security, and failure scenarios as targets.
4. **Establish platform policy and applicability.** Verify authoritative sources and supported versions/profiles per platform. Define platform/control-set applicability before implementing an evaluator. Keep AWS control-plane policy separate from guest policy.
5. **Implement and validate platform adapters.** Extend one platform at a time (CentOS Stream, Windows, Docker, AWS guests, separate AWS control plane, and ARM64 edge). Add evidence, version gating, failure behavior, unit and integration scenarios; require a real representative environment before claiming live support.
6. **Complete Controller orchestration and approvals.** Add authenticated enrollment/target lifecycle, policy selection, reviewable risk decisions, user approval records, and read-only operation visibility across supported adapters.
7. **Validate guarded remediation lifecycle.** In isolated disposable targets, verify state capture, authorization, bounded execution, independent post-change verification, audit evidence, interruption/failure recovery, and rollback. Only then evaluate any broader enablement.
8. **Build remediation-validation sandbox.** Isolate disposable target snapshots, execute only approved test changes, verify outcomes, and restore/reset deterministically. Keep it separate from production targets and from the decoy sandbox.
9. **Build attacker/decoy sandbox separately.** Deploy and contain Cowrie/OpenCanary, define safe interaction boundaries and data handling, and verify the decoy environment cannot reach managed targets or privileged control paths.
10. **Deliver telemetry, audit, and operator views.** Implement event collection/normalization/correlation, tamper-evident audit/evidence history, alert lifecycle, dashboard/reports, and access/retention policies; validate end-to-end with sandbox events.
11. **Operationalize and demonstrate.** Document setup, trust bootstrap, platform prerequisites, day-two operations, recovery, upgrade/rollback, observability, deployment, and a reproducible demo. Complete acceptance gates per supported platform and overall project.

## Acceptance criteria for status advancement

- **IMPLEMENTED:** The behavior is wired into the running product path, has explicit scope and failure semantics, and does not rely on a placeholder, mock-only path, or file existence. Unsupported cases fail closed. This alone is not test completion.
- **UNIT-TESTED:** Focused automated tests exercise success, invalid/unknown inputs, command/API failures, applicability, evidence, and relevant security boundaries. The exact command and result are recorded. Mock tests do not prove platform behavior.
- **INTEGRATION-TESTED:** Real components are exercised together in a documented environment with captured versions, setup, commands, and results. A mock-only test does not qualify.
- **LIVE-VERIFIED:** The named supported platform/version/architecture is tested on a real representative target; artifact identity/checksum, target identity, commands, timestamps, endpoint/output, and outcome are retained. Assessment, execution, verification, and rollback are separately evidenced; testing one does not imply the others.
- **BLOCKED:** State the specific missing dependency/evidence and the action needed to unblock. Do not hide blocked platform slices under a shared project-level IMPLEMENTED status.
- **Platform supported:** Requires an explicitly scoped adapter and control set with verified source/provenance and applicability, correct discovery/dispatch, evidence-bearing assessment, fail-closed planning, and platform-specific automated tests. Live support additionally requires representative live verification. Unsupported/unknown controls never count as compliant or NOT_APPLICABLE without an explicit rule.
- **Remediation supported:** Requires policy-bounded action, authorization and approval, pre-change state capture, safe execution, independent verification, failure recovery/rollback, tamper-evident audit evidence, unit/integration/security coverage, and a documented operational procedure. Live privileged execution and rollback require their own live evidence.
- **Project complete:** Every agreed platform/system workstream in this tracker has an explicit disposition and accepted evidence; shared lifecycle, security, both separate sandboxes, telemetry/audit/dashboard, setup/operations/demo/deployment, and target test matrix meet their acceptance criteria. A successful Ubuntu assessment/plan slice is not overall completion.
