# CentOS Stream 9 ARM64 Assessment Adapter v1

This matrix separates unit coverage from a captured live read-only assessment. The live evidence bundle is for `AH-CENTOS-01` and records its identity, assessment findings, blocked plan, capture time and agent binary checksum. It does not establish broader operating-system hardening, formal benchmark compliance, or remediation support.

## Supported identity and evidence

Dispatch requires all of: Go runtime OS `linux`; `ID=centos`; `NAME=CentOS Stream`; `VERSION_ID=9`; `PRETTY_NAME=CentOS Stream 9`; and Go architecture `arm64` (the OS architecture commonly reported as `aarch64`). Any missing, malformed, inconsistent or out-of-scope identity returns UNKNOWN without invoking the evaluator.

The evaluator runs the fixed command `/usr/bin/sudo -n /usr/sbin/sshd -T`, reads effective configuration, and returns ERROR if a required directive is missing, duplicated, malformed, or the command fails. Findings use source `ssh.effective_config` and retain the setting name and observed value as evidence.

## Project-defined controls

| ID | Directive | Expected value | Severity |
|---|---|---:|---|
| CSTS9-SSH-001 | `PermitEmptyPasswords` | `no` | MEDIUM |
| CSTS9-SSH-002 | `PermitRootLogin` | `no` | HIGH |
| CSTS9-SSH-003 | `PermitUserEnvironment` | `no` | MEDIUM |
| CSTS9-SSH-004 | `UsePAM` | `yes` | MEDIUM |

These rules are a project-defined SSH baseline. No CentOS CIS control IDs, benchmark version, authoritative benchmark mapping, or formal compliance claim is assigned.

## Lifecycle acceptance matrix

`PASS` below means the named automated test passed at its stated evidence level. It does not promote isolated tests into Controller integration, sandbox execution, or live CentOS remediation. End-to-end actions that do not exist remain `NOT RUN`.

| # | Scenario | Expected result | Exact test or command | Level | Actual result / evidence | Status |
|---:|---|---|---|---|---|---|
| 1 | Exact CentOS Stream 9 ARM64 dispatch | Four CentOS findings; fixed evaluator called | `cd agent && go test ./internal/assessment -run TestAssessHostDispatchesExactCentOSStream9ARM64Identity -count=1` | Unit | Dispatch test passes; [platform_test.go](../../agent/internal/assessment/platform_test.go) | PASS |
| 2 | Unsupported or malformed OS identity | UNKNOWN; evaluator not called | `cd agent && go test ./internal/assessment -run 'TestAssessHostRejectsCentOSIdentityOutsideExactScope|TestAssessHostRejectsUnsupportedOrIncompleteIdentityBeforeCommands' -count=1` | Unit | Scope and malformed identity tests pass; [platform_test.go](../../agent/internal/assessment/platform_test.go) | PASS |
| 3 | Compliant four-control assessment | Four PASS findings with matching observed evidence | `cd agent && go test ./internal/assessment -run 'TestCentOSSSHControlsPassAndFailIndependently|TestCentOSMixedFindingsAreIndependent' -count=1` | Unit | Injected CentOS effective-config cases pass; [ssh_test.go](../../agent/internal/assessment/ssh_test.go) | PASS |
| 4 | Root-login finding | `PermitRootLogin=without-password` is FAIL against project value `no` | `cd agent && go test ./internal/assessment -run TestCentOSRootLoginWithoutPasswordFailsProjectBaseline -count=1` | Unit | Exact regression passes; same evidence file as row 3 | PASS |
| 5 | Missing, duplicate, malformed SSH evidence | ERROR, never PASS | `cd agent && go test ./internal/assessment -run 'TestCentOSSSHInvalidOutputAndCommandFailureNeverPass|TestAssessSSHControlsMissingOrMalformedOutputReturnsError' -count=1` | Unit | Injected parser/command failure cases pass; [ssh_test.go](../../agent/internal/assessment/ssh_test.go) | PASS |
| 6 | Policy evaluation rejects missing or unexpected controls | Reject the assessment; no compliant decision | `cd controller && .venv/bin/python -m unittest tests.test_assessment_policy_integration.AssessmentPolicyIntegrationTests.test_assessment_parameters_must_match_exact_ordered_policy_contract` | Unit / Controller fixture | Missing and unexpected findings are rejected against the exact policy control sequence | PASS |
| 7 | Policy evaluation rejects mismatched expected values | Reject exact assignment/assessment mismatch | `cd controller && .venv/bin/python -m unittest tests.test_assessment_policy_integration.AssessmentPolicyIntegrationTests.test_assessment_parameters_must_match_exact_ordered_policy_contract` | Unit / Controller fixture | Changed expected value and architecture are rejected | PASS |
| 8 | UNKNOWN/ERROR evidence cannot be compliant | INDETERMINATE, never COMPLIANT | `cd controller && .venv/bin/python -m unittest tests.test_assessment_policy_integration.AssessmentPolicyIntegrationTests.test_policy_evaluation_distinguishes_noncompliant_and_uncertain_findings` | Unit / Controller fixture | UNKNOWN maps to INDETERMINATE; generic policy fixture only, not reviewed CentOS policy | PASS |
| 9 | CentOS remediation planning pending safe execution boundary | BLOCKED with zero actions | `cd agent && go test ./internal/planner -run TestBuildAssessmentPlanAlwaysBlocksCentOSBaseline -count=1` | Unit | Test confirms CentOS remains BLOCKED with zero actions. No action is defined because the current executor requires root and the helper is an internal library, not a deployed privilege boundary. | PASS |
| 10 | Incomplete findings produce zero-action plan | BLOCKED with no actions | `cd agent && go test ./internal/planner -run TestBuildAssessmentPlanFailsClosedForIncompleteOrUncertainAssessments -count=1` | Unit | Fail-closed Ubuntu planner regression passes; CentOS is independently always blocked | PASS |
| 11 | Correct, unexpired, target-bound approval | Signed envelope accepted only for exact configured context | `cd agent && go test ./internal/approval ./internal/privhelper -run 'TestVerifyAcceptsValidEnvelope|TestHelperValidSignedRequestReachesOnlyInjectedFixedOperation' -count=1` | Unit | Verifier/helper acceptance is isolated; no Controller-to-agent approval path | PASS |
| 12 | Invalid signature, missing trust material, or reviewer role | Reject before operation | `cd agent && go test ./internal/approval ./internal/privhelper -run 'TestVerifyRejectsMalformedAndInvalidSignatures|TestNewVerifierRejectsNonAllowlistedAlgorithmsAndInvalidTrustConfig|TestHelperRejectsInvalidSignaturesExpiredAndMismatchedClaimsBeforeOperation' -count=1` | Unit | Cryptographic configuration/signature rejection passes; Controller reviewer authorization has separate tests | PASS |
| 13 | Expired or target-mismatched approval | Reject before operation | `cd agent && go test ./internal/approval ./internal/privhelper -run 'TestVerifyEnforcesTimeWindowAndClockSkew|TestHelperRejectsInvalidSignaturesExpiredAndMismatchedClaimsBeforeOperation' -count=1` | Unit | Expiry and context mismatch tests pass | PASS |
| 14 | Approval/evidence/plan digest mismatch | Reject mutated bindings | `cd agent && go test ./internal/approval ./internal/privhelper -run 'TestPlanBindingMutationsChangeDigest|TestHelperRecomputesBindingsFromConfiguredTypedContext' -count=1` | Unit | Binding mutations are rejected; no operational approval consumer | PASS |
| 15 | Single-use approval replay | Atomic replay reservation rejects reuse | `cd agent && go test ./internal/privhelper -run 'TestHelperReplayIsAtomicAcrossConcurrencyAndStoreRecreation|TestFileReplayStoreRejectsReplayConflictAndPersistsReservation' -count=1` | Unit | Replay primitive passes with test state; not wired to the running agent | PASS |
| 16 | Audit failure before mutation | Mutation callback is not invoked | `cd agent && go test ./internal/privhelper -run TestReplayPersistenceFailureAndPreOperationAuditFailurePreventMutation -count=1` | Unit | Injected audit failure blocks operation; no production sink is connected | PASS |
| 17 | Successful constrained action | Captured state plus independent effective-value verification | `cd agent && go test ./internal/executor -run TestApplyUsesRealSSHDValidationAndEffectiveConfigurationInTemporaryTree -count=1` | Sandbox | Real `sshd` checks use a temporary tree; executor is not enabled for CentOS | PASS |
| 18 | Syntax error or SSH precedence conflict | No false success; recover or expose recovery failure | `cd agent && go test ./internal/executor -run 'TestEarlierSSHDDirectiveWinsAndExecutorRecoversInsteadOfReportingSuccess|TestApplyFailuresAttemptAndVerifyRecovery' -count=1` | Sandbox / injected failure | Temporary `sshd` precedence and failure cases pass | PASS |
| 19 | Failed execution restores original state | Independently verify recovered effective value | `cd agent && go test ./internal/executor -run 'TestAutomaticRecoveryEffectiveStateMatchReportsVerifiedRecovery|TestSuccessfulRestorationVerifiesPriorContentAndExistence' -count=1` | Unit / sandbox | Recovery and file state are verified in tests; no live write | PASS |
| 20 | Failed recovery disposition | Recovery-required/incomplete; never successful rollback | `cd agent && go test ./internal/privhelper ./internal/executor -run 'TestOperationFailureNeverReturnsSuccessAndRetainsRecoveryRequiredStatus|TestRestoreOrVerificationFailureNeverReportsSuccessfulRollback|TestPostOperationAuditFailureIsExplicitlyIncompleteAndCannotBeRetried' -count=1` | Unit | Failure states are explicit in isolated tests; audit/executor workflow is not connected end to end | PASS |

### Suite result at this revision

- Controller policy fixture: the CentOS Stream 9 ARM64 `PROJECT_DEFINED_BASELINE` definition was registered, reviewed through the existing test-only trust pin, assigned to the test target's active binding generation, and evaluated through the assessment route. The fixture confirms the exact four controls and evidence setting/source contract and records the policy review and assessment audit events. It does not install a production trust pin or policy. The trusted Controller decision is `INDETERMINATE`; the internally consistent agent result is separately reported as `reported_decision=NON_COMPLIANT`. Channel identity alone does not prove assessment collection provenance.
- CentOS remediation planning, operational approval dispatch, CentOS execution, independent post-change verification, and recovery remain BLOCKED/NOT RUN. The repo has no supported CentOS action and no deployed OS-level helper boundary. No disposable CentOS VM with verified snapshot/recovery was available, and the captured `AH-CENTOS-01` was not modified.

- Go: `cd agent && go test -count=1 ./...` and `go vet ./...` passed at the current continuation revision. The run includes the fixed temporary OpenSSH sandbox and agent-route denial tests. It does not exercise CentOS remediation.
- Controller: `cd controller && .venv/bin/python -m unittest discover -s tests -q` passed all 119 tests. Its local process-level mTLS tests use temporary certificates and disposable state; they do not exercise CentOS remediation or approval dispatch.
- CentOS ARM64 build: `GOOS=linux GOARCH=arm64 go build -o /tmp/aha-centos-stream9-arm64 ./cmd/agent` produced an ELF 64-bit ARM aarch64 Linux executable. New artifact SHA-256: `f41b145fdf0d8114dcd0f0f315127ed71035927cce00de6b7062884b9018050b`. This is distinct from the original live-capture binary SHA-256 `aa2c9ad558ae07afd43d7a7ff99f12d396d6a7e3ecbb39ed7b686a0e68d0937f`.
- Teammate PR #2 commit `0bb54d5815a46b0cd3e89b513d4dd104846f5931` is preserved in the local feature history. The current dashboard working tree passed `npm run check`, `npm test` (3 tests), and `npm run build`; these checks do not substitute for an authenticated browser session.
- A running Controller plus browser smoke/end-to-end check is NOT RUN. No claim is made for browser SSO, dashboard-to-Controller end-to-end behavior, or real decoy telemetry. The teammate-owned frontend source was not changed during this continuation.
- The agent's operational `/execute` and `/rollback` routes are absent, and the legacy exported handlers return 404 even when `AGENT_EXECUTION_TOKEN` is set. Signed approval verification, replay reservation, helper audit, and recovery are tested only as isolated or same-process sandbox components; they are not connected to production dispatch.

## Captured live read-only result

Captured `2026-10-23T23:29:06+05:30` (`2026-10-23T17:59:06Z`) from `AH-CENTOS-01` (`ah-centos-01`): CentOS Stream 9, kernel `5.14.0-754.el9.aarch64`, architecture `aarch64` (reported by discovery as `arm64`), IP `192.168.64.3`. Agent binary SHA-256: `aa2c9ad558ae07afd43d7a7ff99f12d396d6a7e3ecbb39ed7b686a0e68d0937f`.

| Control | Effective value | Expected | Result |
|---|---:|---:|---|
| CSTS9-SSH-001 `PermitEmptyPasswords` | `no` | `no` | PASS |
| CSTS9-SSH-002 `PermitRootLogin` | `without-password` | `no` | FAIL |
| CSTS9-SSH-003 `PermitUserEnvironment` | `no` | `no` | PASS |
| CSTS9-SSH-004 `UsePAM` | `yes` | `yes` | PASS |

The captured `/plan` result is `BLOCKED` with an empty `actions` array. No remediation, `/execute`, or `/rollback` was run. These live results are distinct from the injected unit tests above; neither establishes comprehensive hardening or formal compliance.

Evidence bundle: [`evidence/centos-stream-9-arm64/2026-10-23/`](evidence/centos-stream-9-arm64/2026-10-23/).

| File | SHA-256 |
|---|---|
| `status.json` | `9feb90849fac6258b5abbd66b44e39bcde223866b3c27b689515d6a46cbbc05f` |
| `discovery.json` | `d17c201630328cf53569914191476a82a7f6721c0fafa3b99778f38f1a4e87bc` |
| `assessment.json` | `a063828e21ba61ca9cf161408f32455b9919c08891781842b9226cfe4c6471dd` |
| `plan.json` | `a2bd2f2e90b28f597017f392e7c89fd5a49a8587ad3f1c955ea05d7b94f2bc75` |
| `capture-metadata.txt` | `78afca01e97ca15fc5dab1eea0576398d2732a508e416f7c1a8080e9bf3d9f14` |

## Limitations and live acceptance

This adapter assesses only these four effective SSH settings. It does not establish broader OS hardening or benchmark compliance. It does not provide CentOS remediation, execution, verification-after-change, or rollback. The planner intentionally blocks CentOS plans.

The bundle records live discovery, assessment and planning only. Unit fixtures do not replace this live evidence, and the live capture does not replace unit coverage. No VM was accessed or modified during the subsequent implementation/documentation work.
