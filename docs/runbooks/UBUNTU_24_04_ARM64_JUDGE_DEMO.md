# Ubuntu 24.04.5 ARM64 judge demo runbook

This runbook demonstrates the repository's read-only Ubuntu SSH assessment slice. It does not demonstrate live remediation, formal CIS compliance, or a production deployment.

For the local process/filesystem remediation fixture, synthetic decoy simulator, dashboard, and audit view, use the separate [integrated demo runbook](INTEGRATED_DEMO.md). Those sandbox runs do not change this runbook's read-only target boundary.

## 1. One-time preparation before judging

The source checkout is known to exist on the Mac host at the repository path used for this task. The available UTM inventory lists `AH-UBUNTU-01` and `AH-UBUNTU-01-TEST`, both stopped when inspected. No guest was started, so this task could not establish a repository checkout path or binary path inside Ubuntu. The repository's deployment documentation does not give either path. Historical project status reports a Linux ARM64 build and VM checksum check, but do not record the artifact path, checksum, transfer command, or a repeatable deployment procedure. Do not assume that the Mac checkout is mounted inside the guest. **This runbook has not been dry-run inside UTM.**

Before the presentation, the operator must establish one of these prerequisites and record it in local demo notes:

1. A checkout of this repository is present in Ubuntu at a verified path, with a compatible Go toolchain; or
2. A Linux ARM64 agent binary has been placed in Ubuntu using the operator's previously verified deployment process, and its actual path and checksum have been checked against that process.

No checkout path or prebuilt-binary deployment process is documented here, so this runbook does not invent one. The repository's only deployment document, `agent/DEPLOYMENT.md`, describes read-only sudo scope and the remediation blocker; it does not provide build, copy, service-install, or binary-path instructions. If neither prerequisite can be established, the agent demonstration is blocked until the VM owner supplies the verified path/process. Do not copy an unverified binary or claim a dry-run.

The Go module in `agent/go.mod` declares `go 1.27.1`. A source build therefore requires a Go toolchain compatible with that directive (Go 1.27.1 or newer); Go 1.23 is not sufficient. Check the version in the Ubuntu guest before building. Do not install or upgrade the guest toolchain as part of the presentation without an independently approved preparation procedure.

Check the source checkpoint on the Mac host:

```sh
# [MAC HOST]
cd /Users/jusujan/Projects/autonomous-hardening-agent
git status --short --branch
git rev-parse HEAD
```

This runbook is read-only and may be used from the reviewed feature branch or a later approved checkpoint. Confirm the branch, commit, and working-tree state above against the checkpoint selected by the demo operator; this file intentionally does not pin an older integration commit. Do not overwrite an unexpected or dirty checkout.

Before judging, open the Ubuntu UTM guest and log in using the operator's known VM access details. Confirm Ubuntu 24.04.5 ARM64, OpenSSH server tools, `sudo`, `curl`, and an unprivileged account for the agent. If using a guest checkout, verify its actual path and toolchain. Replace `<verified-checkout-path>` below with that observed path before running it; angle-bracket values are placeholders, not commands to type literally.

```sh
# [UBUNTU UTM]
. /etc/os-release
printf '%s\n' "$PRETTY_NAME"
uname -m
curl --version | head -n 1
sshd -V 2>&1 | head -n 1
```

Expected identity is `Ubuntu 24.04.5 LTS` and `aarch64`. The agent reports Go's architecture as `arm64`; this is the same architecture as Linux `aarch64`. The assessor only dispatches the four-control catalog when Linux identity is Ubuntu 24.04.5 and the compiled runtime architecture is ARM64. Other identities should remain unsupported/UNKNOWN.

If using a source checkout, first verify its path with the VM owner, replace the placeholder, then check Go from the module directory:

```sh
# [UBUNTU UTM]
cd <verified-checkout-path>/agent
go version
```

This Go version must be compatible with the module's Go 1.27.1 directive. If using a prebuilt binary, verify its actual file path and recorded checksum by the operator's existing process instead; do not infer either from the Mac checkout.

Check the intended ports before startup. Agent HTTP is loopback port 9000 by default. The recorded tunnel forwards Mac loopback port 19000 to VM loopback port 9000. The previously verified Controller used port 8001; the sample configuration mentions 8000 and is not loaded by the current Controller database module. Select and record the Controller port actually in use.

```sh
# [UBUNTU UTM]
ss -ltnp | grep -E ':(9000)\b' || true

# [MAC HOST]
lsof -nP -iTCP:19000 -sTCP:LISTEN
lsof -nP -iTCP:8001 -sTCP:LISTEN
```

No output from `ss`/`lsof` means no matching listener was found. A nonzero `lsof` exit for no matching port is expected. For Controller-backed requests, confirm its configured `AGENT_STATUS_URL_OVERRIDES` maps the existing target ID to `http://127.0.0.1:19000`, and that its OIDC issuer/audience/JWKS and target-reader role configuration match an available demo token. Those variables and values are not established by this repository's `.env.example`; obtain them from the demo operator's configured environment. The Controller routes also require an existing target, current active binding/credential and, for assessment, a reviewed matching policy assignment. Do not create or alter production records during the demo.

The documented SSH assessment invokes `sudo -n /usr/sbin/sshd -T`. Check read-only authorization as the same account that will run the agent:

```sh
# [UBUNTU UTM]
id
sudo -n /usr/sbin/sshd -T >/dev/null
printf 'sshd assessment exit=%s\n' "$?"
```

Exit 0 establishes that this invocation succeeded at that moment. If it fails, stop and ask the VM administrator to assess the existing least-privilege setup. This runbook does not install sudoers rules or run the agent as root. The `-T` command prints effective configuration and does not change it.

## 2. Terminal labels

Every command below is labelled by where it runs:

- `[UBUNTU UTM]` — inside the Ubuntu guest terminal, including a shell reached over SSH.
- `[MAC HOST]` — on the Mac running UTM/SSH and, where applicable, the local Controller.
- `[CONTROLLER HOST]` — on a separate machine running the Controller. If the Controller runs on the Mac, use `[MAC HOST]` instead.

## 3. Commands inside `[UBUNTU UTM]`

### Source-build option

Use this only if the one-time preparation established a verified guest checkout and `go version` is compatible with `agent/go.mod`'s Go 1.27.1 directive. Replace `<verified-checkout-path>` with the actual confirmed path before running; do not type the angle brackets literally. The output `/tmp/aha-agent` is created by this build command in the guest; it is not a claimed pre-existing deployment path.

```sh
# [UBUNTU UTM]
cd <verified-checkout-path>/agent
go version
go build -o /tmp/aha-agent ./cmd/agent
/tmp/aha-agent
```

If using a prebuilt binary, run only its operator-verified actual path, after confirming its Linux ARM64 identity/checksum through the existing deployment record. This repository does not record that path or deployment procedure. Keep the agent unprivileged. The default listener is `127.0.0.1:9000` and the default ID is `agent-dev`. Startup logs include `agent_id`, `listening` and `tls=false`. The HTTP listener is plaintext but restricted in code to loopback; keep the SSH tunnel on the trusted demo host. Do not change `AGENT_HOST` to a non-loopback address. A TLS-enabled listener requires all four mTLS settings and is not configured by this runbook.

In a second Ubuntu terminal, check local health and the discovery payload:

```sh
# [UBUNTU UTM]
curl --fail --silent --show-error http://127.0.0.1:9000/health
curl --fail --silent --show-error http://127.0.0.1:9000/status
curl --fail --silent --show-error http://127.0.0.1:9000/discovery
```

Health returns `{"status":"ok"}`; status returns `agent_id` and `status:"online"`. Discovery returns `hostname`, `os`, `os_version`, `kernel`, `architecture` and `primary_ip`. Discovery is reported by the running process; it is not independent attestation.

## 4. Read-only demonstration inside `[UBUNTU UTM]`

The direct agent workflow below is reproducible once the preflight succeeds and does not require Controller enrollment or an OIDC token. It assesses the Ubuntu guest that runs the agent.

1. Show the guest identity and agent discovery:

   ```sh
   # [UBUNTU UTM]
   . /etc/os-release
   printf 'OS=%s VERSION_ID=%s ARCH=%s\n' "$ID" "$VERSION_ID" "$(uname -m)"
   curl --fail --silent --show-error http://127.0.0.1:9000/discovery
   ```

   Explain: “The agent reports its local hostname, OS string/version, kernel, runtime architecture, and selected primary IP. The supported assessment dispatch is deliberately limited to Ubuntu 24.04.5 on ARM64.” `primary_ip` selection and agent-reported identity are not security attestations.

2. Show effective SSH settings independently, then request assessment:

   ```sh
   # [UBUNTU UTM]
   sudo -n /usr/sbin/sshd -T | grep -E '^(permitemptypasswords|permitrootlogin|permituserenvironment|usepam) '
   curl --fail --silent --show-error http://127.0.0.1:9000/assessment
   ```

   Explain: “The assessor reads OpenSSH's effective configuration, not just one file, then emits one finding per catalogued setting with its observed value and evidence source.” Expected finding fields include `control_id`, `title`, `status`, `applicability`, `severity`, `current_value`, `expected_value`, `message`, `source`, and `evidence` entries (`name`, `value`, `source`). Expected controls and values are 5.1.19 `PermitEmptyPasswords=no`, 5.1.20 `PermitRootLogin=no`, 5.1.21 `PermitUserEnvironment=no`, and 5.1.22 `UsePAM=yes`. Findings can be PASS or FAIL; command/identity problems must not be described as passing. The `ssh.effective_config` evidence source is produced from `sshd -T` output.

3. Show the separate plan endpoint:

   ```sh
   # [UBUNTU UTM]
   curl --fail --silent --show-error http://127.0.0.1:9000/plan
   ```

   Response fields are top-level `platform`, `findings`, and `plan`; `plan` contains `status`, `platform`, and `actions`. Complete compliant results should produce `status:"READY"` and an empty actions array. A supported failed root-login finding can yield a READY plan containing an approval-required recommendation with `action_id`, `control_id`, `title`, `action_type`, `current_value`, `desired_value`, `risk_score`, `execution_mode`, and `reason`. This is a recommendation only, not authorization or execution. Incomplete, erroneous, unknown or unsupported input should result in a BLOCKED plan with no actions.

   Explain: “Assessment observations and planning recommendations are separate. READY means the planner accepted a complete input and generated its plan; it does not mean a change was approved, executed, or verified.”

4. If the prepared Controller demo prerequisites in section 6 are already met, show Controller health and use its existing authorized, configured target ID and access token for read-only status, assessment and plan. Do not put the token in shell history; use a protected local environment or secret manager provisioned by the operator. Route response schemas are documented by the app: agent status returns `reachable`, and when reachable `agent_id`/`status`; assessment includes `target_id`, `target_name`, `assessment`, `assessment_observation_id`, `assessment_trust_status`, `policy_status` and policy metadata; plan proxies the agent's plan response. The assessment path validates the reviewed assignment against agent-reported discovery and controls, then records an observation as untrusted; it still does not attest the binary or authenticate plaintext tunnel traffic.

## 5. Commands on `[MAC HOST]`

The verified local topology used Mac `127.0.0.1:19000` forwarded to the guest's `127.0.0.1:9000`. Replace both angle-bracket placeholders with the actual Ubuntu login name and SSH-reachable UTM address before execution. **Do not execute this command with the angle brackets still present**; they are explanatory placeholders and shell metacharacters. Keep the agent bound to loopback inside the guest. This tunnel does not justify exposing the plaintext listener on the VM network.

```sh
# [MAC HOST]
ssh -N -L 127.0.0.1:19000:127.0.0.1:9000 <ubuntu-user>@<utm-vm-address>
```

Use a second Mac terminal to check the tunnel:

```sh
# [MAC HOST]
curl --fail --silent --show-error http://127.0.0.1:19000/health
```

The Mac host is known to have the repository at `/Users/jusujan/Projects/autonomous-hardening-agent`. The guest checkout is not established by available evidence. Do not infer a shared directory or successful copy from that Mac path.

## 6. Optional Controller commands and prerequisites

Run these only if the Controller environment was already prepared and its existing authorized target, active identity/binding/credential, reviewed policy assignment, OIDC configuration/token, and tunnel URL override are available. Do not modify database records or relax authorization to make the demo work. A separate Controller host needs its own approved path to the tunnel endpoint; `127.0.0.1` on that host does not refer to the Mac.

```sh
# [CONTROLLER HOST] (use [MAC HOST] if Controller runs locally)
cd <verified-repository-path>/controller
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Replace `<verified-repository-path>` with the Controller host's actual repository path before running. On this Mac, the known path is `/Users/jusujan/Projects/autonomous-hardening-agent/controller`. A separate Controller host path and an existing Python 3.12 `.venv` are not established by this runbook. Keep its process running. `/health` returns `{"status":"ok"}`. The app creates its SQLite schema on startup at `controller/hardening.db`; its DB path is fixed in `app/db/database.py`. Controller APIs are OIDC role-protected; startup alone does not create an authorized target, binding, credential, or reviewed policy.

```sh
# [CONTROLLER HOST] (or [MAC HOST] for a local Controller)
curl --fail --silent --show-error http://127.0.0.1:8001/health
```

If the Controller prerequisites are all satisfied, use its already-provisioned read-only token mechanism and target ID for status, assessment and plan. Do not put bearer tokens in shell history. Agent status returns `reachable` and, when reachable, `agent_id`/`status`. Assessment includes `target_id`, `target_name`, `assessment`, `assessment_observation_id`, `assessment_trust_status`, `policy_status` and policy metadata. Plan proxies the agent response. Controller assessment validates the reviewed assignment against agent-reported discovery and controls, then records an observation as untrusted; it does not attest the binary or authenticate plaintext tunnel traffic.

## 7. Ubuntu test catalogue

The exact scenario mapping below comes from `docs/test-matrix/UBUNTU_24_04_ARM64_V1.md`. Run the full test command once; several scenarios deliberately share a single table-driven test and must not be presented as separately invoked tests.

```sh
# [MAC HOST] (repository checkout; requires a Go toolchain compatible with go 1.27.1)
cd /Users/jusujan/Projects/autonomous-hardening-agent/agent
go test -count=1 ./...
```

All listed cases are recorded as `UNIT-TESTED` in the matrix. UBU-20 also contains an isolated process-level OpenSSH check against temporary configuration, with reload stubbed; it is not live target evidence.

| Scenario(s) | Automated test name(s) | What it shows / does not show |
|---|---|---|
| UBU-01 | `TestAssessHostDispatchesOnlySupportedUbuntuCatalog` | Injected supported identity dispatches and returns four findings; not live discovery. |
| UBU-02 | `TestAssessHostRejectsUnsupportedOrIncompleteIdentityBeforeCommands`; `TestAssessHostRejectsUnsupportedUbuntuReleaseBeforeCommands` | Unsupported release is UNKNOWN before SSH; not support for those releases. |
| UBU-03 | `TestAssessHostUnknownOSAndDetectionFailureFailClosed`; `TestAssessHostDoesNotDispatchUbuntuControlsToCentOSStream` | Unsupported OS/distro fails closed; not other-distro support. |
| UBU-04 | `TestAssessHostRejectsUnsupportedOrIncompleteIdentityBeforeCommands` | Malformed/missing/duplicate identity and non-ARM64 fail closed; not identity attestation. |
| UBU-05–06 | `TestEachCataloguedControlPassesAndFailsIndependently` | Fixture PASS/FAIL for 5.1.19; not live SSH config. |
| UBU-07–08 | `TestEachCataloguedControlPassesAndFailsIndependently` | Fixture PASS/FAIL for 5.1.20; not live SSH config. |
| UBU-09–10 | `TestEachCataloguedControlPassesAndFailsIndependently` | Fixture PASS/FAIL for 5.1.21; not live SSH config. |
| UBU-11–12 | `TestEachCataloguedControlPassesAndFailsIndependently` | Fixture PASS/FAIL for 5.1.22; not live SSH config. |
| UBU-13 | `TestAssessSSHControlsMissingOrMalformedOutputReturnsError`; `TestParseEffectiveSSHConfigFourDirectives` | Invalid/missing directive output errors; injected output only. |
| UBU-14 | `TestAssessSSHControlsCommandInvocationFailureReturnsError`; `TestEvaluatorFailureNeverProducesPassingFindings`; `TestAssessHostRetainsNormalizedUbuntuCommandFailure` | Command/sudo failure does not pass; tests do not run real sudo. |
| UBU-15 | `TestAssessSSHControlsCompliantConfiguration`; `TestEachCataloguedControlPassesAndFailsIndependently` | Finding metadata/evidence matches fixture and catalog; not benchmark authority. |
| UBU-16 | `TestAssessHostRejectsUnsupportedOrIncompleteIdentityBeforeCommands`; `TestAssessHostUnknownOSAndDetectionFailureFailClosed` | Unsupported/incomplete identity remains UNKNOWN; unit evidence only. |
| UBU-17 | `TestBuildAssessmentPlanFailsClosedForIncompleteOrUncertainAssessments`; `TestBuildAssessmentPlanBlocksUnsupportedCentOSStreamAssessment` | Incomplete or unsupported assessment yields BLOCKED/no actions; not authorization. |
| UBU-18 | `TestBuildAssessmentPlanCompleteCompliantUbuntuIsReady`; `TestBuildAssessmentPlanCompleteFailingSSHRootLoginRequiresApproval` | Findings remain distinct from READY plan/recommendations; not Controller E2E. |
| UBU-19 | `TestExecuteHandlerRejectsRequestsBeforeExecution`; `TestExecuteHandlerDisablesExecutionWhenTokenIsUnset`; `TestRollbackHandlerRejectsRequestsBeforeRollback`; `TestRollbackHandlerDisablesExecutionWhenTokenIsUnset`; helper tests `TestHelperRejectsMalformedOversizedDuplicateUnknownAndTrailingRequestsWithoutOperation`, `TestHelperRejectsInvalidSignaturesExpiredAndMismatchedClaimsBeforeOperation`, `TestReplayPersistenceFailureAndPreOperationAuditFailurePreventMutation`, `TestHelperRecomputesBindingsFromConfiguredTypedContext` | Rejected requests do not call injected operations; handler/helper are disconnected from Controller dispatch. No target operation occurs. |
| UBU-20 | `TestDuplicateExecutionCannotOverwriteInitialSnapshot`; `TestAlreadyCompliantStateDoesNotOverwriteSavedSnapshot`; `TestCorruptedSnapshotContentIsRejected`; `TestUnexpectedSavedFilePathIsRejected`; `TestSuccessfulRestorationVerifiesPriorContentAndExistence`; `TestApplyUsesRealSSHDValidationAndEffectiveConfigurationInTemporaryTree`; `TestEarlierSSHDDirectiveWinsAndExecutorRecoversInsteadOfReportingSuccess`; `TestApplyFailuresAttemptAndVerifyRecovery`; `TestRestoreOrVerificationFailureNeverReportsSuccessfulRollback`; helper tests `TestHelperReplayIsAtomicAcrossConcurrencyAndStoreRecreation`, `TestPostOperationAuditFailureIsExplicitlyIncompleteAndCannotBeRetried`, `TestOperationFailureNeverReturnsSuccessAndRetainsRecoveryRequiredStatus` | Snapshot/recovery and OpenSSH behavior on temporary files, with stubbed reload/fake callbacks; no privileged VM integration or live rollback. |

The official CIS Ubuntu 24.04 LTS Benchmark profile/PDF was not directly reviewed for this evidence, and applicability to the exact Ubuntu 24.04.5 ARM64 target remains unresolved. Do not claim full CIS compliance.

## 8. Validation checklist

These commands reproduce the repository-level checks. Python commands use the project's existing `.venv`; `pyproject.toml` requires Python 3.12. Do not install dependencies during the demo.

```sh
# [MAC HOST] (repository root; Go must be compatible with go 1.27.1)
cd /Users/jusujan/Projects/autonomous-hardening-agent/agent
go test -count=1 ./...
go vet ./...

# [MAC HOST]
cd ../controller
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m compileall -q app tests
.venv/bin/python -m tabnanny app tests

# [MAC HOST]
cd ..
git diff --check
gofmt -d agent/internal/assessment/platform.go agent/internal/assessment/platform_test.go agent/internal/assessment/ssh_test.go
```

`gofmt -d` checks only the three listed assessment dispatch/test files and should print no differences; it does not check every Go file. `git diff --check` should print nothing and exit 0. The last documented full Controller suite had 108 passing tests in the prior evidence record (E-24); the exact command above is recorded there. That count/result is historical, not freshly run for this documentation task. The Go and Python results in E-24 are likewise prior reports. The current module's Go 1.27.1 directive applies to Go builds/tests. Record any fresh result separately and do not relabel fixture/unit evidence as `INTEGRATION-TESTED` or `LIVE-VERIFIED`.

## 9. Expected outputs and troubleshooting

- **Agent startup says port/address in use:** inspect with `ss -ltnp`; do not kill an unidentified process. Resolve the port with the VM operator. Agent defaults to loopback `127.0.0.1:9000`.
- **No guest checkout or binary path can be established:** stop before starting the agent. Obtain the known-good checkout/artifact details from the VM owner or verified deployment record; do not guess a path or claim successful copying/building.
- **Go toolchain is older than the module requirement:** do not attempt a source build. Prepare a compatible toolchain through the normal approved VM process or use the operator-verified ARM64 binary artifact and recorded checksum.
- **Agent refuses non-loopback plaintext:** this is intentional. Keep default loopback and use the SSH tunnel. The HTTPS/mTLS mode requires complete cert, key, client CA and Controller URI configuration; do not improvise it for the demo.
- **`sudo -n /usr/sbin/sshd -T` fails:** this may mean the account lacks the existing noninteractive permission or sshd/config is unavailable. Do not type a password into a noninteractive assessment, add a sudoers rule, or run the whole agent as root. Ask the VM administrator to resolve the approved read-only prerequisite.
- **Tunnel does not connect:** check VM SSH reachability, username/address, tunnel process, VM agent `ss -ltnp` output, Mac port 19000, and local `/health`. A failed tunnel says nothing about assessment correctness. Do not expose the guest agent on a non-loopback interface as a workaround.
- **Assessment returns ERROR:** inspect agent terminal logs, read-only `sudo -n /usr/sbin/sshd -T` exit status, and whether the four required effective settings are emitted. A prior `/run/sshd` issue was observed once and its cause is unknown; do not claim it is resolved.
- **Platform UNKNOWN/unsupported:** show the reported release/architecture and stop the live assessment claim. Only Ubuntu 24.04.5 ARM64 dispatch is established.
- **Controller returns 401/403:** OIDC token/role prerequisite is not met. 404 can mean target missing. 502 can indicate transport, upstream, or policy/assessment validation rejection; 503 can indicate missing Controller state/configuration or persistence/audit failure. Do not weaken auth or seed records during the demo.
- **Plan is BLOCKED or UNKNOWN:** treat it as fail-closed behavior. Check that assessment has all four catalog findings, expected evidence and no command errors; never interpret UNKNOWN as compliant. A READY plan is still not execution approval.

## 10. Security boundaries

`agent/internal/privhelper` is a disabled, disconnected library prototype. It is not an executable, service, HTTP handler, or deployed privilege boundary. Do not enable it. Do not perform privileged remediation during this runbook.

- Do not configure `AGENT_EXECUTION_TOKEN`.
- Do not call live `/execute` or `/rollback` routes.
- Do not write SSH configuration or recovery state.
- Do not reload `ssh.service`.
- Do not install a sudoers rule or privileged service.
- Do not run the agent as root.

The assessment-only `sudo -n /usr/sbin/sshd -T` permission, if already provisioned, is read-only. A passing assessment or READY plan does not mean remediation lifecycle is live-verified. The Controller's lab SSH tunnel is unauthenticated HTTP transport in the documented local topology; it is not production identity or authorization. Do not claim verified agent integrity, formal CIS applicability, or complete lifecycle support.

## 11. Presentation plans

### 3–5 minute walkthrough

1. `[UBUNTU UTM]` Show `/etc/os-release` and `uname -m`: evidence of the guest identity currently presented, not independent attestation.
2. `[UBUNTU UTM]` Show `/health`, `/status`, `/discovery`: evidence that the process is running and reports the expected identity fields.
3. `[UBUNTU UTM]` Show the read-only `sshd -T` values and `/assessment`: evidence of effective settings and four finding records, with current/expected values and source evidence.
4. `[UBUNTU UTM]` Show `/plan`: evidence of separate planning and fail-closed status; explain no action is authorized or executed.
5. Close by disclosing unit-test versus live evidence, the unresolved official benchmark/applicability review, and the absence of live execute/rollback verification.

### Longer technical walkthrough

Run the section 8 checks and describe them accurately: Go suite and vet check Go code; Controller unittest/compileall/tabnanny check Python code; formatting and diff checks check source hygiene. Explain UBU-01–UBU-20 using the catalogue, especially that shared test names cover grouped scenarios and fixtures are `UNIT-TESTED`. If the Controller prerequisites are already satisfied, show health, read-only status, assessment and plan over the forwarded loopback connection, then explain target binding, reviewed policy and observation trust status. Disclose that this recorded topology used SSH forwarding and did not authenticate the agent channel. No command in this walkthrough demonstrates privileged execution, rollback, formal CIS compliance or production readiness.

## 12. After-demo cleanup

Stop only the processes started for this demo using Ctrl-C in their own terminals: the Go agent, SSH tunnel, and (if started for this session) Controller. Confirm the agent listener is gone if needed:

```sh
# [UBUNTU UTM]
ss -ltnp | grep -E ':(9000)\b' || true

# [MAC HOST]
lsof -nP -iTCP:19000 -sTCP:LISTEN
```

Do not delete the Controller database, remove configuration, alter SSH settings, disable services, or terminate processes not started for this demo.
