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

## Acceptance matrix

| Scenario | Expected result | Level |
|---|---|---|
| Exact CentOS Stream 9 ARM64 identity | Four findings from the CentOS catalog | Unit |
| Wrong distribution/version/architecture or inconsistent, incomplete, malformed identity | UNKNOWN; SSH runner not called | Unit |
| Each directive equals its expected value | Corresponding control PASS with matching evidence | Unit |
| Each directive differs, including `PermitRootLogin without-password` | Corresponding control FAIL; other findings remain independent | Unit |
| Missing, duplicate, malformed or incomplete required directive | One normalized assessment ERROR; no PASS | Unit |
| `sudo -n` denial or command exit failure | Normalized assessment ERROR; no PASS | Unit |
| Catalog identity, provenance, evidence and verification metadata | Stable CentOS IDs and project-defined provenance; no benchmark claims or remediation | Unit |
| Incomplete, uncertain, passing, or failing CentOS assessment reaches planner | BLOCKED plan with empty actions | Unit |
| Ubuntu assessment and `ACT-SSH-5.1.20` planning | Existing four-control behavior preserved | Unit regression |

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
