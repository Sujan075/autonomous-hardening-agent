# Security Model and Execution Readiness

**Status date:** 2026-10-23
**Repository snapshot:** `infothon/rapid-integration` at `94b60b6` (starting snapshot; local security-hardening changes are uncommitted)

This document records the current security boundary of the prototype and the prerequisites for any remote privileged operation. It is not a production security approval. No live execution token is configured or included here.

## Current trust boundaries

- The Go agent runs on the target host and exposes health, status, discovery, assessment, plan, execute, and rollback HTTP handlers. Its default bind address is `127.0.0.1:9000`; this is a loopback default, not a production network boundary. `AGENT_HOST` can change the bind address, so deployment must keep it loopback until transport and authorization are reviewed.
- Agent HTTP uses `net/http` without TLS. Requests and responses are plaintext wherever the connection travels. The previously demonstrated SSH local tunnel only protected that lab path and does not establish a production trust model.
- The Controller currently proxies read-only status, assessment, and plan requests. No Controller execute or rollback API exists. The agent execution handlers are not a completed Controller-to-agent orchestration path.
- The agent's execute and rollback handlers require `POST` and a bearer value equal to `AGENT_EXECUTION_TOKEN`. If that environment variable is absent or empty, both handlers return `503` before calling privileged executor operations. The token is compared in constant time after a length check. It is a shared bearer secret, not agent identity, user identity, or proof of human approval.
- Execute accepts a JSON `approved` boolean and one supported action ID (`ACT-SSH-5.1.20`). That boolean is caller supplied and is **not authenticated approval evidence**. It cannot establish who approved, what exact change was approved, which target was approved, or whether approval is still valid. Rollback currently has no request-body approval/action contract; bearer authorization is its handler gate.
- Executor code supports one SSH root-login remediation with state capture, validation, verification, recovery, and rollback logic. Unit tests use injected operations. No live privileged execution or rollback has been performed.
- Recovery snapshots are local executor state. They are not a tamper-evident audit trail, durable evidence service, or proof of operator approval.

## Implemented safeguards and evidence

- Execute and rollback reject non-`POST` methods and reject requests when the execution token is unset, missing, or invalid. Handler tests inject executor callbacks and check that rejected requests make zero calls.
- Execute rejects malformed JSON, trailing JSON values, missing approval boolean (`false`), and unsupported action IDs before invoking its executor callback.
- Execution remains disabled by default because no token is configured in code or deployment by this change. Tokens are not logged or returned in handler responses.
- The existing executor unit tests cover state capture, state validation, action/path/digest checks, verification, recovery, and rollback behavior with fake operations. They do not exercise privileged system commands on a real host.
- The agent startup defaults to loopback. The startup configuration does not add TLS, enrollment, per-agent credentials, or remote execution authorization.

These tests establish only the tested handler conditions and fake-operation behavior. They do not prove end-to-end authorization, trustworthy approval, production transport security, or safe live remediation.

## Missing security controls

### Agent identity, enrollment, and key lifecycle

There is no authenticated agent enrollment or durable cryptographic agent identity. `agent-dev` is a development identifier, not an identity credential. No issuance, secure storage, rotation, expiry, revocation, compromise recovery, or inventory binding for agent keys/certificates is implemented. A shared execution token cannot replace these controls; it has no per-agent identity or scoped lifecycle.

Before remote execution, define and implement authenticated enrollment that binds a credential to a specific agent and target, protects private keys at rest, supports rotation and revocation, and prevents an unenrolled or cloned agent from being trusted. Define ownership, renewal, expiry, recovery, and audit for each key lifecycle operation.

### Transport and request authorization

HTTP is plaintext. For remote operation, use authenticated TLS with normal certificate and hostname verification (prefer mutual TLS where both Controller and agent identities are required), an explicit trust-root/rotation/revocation process, and safe failure on verification errors. Do not treat loopback binding, network location, or an SSH tunnel as authorization. Restrict network reachability and apply least privilege independently of application checks.

Replace the prototype shared bearer token with scoped, per-agent authorization or another reviewed mechanism. Bind authorization to the authenticated principal, target, action, and request; define expiry and revocation; protect secrets at rest and in transit; and ensure credentials never enter logs, error messages, telemetry, or user-visible artifacts. Keep privileged execution disabled until this design is implemented and reviewed.

### Authenticated approval

Before any remediation request can be authorized, add an approval record created through an authenticated Controller workflow. The record must bind at least:

- the authenticated approver and their authorization role;
- the exact action ID and immutable action parameters or plan digest;
- the exact target identity (not a mutable display name alone);
- the policy/catalog version and relevant pre-change assessment/evidence;
- an issuance time, short expiry, unique approval identifier, and current approval status.

The agent or trusted execution service must validate the signed or otherwise integrity-protected approval record, confirm its target/action/parameters match the requested operation, enforce its expiry and revocation state, and record the approver and decision. A request field such as `approved: true` must never be accepted as proof of human approval. No such authenticated approval system currently exists.

### Replay protection and idempotency

Bearer authorization and a boolean approval do not prevent replay. Before remote execution, use a unique request/approval nonce or identifier, a narrow validity window, and durable one-time consumption or equivalent replay detection scoped to target and action. Define idempotency behavior, duplicate delivery, retries, clock skew, concurrent requests, and crash recovery. Persist consumed approval/request identifiers so restart does not make an old request valid again.

### Audit and evidence

Create a durable, access-controlled, tamper-evident audit trail before execution is enabled. Record authenticated requester and approver identities, target identity, action and parameters, approval reference, policy version, request/decision timestamps, before-state evidence, executor/version, authorization result, command/result status, verification evidence, rollback/recovery outcome, and failures. Protect integrity and confidentiality, define retention and export, prevent secrets from being recorded, and test behavior when audit persistence is unavailable. Local recovery snapshots do not meet this requirement.

## Security gates before remote execution

Do not enable remote privileged execution until all of these gates are satisfied and evidenced:

1. Complete a threat model and security review for Controller, agent, enrollment, transport, authorization, approvals, privilege boundaries, updates, and recovery.
2. Implement and test authenticated agent enrollment, per-agent identity, secure key storage, rotation, expiry, and revocation.
3. Deploy authenticated TLS/mTLS with certificate validation, trust-root management, rotation/revocation, and network access controls. Preserve loopback binding unless a reviewed deployment design explicitly requires a different bind.
4. Replace the caller-provided approval boolean with authenticated, action-bound, target-bound, parameter-bound, time-limited approval records and enforce them at the execution boundary.
5. Add durable replay protection, request idempotency, concurrency control, and restart-safe approval consumption.
6. Implement tamper-evident audit and evidence persistence; fail closed when required authorization or audit dependencies are unavailable.
7. Validate the entire lifecycle in an isolated remediation-validation sandbox with failure injection, bounded privileges, verification, rollback, interruption recovery, and independent review. Keep this separate from the Cowrie/OpenCanary decoy sandbox.
8. Complete focused unit, integration, security, and negative-path tests, then perform separately approved live execution and rollback on disposable representative targets with captured evidence. Passing unit tests alone is insufficient.
9. Only after these gates, separately authorize and implement Controller orchestration. This task does not add Controller execute/rollback APIs, configure a token, enable remote execution, or perform live privileged operations.

## Current decision

**Remote privileged execution is not security-approved.** With `AGENT_EXECUTION_TOKEN` unset, agent execution and rollback handlers remain disabled. The next dependency is an approved end-to-end trust and authorization design—especially agent enrollment, authenticated transport, and cryptographically verifiable action/target/time-bound approval—followed by sandbox validation and security review.
