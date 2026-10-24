# CentOS Stream 9 ARM64 Judge Demo Runbook

This runbook performs a read-only agent demo against `AH-CENTOS-01`. The adapter supports only CentOS Stream 9 ARM64 and the four project-defined SSH baseline controls listed below. It does not claim CIS compliance or comprehensive hardening. Do not call `/execute` or `/rollback`.

## Target and prerequisites

Target identity recorded for the demo:

- VM: `AH-CENTOS-01`; hostname: `ah-centos-01`
- OS: CentOS Stream 9; expected `/etc/os-release`: `ID=centos`, `NAME="CentOS Stream"`, `VERSION_ID=9`, `PRETTY_NAME="CentOS Stream 9"`
- Kernel: `5.14.0-754.el9.aarch64`
- Architecture: `aarch64` on the VM, `arm64` as reported by Go discovery
- IP: `192.168.64.3`; SSH account: `sujan`
- The demo agent listens on `127.0.0.1:9000`, with TLS disabled, and is reached through an SSH tunnel.
- The VM currently has `/etc/sudoers.d/autonomous-hardening-agent`, which grants `sujan` passwordless permission only for `/usr/sbin/sshd -T`. The agent invokes it through the fixed `/usr/bin/sudo -n /usr/sbin/sshd -T` command.

Use a local Go toolchain and SSH access to the lab VM. Do not broaden the sudoers rule. Before starting, confirm the target identity in a read-only SSH session:

```sh
ssh sujan@192.168.64.3
hostname
cat /etc/os-release
uname -r
uname -m
ip -brief address
sudo -n /usr/sbin/sshd -T >/dev/null && echo 'read-only sshd check: OK'
```

Expected: hostname `ah-centos-01`; CentOS Stream 9 identity above; kernel `5.14.0-754.el9.aarch64`; machine `aarch64`; address `192.168.64.3`; and the final `OK` line. Stop if identity differs or the noninteractive command fails. The command does not edit SSH configuration.

## Build and transfer

From the repository root, run the Go suite and static checks:

```sh
cd agent
go test -count=1 ./...
go vet ./...
```

`go test` runs unit and repository integration tests; `go vet` checks for common Go mistakes. Both must pass before the demo. Build a Linux ARM64 agent:

```sh
GOOS=linux GOARCH=arm64 go build -o /tmp/agent-centos-stream9-arm64 ./cmd/agent
file /tmp/agent-centos-stream9-arm64
shasum -a 256 /tmp/agent-centos-stream9-arm64
```

Expected `file` output identifies a 64-bit ARM aarch64 Linux executable. Record the SHA-256. The previously captured live-demo binary had SHA-256 `aa2c9ad558ae07afd43d7a7ff99f12d396d6a7e3ecbb39ed7b686a0e68d0937f`; a new build may differ, so use the checksum of the exact binary transferred for any new capture.

Transfer the binary and verify the copy matches the local file:

```sh
scp /tmp/agent-centos-stream9-arm64 sujan@192.168.64.3:/tmp/agent-centos-stream9-arm64
shasum -a 256 /tmp/agent-centos-stream9-arm64
ssh sujan@192.168.64.3 'sha256sum /tmp/agent-centos-stream9-arm64'
```

The two hashes must match. This verifies transfer integrity, not source authenticity; separately retain the source revision and build environment with the demo record.

## Start the agent and open the tunnel

In an SSH terminal on the VM, run the agent in the foreground:

```sh
ssh sujan@192.168.64.3
AGENT_HOST=127.0.0.1 AGENT_PORT=9000 /tmp/agent-centos-stream9-arm64
```

Expected startup log identifies `listening=127.0.0.1:9000` and `tls=false`. Keep this terminal open. The process runs as `sujan`; only the fixed read-only SSH configuration command uses noninteractive sudo.

In a second local terminal, forward local port 19000 to the VM loopback listener:

```sh
ssh -N -L 19000:127.0.0.1:9000 sujan@192.168.64.3
```

Keep the tunnel open. In a third local terminal, call only the read-only GET endpoints:

```sh
curl --fail --silent --show-error http://127.0.0.1:19000/health
curl --fail --silent --show-error http://127.0.0.1:19000/status
curl --fail --silent --show-error http://127.0.0.1:19000/discovery
curl --fail --silent --show-error http://127.0.0.1:19000/assessment
curl --fail --silent --show-error http://127.0.0.1:19000/plan
```

Expected: health is `ok`; status is `online`; discovery identifies `ah-centos-01`, Linux, CentOS Stream 9, ARM64, and `192.168.64.3`; assessment returns four findings; plan reports `BLOCKED` with `"actions":[]`. Save the JSON responses with a timestamp and the exact binary SHA-256. Do not interpret the blocked plan as an assessment failure: the planner intentionally has no CentOS remediation actions.

The separate Controller assessment endpoint requires an active target-agent binding and a current reviewed, explicitly versioned policy assignment. When those prerequisites exist, its `policy_evaluation.decision` is `COMPLIANT`, `NON_COMPLIANT`, or `INDETERMINATE`; only matching values with substantiating evidence can be COMPLIANT. `policy_status` reports that the assigned policy matched the agent-reported assessment, not a formal compliance certification. The captured CentOS bundle was collected directly from the agent and does not establish a reviewed Controller policy assignment.

The Controller exposes read-only discovery/status, assessment, and planning routes. It has no execution or rollback routes. The agent's legacy `/execute` and `/rollback` handlers are not an approved human-approval workflow: do not set `AGENT_EXECUTION_TOKEN`, send requests to those endpoints, or use this target for writes.

## Expected assessment

All findings use source `ssh.effective_config` and evidence from effective `sshd -T` configuration.

| Control | Directive | Observed | Expected | Result |
|---|---|---:|---:|---|
| CSTS9-SSH-001 | `PermitEmptyPasswords` | `no` | `no` | PASS |
| CSTS9-SSH-002 | `PermitRootLogin` | `without-password` | `no` | FAIL |
| CSTS9-SSH-003 | `PermitUserEnvironment` | `no` | `no` | PASS |
| CSTS9-SSH-004 | `UsePAM` | `yes` | `yes` | PASS |

These values are the captured target result. A later run may differ; report the values returned by that run. `without-password` does not satisfy this project's expected value `no`.

## Existing evidence and checksums

The captured bundle is `docs/test-matrix/evidence/centos-stream-9-arm64/2026-10-23/`. Capture time is `2026-10-23T23:29:06+05:30` (`2026-10-23T17:59:06Z`). Its recorded agent binary SHA-256 is `aa2c9ad558ae07afd43d7a7ff99f12d396d6a7e3ecbb39ed7b686a0e68d0937f`.

| Evidence file | SHA-256 |
|---|---|
| `status.json` | `9feb90849fac6258b5abbd66b44e39bcde223866b3c27b689515d6a46cbbc05f` |
| `discovery.json` | `d17c201630328cf53569914191476a82a7f6721c0fafa3b99778f38f1a4e87bc` |
| `assessment.json` | `a063828e21ba61ca9cf161408f32455b9919c08891781842b9226cfe4c6471dd` |
| `plan.json` | `a2bd2f2e90b28f597017f392e7c89fd5a49a8587ad3f1c955ea05d7b94f2bc75` |
| `capture-metadata.txt` | `78afca01e97ca15fc5dab1eea0576398d2732a508e416f7c1a8080e9bf3d9f14` |

Verify bundle integrity from the repository root with:

```sh
shasum -a 256 docs/test-matrix/evidence/centos-stream-9-arm64/2026-10-23/*
```

The output should match the table. The JSON files document read-only status, discovery, assessment and planning results. They do not prove execution, rollback, or compliance with a benchmark.

## Troubleshooting

- **Identity is UNKNOWN:** Recheck the exact `/etc/os-release` values, `uname -m`, and Go binary architecture. Only CentOS Stream 9 ARM64 is dispatched; CentOS Linux, Stream 10, other RHEL derivatives, and other architectures are unsupported.
- **Assessment returns ERROR:** Inspect foreground agent stderr. Check that `/usr/sbin/sshd` exists and that `sudo -n /usr/sbin/sshd -T` succeeds without prompting. The sudoers authorization must remain limited to that command; do not use a shell or widen the rule.
- **Connection refused:** Confirm the foreground agent reports `127.0.0.1:9000`, TLS is disabled, and the SSH tunnel is still running. The listener is loopback-only; access it through the tunnel.
- **Unexpected findings:** Preserve the exact response and evidence. Findings reflect effective settings, not only a particular configuration file. Do not change settings during the assessment demo.
- **Plan is BLOCKED:** This is expected for every CentOS assessment until a separate reviewed remediation design exists. There should be no actions.

## Cleanup after the demo

Cleanup is an operator action for after the demo; it has **not** been performed as part of this documentation work.

1. Stop the foreground agent with `Ctrl-C` in its VM terminal.
2. Stop the SSH tunnel with `Ctrl-C` in its local terminal.
3. Remove the transferred temporary binary from the VM as `sujan`: `rm -f /tmp/agent-centos-stream9-arm64`.
4. Remove the persistent sudoers rule using VM console or a separate administrative/root session. The rule itself permits only `sshd -T`, so it does not authorize its own removal:

   ```sh
   sudo rm /etc/sudoers.d/autonomous-hardening-agent
   sudo visudo -c
   ```

   Confirm `visudo -c` reports the sudoers configuration parsed successfully. Do not remove any unrelated policy files.
5. Remove the local temporary binary when no longer needed: `rm -f /tmp/agent-centos-stream9-arm64`.
6. Retain the evidence bundle and its checksums with the project records.
