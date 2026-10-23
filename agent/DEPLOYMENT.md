# Ubuntu agent deployment

The read-only SSH assessment invokes only `sudo -n /usr/sbin/sshd -T`. To grant that assessment command without making the agent privileged, an administrator can add a sudoers rule for the agent account (replace `agent-user` with the account that runs the agent):

```sudoers
agent-user ALL=(root) NOPASSWD: /usr/sbin/sshd -T
```

This permits only the fixed `/usr/sbin/sshd -T` invocation used by the assessor. Do not add wildcards or grant the agent broader sudo access. Keep SSH configuration file permissions unchanged. This rule does not grant remediation permissions.

Validate a sudoers drop-in's syntax before relying on it:

```sh
sudo visudo -cf /etc/sudoers.d/autonomous-hardening-agent
```

After an administrator installs the rule, check it as the agent account without performing remediation:

```sh
sudo -n /usr/sbin/sshd -T >/dev/null
```

`sshd -T` evaluates and prints effective configuration; it does not change SSH configuration. A nonzero exit status means the noninteractive permission or SSH configuration needs attention.

## Remediation is blocked pending a reviewed privilege boundary

The SSH executor is a feature-off prototype. Its current implementation requires the agent process to run as root, writes `/etc/ssh/sshd_config.d/99-autonomous-hardening-agent.conf`, stores recovery state below `/var/lib/autonomous-hardening-agent/state`, and reloads `ssh.service`. It does not use the assessment-only sudo command above. Running the whole agent as root conflicts with the intended unprivileged-agent deployment model and is not an approved deployment configuration. No helper, narrower sudo rule, privileged service, execution token, or remote execution path is configured by this documentation.

Before considering remediation, design and review a narrow privileged helper/service boundary that accepts only the fixed typed action, validates fixed paths and recovery-state ownership, and exposes no arbitrary command or file operation. Test the helper and agent as separate identities in a disposable Ubuntu VM, including effective `sshd -T` verification, first-value precedence conflicts, interrupted writes/reloads, recovery and recovery verification. Obtain a security review and explicit deployment approval before any live privileged execution. Until then, keep `AGENT_EXECUTION_TOKEN` unset and do not run the executor on a managed host.
