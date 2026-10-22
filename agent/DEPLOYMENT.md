# Ubuntu agent deployment

The agent stays unprivileged. To allow only its SSH assessment, an administrator can add a sudoers rule for the agent account (replace `agent-user` with the account that runs the agent):

```sudoers
agent-user ALL=(root) NOPASSWD: /usr/sbin/sshd -T
```

This permits only the fixed `/usr/sbin/sshd -T` invocation used by the assessor. Do not add wildcards or grant the agent broader sudo access. Keep SSH configuration file permissions unchanged.

Validate a sudoers drop-in's syntax before relying on it:

```sh
sudo visudo -cf /etc/sudoers.d/autonomous-hardening-agent
```

After an administrator installs the rule, check it as the agent account without performing remediation:

```sh
sudo -n /usr/sbin/sshd -T >/dev/null
```

`sshd -T` evaluates and prints effective configuration; it does not change SSH configuration. A nonzero exit status means the noninteractive permission or SSH configuration needs attention.
