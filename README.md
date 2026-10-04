# Autonomous Multi-Platform Security Hardening Agent

An autonomous, policy-bounded security hardening platform designed to assess and remediate security configuration across heterogeneous environments.

## Problem Statement

SIH25237 — Autonomous Multi-Platform Security Hardening Agent

The system is designed to enforce security hardening policies across multiple environments including operating systems, containers, cloud guest instances, and edge systems.

## Project Goal

Build a secure and auditable hardening platform that can:

- Discover target systems
- Identify applicable security controls
- Assess the current security state
- Generate findings
- Plan remediation
- Evaluate remediation risk
- Execute approved and policy-bounded changes
- Verify the resulting state
- Recover or roll back when required
- Preserve tamper-evident audit evidence

## Current Prototype Strategy

The first complete vertical slice targets Ubuntu.

The initial prototype focuses on proving the complete lifecycle:

Discover → Assess → Find → Plan → Risk Decision → Execute → Verify → Recover → Audit

After the Ubuntu workflow is stable, the same architecture will be extended to CentOS and Docker, followed by representative Windows, cloud, and edge environments.

## Supported Environment Scope

### Initial Implementation

- Ubuntu
- CentOS
- Docker

### Representative Expansion

- Windows
- AWS EC2 guest OS
- Edge Linux / Raspberry Pi-class ARM64 systems

## Architecture

The system follows a Controller + Target Agent architecture.

```text
                     Web Dashboard
                           |
                           v
                    Central Controller
                           |
                    HTTPS + mTLS
                           |
                           v
                     Target Agent
                           |
              +------------+------------+
              |            |            |
           Ubuntu       CentOS       Docker
              |            |            |
              +------------+------------+
                           |
                     Target System

---

## Create `.gitignore`

Run:

```bash
cat > .gitignore <<'EOF'
# Environment files
.env
.env.*
!.env.example

# Python
.venv/
venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/

# Node
node_modules/
dist/
build/
.vite/

# Go
bin/
*.exe
*.test
*.out

# Databases
*.db
*.db-shm
*.db-wal

# Logs
*.log
logs/

# Certificates and private keys
*.key
*.pem
*.p12
*.pfx
certs/
private/
secrets/

# OS/editor
.DS_Store
.vscode/
.idea/

# Temporary files
tmp/
temp/
*.tmp

# Coverage
.coverage
htmlcov/
coverage.xml
