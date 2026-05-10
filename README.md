# smb-mock

A self-contained Docker stack that runs a real Samba file server backed by a real MIT Kerberos KDC — purpose-built for integration testing SMB/CIFS clients without a Windows domain controller.

[![CI](https://github.com/ownjoo-org/smb-mock/actions/workflows/ci.yml/badge.svg)](https://github.com/ownjoo-org/smb-mock/actions/workflows/ci.yml)
[![Docker](https://github.com/ownjoo-org/smb-mock/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/ownjoo-org/smb-mock/actions/workflows/docker-publish.yml)

## Quick start

```bash
docker compose up
```

This starts two containers:

| Container | Role | Ports |
|-----------|------|-------|
| `mock-kdc` | MIT Kerberos KDC — issues tickets, writes keytab | 88/tcp+udp, 8088/tcp (keytab HTTP API) |
| `smb-mock-samba` | Samba smbd — serves SMB2/3 shares | 445/tcp |

Samba waits for the KDC healthcheck before starting, so the stack is ready when `docker compose up` returns.

Default credentials: `testuser` / `testpass`  
Default shares: `testshare` (rw), `readonly` (ro)

## Authentication methods

All methods are independently toggleable via environment variables:

| Method | Env var | Default |
|--------|---------|---------|
| Anonymous / guest | `SMB_ENABLE_ANONYMOUS` | `true` |
| NTLMv2 | `SMB_ENABLE_NTLM` | `true` |
| Kerberos / SPNEGO | `SMB_ENABLE_KERBEROS` | `true` |

SMBv1 is disabled. SMBv2 and SMBv3 are enforced.

## Configuration

All configuration is through environment variables, either in a `.env` file or passed to `docker compose`.

### Users

```
SMB_USER_0=alice:s3cret
SMB_USER_1=bob:s3cret2
```

Supports UPN format (`alice@REALM`) for both Kerberos and NTLM.

### Shares

```
SMB_SHARE_0=docs:/smb-data/docs:rw
SMB_SHARE_1=archive:/smb-data/archive:ro
```

Format: `name:path-in-container:rw|ro`

### Identity

```
SMB_HOSTNAME=smbserver.smbtest.local
SMB_WORKGROUP=SMBTEST
KRB5_REALM=SMBTEST.LOCAL
KRB5_ADMIN_PASSWORD=adminpass
```

### Ports

```
SMB_PORT=445      # host port → container 445
KDC_PORT=88       # host port → container 88
KDC_HTTP_PORT=8088  # keytab HTTP API port (default 8088)
KDC_KEYTAB_PATH=/shared/krb5.keytab  # path inside container where keytab is written
```

## KDC keytab HTTP API

The KDC container (`speedimusmaximus/mock-kdc`) exposes a lightweight HTTP server on port 8088 so consumers can retrieve the keytab without a shared Docker volume:

```
GET http://<kdc-host>:8088/keytab   →  raw keytab bytes (application/octet-stream)
GET http://<kdc-host>:8088/healthz  →  200 ok once keytab is ready
```

The keytab is also emitted as a base64-encoded line in container stdout at startup:

```
KEYTAB_B64:<base64-encoded-keytab>
```

This lets consumers that cannot reach the HTTP endpoint parse `docker logs` instead.

The `/shared` directory inside the container is a conventional mount point (not a declared `VOLUME`) — you can mount it or ignore it and use the HTTP API instead.

### Wizards

**CLI wizard** (generates `.env`, `docker run` script, or compose override):

```bash
pip install -e ".[cli]"
smb-mock-wizard
```

**HTML wizard** — open `wizard.html` directly in a browser (no server required). Fill in the form; output updates live. Download or copy the generated config.

## Kerberos requirements

Kerberos requires the server FQDN to resolve on any machine running a Kerberos client. Add to your hosts file:

```
127.0.0.1  smbserver.smbtest.local
```

On Windows: `C:\Windows\System32\drivers\etc\hosts` (requires admin).

The Kerberos integration tests obtain tickets via `docker exec` into the KDC container — no local `kinit` installation required.

## Running tests

```bash
pip install -r requirements-test.txt

# Unit tests only (no Docker required)
pytest tests/unit/

# Integration tests (Docker must be running)
pytest tests/integration/

# Skip compose lifecycle if containers are already up
SMB_SKIP_COMPOSE=1 SMB_PORT=4450 KDC_PORT=8800 pytest tests/integration/
```

## Security notes

### Passwords in environment variables

Environment variables are the standard Docker configuration mechanism, but they are visible via `docker inspect` and readable from `/proc/1/environ` inside the container. For any deployment beyond a local developer workstation:

- Use [Docker secrets](https://docs.docker.com/engine/swarm/secrets/) or a secrets manager (Vault, AWS Secrets Manager, etc.) to inject credentials
- Restrict who can run `docker inspect` on the host
- Rotate credentials after any container exposure

### This is a test tool

`smb-mock` is designed for CI/CD pipelines and developer workstations. Default credentials are intentionally simple. **Do not expose the SMB or KDC ports to the public internet with default credentials.**

If you do expose this publicly (e.g., for shared test infrastructure):
- Change all default passwords via env vars
- Disable anonymous access (`SMB_ENABLE_ANONYMOUS=false`)
- Place behind a firewall or VPN; restrict source IPs at the host level
- Pin to a specific image tag rather than `latest`

### What is hardened

- Port 749 (kadmind) is not exposed on the host — KDC admin stays inside the Docker network
- `server string` is blank — no software fingerprinting via SMB banner
- `server signing = mandatory` when anonymous access is disabled
- `restrict anonymous = 2` when anonymous access is disabled — blocks unauthenticated info queries
- `valid users` enforced per share when anonymous access is disabled
- SMBv1 disabled; SMBv2 minimum enforced
- NTLMv1 disabled; NTLMv2 only
- Linux capabilities dropped to minimum required (`cap_drop: ALL` + selective `cap_add`)
- Container memory and CPU limits set

## Automated security testing

The following security checks run automatically on every push and pull request, and on a weekly schedule:

| Check | Tool | What it catches |
|-------|------|-----------------|
| Python SAST | [CodeQL](https://codeql.github.com/) | Injection, path traversal, insecure deserialization, and other CWE-class bugs in Python source |
| Python security linter | [Bandit](https://bandit.readthedocs.io/) | Hardcoded secrets, shell injection, insecure subprocess usage, weak crypto |
| Container CVE scan | [Trivy](https://trivy.dev/) | Known CVEs (CRITICAL/HIGH) in Alpine base image and installed packages; results appear in the GitHub Security tab |
| Dockerfile linting | [Hadolint](https://github.com/hadolint/hadolint) | Dockerfile best-practice violations and shell-script mistakes in `RUN` instructions |
| Dependency updates | [Dependabot](https://docs.github.com/en/code-security/dependabot) | Automated PRs for outdated pip packages, Docker base images, and GitHub Actions versions |

### What is NOT covered

Automated scanning does not replace a full security assessment. The following are explicitly out of scope for this project's built-in CI:

- **Runtime / dynamic analysis (DAST)** — no fuzzing, no traffic interception, no active exploitation attempts against a live container.
- **SMB protocol-level attack simulation** — relay attacks (NTLM relay, Pass-the-Hash), Kerberoasting, AS-REP roasting, and similar Active Directory attack paths are not tested.
- **Network-layer hardening** — firewall rules, TLS termination, and host-level access controls are your responsibility.
- **Secrets management** — credentials passed via environment variables are visible via `docker inspect`. This project does not enforce Docker secrets or a secrets manager; that is your operational responsibility.
- **Penetration testing** — no automated pen-test runs against the deployed stack.
- **Compliance auditing** — no CIS benchmark, SOC 2, PCI-DSS, or similar compliance checks.

### Security responsibility and disclaimer

> **You are solely responsible for the security of any deployment of this software.**
>
> `smb-mock` is a developer test tool. It is provided as-is for use in controlled, non-production environments (local workstations and CI pipelines). The automated checks above improve code quality and surface known vulnerabilities, but **they do not guarantee that the software is free of security defects, nor that any particular deployment is secure**.
>
> **The maintainers of this project accept no liability for any security incident, data loss, unauthorized access, or other harm arising from the use, misuse, or inability to use this software.** See the [MIT License](LICENSE) for the complete disclaimer of warranties and limitation of liability.
>
> Before exposing any port of this stack to a network, review the [Security notes](#security-notes) section and apply mitigations appropriate to your environment.

## Cross-realm trust (v1.1)

Trust relationship configuration is schema-complete and the env var contract is defined:

```
SMB_TRUST_0=CORP.EXAMPLE.COM:kdc.corp.example.com:sharedsecret:one-way
```

Full implementation (krbtgt principal creation, capaths, username mapping) is tracked for v1.1. Integration tests exist as `xfail` stubs.

## License

[MIT](LICENSE)
