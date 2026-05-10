# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A two-container Docker stack (`smb-mock-kdc` + `smb-mock-samba`) for integration-testing SMB/CIFS clients without a Windows domain controller. All configuration flows in via environment variables; the containers generate their own config files at startup.

## Commands

```bash
# Unit tests (no Docker required)
python -m pytest tests/unit/ -q

# Single unit test
python -m pytest tests/unit/test_samba_config.py::test_username_map_script_always_present -q

# Integration tests — containers must be running first
docker compose up -d
SMB_SKIP_COMPOSE=1 SMB_PORT=4450 KDC_PORT=8800 python -m pytest tests/integration/ -v

# Build containers
docker compose build

# CLI wizard
pip install -e ".[cli]"
smb-mock-wizard

# Python security linter
pip install bandit[toml]
bandit -r docker/ cli/ -ll -q
```

**Windows note:** Port 445 is owned by Windows. Always use `SMB_PORT=4450 KDC_PORT=8800` (or any free ports) when running locally. Pass `SMB_SKIP_COMPOSE=1` when containers are already up.

## Architecture

### Container startup flow

Both containers follow the same pattern: `entrypoint.py` reads env vars → generates config files on disk → creates OS/Kerberos principals → `os.execvp()` the daemon as PID 1.

**KDC** (`docker/kdc/`):
1. `config.py` parses env → `KdcConfig` dataclass
2. `entrypoint.py` writes `/etc/krb5.conf`, `/etc/krb5kdc/kdc.conf`, `kadm5.acl`
3. Runs `kdb5_util create` to init principal DB
4. Runs `kadmin.local` for each principal (admin, `host/FQDN`, `cifs/FQDN`, users, trust krbtgts)
5. Exports keytab to `/shared/krb5.keytab` (Docker volume shared with Samba)
6. Starts `kadmind` in background (suppressed, internal only — port 749 never host-exposed)
7. `exec krb5kdc -n` as PID 1

**Samba** (`docker/samba/`):
1. `config.py` parses env → `SambaConfig` dataclass
2. `entrypoint.py` writes `/etc/samba/smb.conf`, `/etc/krb5.conf`, `/etc/samba/username_map.sh`
3. Creates Linux users (`adduser`) and sets Samba passwords (`smbpasswd`)
4. Waits up to 120s for `/shared/krb5.keytab` (written by KDC)
5. `exec smbd -F --no-process-group` as PID 1

### Config generation

`docker/samba/config.py` and `docker/kdc/config.py` are pure Python with no dependencies — they take a dataclass in, return a config file string out. This is the entire unit-testable surface.

Key behaviours baked into `generate_smb_conf`:
- `server signing = mandatory` when anonymous is disabled, `auto` when enabled (guest sessions cannot sign)
- `restrict anonymous = 2` when anonymous disabled
- `valid users` enforced per share when anonymous disabled
- `username map script` always present (strips `@REALM` so UPN format works for NTLM)
- `browseable = No`, blank `server string` (no fingerprinting)

### Test layout

- `tests/unit/` — pure config-generation tests, no Docker, fast
- `tests/integration/` — live SMB protocol tests via `smbprotocol`/`smbclient`
- `tests/integration/conftest.py` — manages compose lifecycle and session fixtures; `SMB_SKIP_COMPOSE=1` bypasses compose up/down

### smbprotocol quirks

- `smbclient.ClientConfig()` is a global singleton — mutation must be cleaned up between tests
- Guest sessions on SMBv2/3 cannot sign: requires `require_signing=False` in `register_session` **and** `ClientConfig().require_secure_negotiate = False`
- `listdir`, `open_file`, etc. default to port 445 regardless of `register_session` port — always pass `port=` explicitly
- Kerberos SPN matching requires the FQDN to resolve — IP addresses do not work

### Kerberos test approach

Integration tests obtain Kerberos tickets via `docker exec` into the KDC container (no local `kinit` needed), then `docker cp` the ccache out. See `tests/integration/test_kerberos.py`.

### CI / publishing

- `ci.yml` — unit tests + Bandit + Hadolint on every push/PR
- `docker-publish.yml` — builds and pushes `speedimusmaximus/mock-kdc` and `speedimusmaximus/mock-smb` to Docker Hub on `main` push or `v*` tag
- `codeql.yml` — GitHub SAST, weekly + push/PR to main
- `trivy.yml` — CVE scan of both images, SARIF → GitHub Security tab

### Cross-realm trust

Schema and env var contract defined (`SMB_TRUST_N=REALM:kdc_host:secret:one-way|two-way`). Full implementation (krbtgt principal creation, capaths, username mapping) is tracked for v1.1 — integration tests are `xfail` stubs.
