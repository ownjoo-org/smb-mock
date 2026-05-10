"""
Integration test fixtures.

Requires Docker.  Set SMB_SKIP_COMPOSE=1 to skip compose up/down
(e.g. when containers are already running externally).

Key env vars (all have defaults for the stock docker-compose.yml):
  SMB_HOST          host where port 445 is mapped  (default: 127.0.0.1)
  SMB_PORT          mapped SMB port                (default: 445)
  KDC_HOST_MAPPED   host where port 88 is mapped   (default: 127.0.0.1)
  KDC_PORT          mapped KDC port                (default: 88)
  SMB_HOSTNAME      Kerberos service hostname      (default: smbserver.smbtest.local)
  KRB5_REALM        Kerberos realm                 (default: SMBTEST.LOCAL)
"""
import os
import shutil
import socket
import subprocess
import time

import pytest

# ---------------------------------------------------------------------------
# Coordinates
# ---------------------------------------------------------------------------
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
COMPOSE_FILE = os.path.join(REPO_ROOT, "docker-compose.yml")

SMB_HOST: str = os.environ.get("SMB_HOST", "127.0.0.1")
SMB_PORT: int = int(os.environ.get("SMB_PORT", "445"))
KDC_HOST_MAPPED: str = os.environ.get("KDC_HOST_MAPPED", "127.0.0.1")
KDC_PORT: int = int(os.environ.get("KDC_PORT", "88"))
SMB_HOSTNAME: str = os.environ.get("SMB_HOSTNAME", "smbserver.smbtest.local")
KRB5_REALM: str = os.environ.get("KRB5_REALM", "SMBTEST.LOCAL")

TEST_USER: str = "testuser"
TEST_PASSWORD: str = "testpass"
TEST_SHARE: str = "testshare"
READONLY_SHARE: str = "readonly"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _wait_tcp(host: str, port: int, timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection((host, port), timeout=2):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise TimeoutError(f"{host}:{port} not ready after {timeout}s")
            time.sleep(1)


# ---------------------------------------------------------------------------
# Session fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def compose_stack():
    """Build and start the compose stack once per test session."""
    if not shutil.which("docker"):
        pytest.skip("docker not available")

    skip_compose = os.environ.get("SMB_SKIP_COMPOSE", "").lower() in ("1", "true", "yes")

    if not skip_compose:
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "up", "--build", "-d"],
            check=True,
            cwd=REPO_ROOT,
        )

    # Skip DFS referral round-trips — our server has no DFS namespace.
    try:
        import smbclient as _sc
        _sc.ClientConfig().skip_dfs = True
    except ImportError:
        pass

    try:
        _wait_tcp(KDC_HOST_MAPPED, KDC_PORT, timeout=120)
        _wait_tcp(SMB_HOST, SMB_PORT, timeout=60)
        # Brief grace period: smbd needs a moment after TCP port opens
        time.sleep(3)
        yield
    finally:
        if not skip_compose:
            subprocess.run(
                ["docker", "compose", "-f", COMPOSE_FILE, "down", "-v"],
                check=False,
                cwd=REPO_ROOT,
            )


@pytest.fixture(scope="session")
def smb_host() -> str:
    return SMB_HOST


@pytest.fixture(scope="session")
def smb_port() -> int:
    return SMB_PORT


@pytest.fixture(scope="session")
def test_credentials() -> tuple[str, str]:
    return TEST_USER, TEST_PASSWORD


@pytest.fixture(scope="session")
def test_share() -> str:
    return TEST_SHARE


@pytest.fixture(scope="session")
def readonly_share() -> str:
    return READONLY_SHARE


@pytest.fixture(scope="session")
def krb5_conf_path(tmp_path_factory) -> str:
    """Write a minimal krb5.conf pointing at the test KDC."""
    tmp = tmp_path_factory.mktemp("krb5")
    path = tmp / "krb5.conf"
    path.write_text(
        "[libdefaults]\n"
        f"    default_realm = {KRB5_REALM}\n"
        "    dns_lookup_realm = false\n"
        "    dns_lookup_kdc = false\n"
        # rdns=false: GSSAPI must not reverse-resolve 127.0.0.1→localhost
        # when canonicalizing the cifs/smbserver.smbtest.local SPN.
        # dns_canonicalize_hostname=false: use the hostname as supplied.
        "    rdns = false\n"
        "    dns_canonicalize_hostname = false\n"
        # udp_preference_limit=1: always use TCP (Docker UDP NAT can be unreliable).
        "    udp_preference_limit = 1\n"
        "\n"
        "[realms]\n"
        f"    {KRB5_REALM} = {{\n"
        f"        kdc = {KDC_HOST_MAPPED}:{KDC_PORT}\n"
        "    }\n"
        "\n"
        "[domain_realm]\n"
        "    .smbtest.local = SMBTEST.LOCAL\n"
        "    smbtest.local = SMBTEST.LOCAL\n"
    )
    return str(path)


# ---------------------------------------------------------------------------
# Per-test fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def reset_smb_sessions():
    """Flush smbprotocol session cache between tests."""
    try:
        import smbclient
        smbclient.reset_connection_cache()
    except ImportError:
        pass
    yield
    try:
        import smbclient
        smbclient.reset_connection_cache()
    except ImportError:
        pass
    except Exception:
        pass
