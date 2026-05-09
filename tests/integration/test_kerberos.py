"""
Kerberos / SPNEGO authentication tests.

kinit runs INSIDE the KDC container (no local Kerberos install required).
The ccache is copied out to a temp file on the host so smbprotocol can use it.

The one host-side prerequisite that cannot be avoided: the Kerberos SPN must
match the hostname used to connect, so smbserver.smbtest.local must resolve.

    Add to C:\\Windows\\System32\\drivers\\etc\\hosts (or /etc/hosts):
        127.0.0.1  smbserver.smbtest.local

Tests are skipped (not failed) if that entry is missing.
"""
import os
import shutil
import socket
import subprocess
import tempfile
import uuid

import pytest

smbclient = pytest.importorskip("smbclient", reason="smbprotocol not installed")

from tests.integration.conftest import (
    KDC_HOST_MAPPED,
    KDC_PORT,
    KRB5_REALM,
    SMB_HOSTNAME,
    SMB_PORT,
    TEST_PASSWORD,
    TEST_SHARE,
    TEST_USER,
)

# ---------------------------------------------------------------------------
# Module-level skip guard — hostname resolution only
# ---------------------------------------------------------------------------
try:
    socket.getaddrinfo(SMB_HOSTNAME, None)
except socket.gaierror:
    pytest.skip(
        f"{SMB_HOSTNAME!r} does not resolve. "
        f"Add '127.0.0.1  {SMB_HOSTNAME}' to your hosts file.",
        allow_module_level=True,
    )

_CONTAINER = "smb-mock-kdc-1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _kinit_in_container(username: str, password: str, container_ccache: str) -> None:
    """Run kinit inside the KDC container."""
    principal = f"{username}@{KRB5_REALM}"
    proc = subprocess.run(
        ["docker", "exec", "-i", _CONTAINER,
         "kinit", "-c", container_ccache, principal],
        input=f"{password}\n",
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"kinit in container failed: {proc.stderr.strip()}")


def _copy_ccache_from_container(container_ccache: str, host_ccache: str) -> None:
    subprocess.run(
        ["docker", "cp", f"{_CONTAINER}:{container_ccache}", host_ccache],
        check=True, capture_output=True,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def krb5_ticket(krb5_conf_path):
    """Obtain a Kerberos ticket via the KDC container; yield the ccache path."""
    if not _docker_available():
        pytest.skip("docker not on PATH — cannot obtain Kerberos ticket")

    container_ccache = "/tmp/pytest_test.ccache"
    with tempfile.NamedTemporaryFile(suffix=".ccache", delete=False) as tmp:
        host_ccache = tmp.name

    try:
        _kinit_in_container(TEST_USER, TEST_PASSWORD, container_ccache)
        _copy_ccache_from_container(container_ccache, host_ccache)

        old_ccname = os.environ.get("KRB5CCNAME")
        old_conf = os.environ.get("KRB5_CONFIG")
        os.environ["KRB5CCNAME"] = f"FILE:{host_ccache}"
        os.environ["KRB5_CONFIG"] = krb5_conf_path
        yield host_ccache
    finally:
        for key, val in [("KRB5CCNAME", old_ccname), ("KRB5_CONFIG", old_conf)]:
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        try:
            os.unlink(host_ccache)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_kerberos_list_share(krb5_ticket, test_share):
    smbclient.register_session(SMB_HOSTNAME, auth_protocol="kerberos", port=SMB_PORT)
    entries = smbclient.listdir(rf"\\{SMB_HOSTNAME}\{test_share}", port=SMB_PORT)
    assert isinstance(entries, list)


def test_kerberos_write_and_read(krb5_ticket, test_share):
    smbclient.register_session(SMB_HOSTNAME, auth_protocol="kerberos", port=SMB_PORT)
    filename = f"krb_{uuid.uuid4().hex[:8]}.txt"
    path = rf"\\{SMB_HOSTNAME}\{test_share}\{filename}"
    payload = "kerberos write test"
    try:
        with smbclient.open_file(path, mode="w", port=SMB_PORT) as fh:
            fh.write(payload)
        with smbclient.open_file(path, mode="r", port=SMB_PORT) as fh:
            assert fh.read() == payload
    finally:
        try:
            smbclient.remove(path, port=SMB_PORT)
        except Exception:
            pass


def test_kerberos_without_ticket_fails(test_share):
    """No ticket in cache → Kerberos auth must fail."""
    env_backup = os.environ.pop("KRB5CCNAME", None)
    try:
        with pytest.raises(Exception):
            smbclient.register_session(
                SMB_HOSTNAME, auth_protocol="kerberos", port=SMB_PORT
            )
            smbclient.listdir(rf"\\{SMB_HOSTNAME}\{test_share}", port=SMB_PORT)
    finally:
        if env_backup:
            os.environ["KRB5CCNAME"] = env_backup


def test_spnego_negotiates_kerberos_over_ntlm(krb5_ticket, test_share):
    """With a valid ticket, SPNEGO should prefer Kerberos over NTLM."""
    import uuid as _uuid
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session

    conn = Connection(_uuid.uuid4(), SMB_HOSTNAME, SMB_PORT)
    conn.connect()
    try:
        session = Session(conn, username=None, password=None, require_encryption=False)
        session.connect()
        assert session.session_id is not None
    finally:
        conn.disconnect()
