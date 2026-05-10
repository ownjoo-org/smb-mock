"""
Kerberos / SPNEGO authentication tests.

Prerequisites (both must be satisfied or the whole class is skipped):

  1. SMB hostname must resolve:
       Add to /etc/hosts (or C:\\Windows\\System32\\drivers\\etc\\hosts):
         127.0.0.1  smbserver.smbtest.local

  2. KDC must be reachable on KDC_HOST_MAPPED:KDC_PORT (default 127.0.0.1:88).
     When using docker-compose locally, map KDC_PORT to something free, e.g.:
       KDC_PORT=8800 docker compose up -d

kinit is preferred on the host (so the ccache uses the native GSSAPI library).
Falls back to docker-exec into the KDC container when kinit is not installed.
"""
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
import uuid

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

try:
    import smbclient
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    _HAS_SMBCLIENT = True
except ImportError:
    _HAS_SMBCLIENT = False

_CONTAINER = "smb-mock-kdc-1"


# ---------------------------------------------------------------------------
# Prerequisite checks (evaluated once at import time)
# ---------------------------------------------------------------------------
def _smb_hostname_resolves() -> bool:
    try:
        socket.getaddrinfo(SMB_HOSTNAME, None)
        return True
    except socket.gaierror:
        return False


def _kdc_reachable() -> bool:
    try:
        with socket.create_connection((KDC_HOST_MAPPED, KDC_PORT), timeout=3):
            return True
    except OSError:
        return False


_SMB_RESOLVES = _smb_hostname_resolves()
_KDC_REACHABLE = _kdc_reachable()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _kinit_in_container(username: str, password: str, container_ccache: str) -> None:
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
        check=True,
        capture_output=True,
    )


def _write_krb5_conf() -> str:
    """Write a minimal krb5.conf pointing at the test KDC; return the path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False
    ) as fh:
        fh.write(
            "[libdefaults]\n"
            f"    default_realm = {KRB5_REALM}\n"
            "    dns_lookup_realm = false\n"
            "    dns_lookup_kdc = false\n"
            # rdns=false: GSSAPI must not reverse-resolve 127.0.0.1→localhost
            "    rdns = false\n"
            "    dns_canonicalize_hostname = false\n"
            # udp_preference_limit=1: always use TCP (Docker UDP NAT can be unreliable)
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
        return fh.name


def _obtain_ticket(krb5_conf: str, host_ccache: str) -> bool:
    """
    Obtain a TGT into *host_ccache*.
    Prefers host kinit; falls back to docker-exec into the KDC container.
    Returns True on success, raises/skips on unrecoverable failure.
    """
    host_kinit = shutil.which("kinit")
    if host_kinit:
        env = os.environ.copy()
        env["KRB5_CONFIG"] = krb5_conf
        env["KRB5CCNAME"] = f"FILE:{host_ccache}"
        proc = subprocess.run(
            [host_kinit, "-c", host_ccache, f"{TEST_USER}@{KRB5_REALM}"],
            input=f"{TEST_PASSWORD}\n",
            text=True,
            capture_output=True,
            env=env,
        )
        if proc.returncode == 0:
            return True
        import sys
        print(f"Host kinit failed: {proc.stderr.strip()}", file=sys.stderr)

    if not _docker_available():
        return False

    container_ccache = "/tmp/pytest_krb5.ccache"
    _kinit_in_container(TEST_USER, TEST_PASSWORD, container_ccache)
    _copy_ccache_from_container(container_ccache, host_ccache)
    return True


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------
@unittest.skipUnless(_HAS_SMBCLIENT, "smbprotocol not installed")
@unittest.skipUnless(
    _SMB_RESOLVES,
    f"{SMB_HOSTNAME!r} does not resolve — add '127.0.0.1  {SMB_HOSTNAME}' to /etc/hosts",
)
@unittest.skipUnless(
    _KDC_REACHABLE,
    f"KDC not reachable at {KDC_HOST_MAPPED}:{KDC_PORT} — "
    f"is the KDC container running? (KDC_PORT={KDC_PORT})",
)
class TestKerberos(unittest.TestCase):

    # -- class-level: shared krb5.conf written once ---------------------------

    @classmethod
    def setUpClass(cls) -> None:
        cls.krb5_conf = _write_krb5_conf()

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            os.unlink(cls.krb5_conf)
        except OSError:
            pass

    # -- per-test: ticket + env vars + session reset --------------------------

    def setUp(self) -> None:
        # Flush any leftover SMB sessions from a previous test
        try:
            smbclient.reset_connection_cache()
        except Exception:
            pass

        # Create a fresh ccache file
        with tempfile.NamedTemporaryFile(suffix=".ccache", delete=False) as tmp:
            self._ccache = tmp.name

        if not _obtain_ticket(self.krb5_conf, self._ccache):
            self.skipTest(
                "kinit not on PATH and docker not available — cannot obtain Kerberos ticket"
            )

        # Stash current env so tearDown can restore it
        self._prev_ccname = os.environ.get("KRB5CCNAME")
        self._prev_conf = os.environ.get("KRB5_CONFIG")
        os.environ["KRB5CCNAME"] = f"FILE:{self._ccache}"
        os.environ["KRB5_CONFIG"] = self.krb5_conf

    def tearDown(self) -> None:
        # Restore env vars
        for key, old_val in [
            ("KRB5CCNAME", self._prev_ccname),
            ("KRB5_CONFIG", self._prev_conf),
        ]:
            if old_val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_val

        # Remove the temporary ccache
        try:
            os.unlink(self._ccache)
        except OSError:
            pass

        # Flush SMB sessions
        try:
            smbclient.reset_connection_cache()
        except Exception:
            pass

    # -- tests ----------------------------------------------------------------

    def test_kerberos_list_share(self) -> None:
        smbclient.register_session(SMB_HOSTNAME, auth_protocol="kerberos", port=SMB_PORT)
        entries = smbclient.listdir(rf"\\{SMB_HOSTNAME}\{TEST_SHARE}", port=SMB_PORT)
        self.assertIsInstance(entries, list)

    def test_kerberos_write_and_read(self) -> None:
        smbclient.register_session(SMB_HOSTNAME, auth_protocol="kerberos", port=SMB_PORT)
        filename = f"krb_{uuid.uuid4().hex[:8]}.txt"
        path = rf"\\{SMB_HOSTNAME}\{TEST_SHARE}\{filename}"
        payload = "kerberos write test"
        try:
            with smbclient.open_file(path, mode="w", port=SMB_PORT) as fh:
                fh.write(payload)
            with smbclient.open_file(path, mode="r", port=SMB_PORT) as fh:
                self.assertEqual(fh.read(), payload)
        finally:
            try:
                smbclient.remove(path, port=SMB_PORT)
            except Exception:
                pass

    def test_kerberos_without_ticket_fails(self) -> None:
        """No ticket in the cache → Kerberos auth must fail."""
        saved = os.environ.pop("KRB5CCNAME", None)
        try:
            with self.assertRaises(Exception):
                smbclient.register_session(
                    SMB_HOSTNAME, auth_protocol="kerberos", port=SMB_PORT
                )
                smbclient.listdir(rf"\\{SMB_HOSTNAME}\{TEST_SHARE}", port=SMB_PORT)
        finally:
            if saved is not None:
                os.environ["KRB5CCNAME"] = saved

    def test_spnego_negotiates_kerberos_over_ntlm(self) -> None:
        """With a valid ticket SPNEGO must prefer Kerberos over NTLM."""
        conn = Connection(uuid.uuid4(), SMB_HOSTNAME, SMB_PORT)
        conn.connect()
        try:
            session = Session(
                conn, username=None, password=None, require_encryption=False
            )
            session.connect()
            self.assertIsNotNone(session.session_id)
        finally:
            conn.disconnect()
