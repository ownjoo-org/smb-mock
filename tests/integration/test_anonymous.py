"""
Anonymous / guest access tests.

Guest sessions on SMBv2/3 cannot sign or verify secure-negotiate.
We disable require_secure_negotiate globally for this test module
(and reset it after each test via the autouse fixture below).
"""
import uuid

import pytest

smbclient = pytest.importorskip("smbclient", reason="smbprotocol not installed")


@pytest.fixture(autouse=True)
def guest_client_config():
    cfg = smbclient.ClientConfig()
    cfg.require_secure_negotiate = False
    yield
    cfg.require_secure_negotiate = True


def _unc(host: str, share: str, *parts: str) -> str:
    base = rf"\\{host}\{share}"
    return "\\".join([base] + list(parts)) if parts else base


def _guest_session(smb_host: str, smb_port: int, username: str = "guest", password: str = "") -> None:
    smbclient.register_session(
        smb_host, username=username, password=password, port=smb_port, require_signing=False
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_list_share_as_guest(smb_host, smb_port, test_share):
    _guest_session(smb_host, smb_port)
    entries = smbclient.listdir(_unc(smb_host, test_share), port=smb_port)
    assert isinstance(entries, list)


def test_write_file_as_guest(smb_host, smb_port, test_share):
    _guest_session(smb_host, smb_port)
    filename = f"anon_{uuid.uuid4().hex[:8]}.txt"
    path = _unc(smb_host, test_share, filename)
    try:
        with smbclient.open_file(path, mode="w", port=smb_port) as fh:
            fh.write("anonymous write test")
    finally:
        try:
            smbclient.remove(path, port=smb_port)
        except Exception:
            pass


def test_read_file_written_as_guest(smb_host, smb_port, test_share):
    _guest_session(smb_host, smb_port)
    filename = f"anon_{uuid.uuid4().hex[:8]}.txt"
    path = _unc(smb_host, test_share, filename)
    payload = "hello from anonymous"
    try:
        with smbclient.open_file(path, mode="w", port=smb_port) as fh:
            fh.write(payload)
        with smbclient.open_file(path, mode="r", port=smb_port) as fh:
            assert fh.read() == payload
    finally:
        try:
            smbclient.remove(path, port=smb_port)
        except Exception:
            pass


def test_bad_user_mapped_to_guest(smb_host, smb_port, test_share):
    """map to guest = bad user: unknown user is silently mapped to guest."""
    _guest_session(smb_host, smb_port, username="nobody_real", password="wrongpassword")
    entries = smbclient.listdir(_unc(smb_host, test_share), port=smb_port)
    assert isinstance(entries, list)


def test_list_readonly_share_as_guest(smb_host, smb_port, readonly_share):
    _guest_session(smb_host, smb_port)
    entries = smbclient.listdir(_unc(smb_host, readonly_share), port=smb_port)
    assert isinstance(entries, list)


def test_write_to_readonly_share_denied(smb_host, smb_port, readonly_share):
    _guest_session(smb_host, smb_port)
    path = _unc(smb_host, readonly_share, f"should_fail_{uuid.uuid4().hex[:8]}.txt")
    with pytest.raises(Exception):
        with smbclient.open_file(path, mode="w", port=smb_port) as fh:
            fh.write("this should fail")
