"""
NTLMv2 authentication tests.

Connects using username + password (no Kerberos ticket).
smbprotocol negotiates SPNEGO and selects NTLM automatically.
"""
import uuid

import pytest

smbclient = pytest.importorskip("smbclient", reason="smbprotocol not installed")

from tests.integration.conftest import TEST_PASSWORD, TEST_USER


def _unc(host: str, share: str, *parts: str) -> str:
    base = rf"\\{host}\{share}"
    return "\\".join([base] + list(parts)) if parts else base


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_ntlm_authenticated_session(smb_host, smb_port, test_credentials, test_share):
    username, password = test_credentials
    smbclient.register_session(
        smb_host,
        username=username,
        password=password,
        port=smb_port,
        auth_protocol="ntlm",
    )
    entries = smbclient.listdir(_unc(smb_host, test_share), port=smb_port)
    assert isinstance(entries, list)


def test_ntlm_write_and_read(smb_host, smb_port, test_credentials, test_share):
    username, password = test_credentials
    smbclient.register_session(
        smb_host, username=username, password=password, port=smb_port
    )
    filename = f"ntlm_{uuid.uuid4().hex[:8]}.txt"
    path = _unc(smb_host, test_share, filename)
    payload = "ntlm write test"
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


def test_ntlm_upn_format(smb_host, smb_port, test_credentials, test_share):
    """user@REALM UPN format should authenticate via NTLM."""
    username, password = test_credentials
    from tests.integration.conftest import KRB5_REALM
    upn = f"{username}@{KRB5_REALM}"
    smbclient.register_session(
        smb_host, username=upn, password=password, port=smb_port
    )
    entries = smbclient.listdir(_unc(smb_host, test_share), port=smb_port)
    assert isinstance(entries, list)


def test_ntlm_wrong_password_denied(smb_host, smb_port, test_share):
    with pytest.raises(Exception):
        smbclient.register_session(
            smb_host,
            username=TEST_USER,
            password="definitelywrong",
            port=smb_port,
            auth_protocol="ntlm",
        )
        smbclient.listdir(_unc(smb_host, test_share), port=smb_port)


def test_ntlm_readonly_share_list(smb_host, smb_port, test_credentials, readonly_share):
    username, password = test_credentials
    smbclient.register_session(
        smb_host, username=username, password=password, port=smb_port
    )
    entries = smbclient.listdir(_unc(smb_host, readonly_share), port=smb_port)
    assert isinstance(entries, list)


def test_ntlm_write_to_readonly_denied(smb_host, smb_port, test_credentials, readonly_share):
    username, password = test_credentials
    smbclient.register_session(
        smb_host, username=username, password=password, port=smb_port
    )
    path = _unc(smb_host, readonly_share, f"blocked_{uuid.uuid4().hex[:8]}.txt")
    with pytest.raises(Exception):
        with smbclient.open_file(path, mode="w", port=smb_port) as fh:
            fh.write("blocked")


def test_ntlm_delete_file(smb_host, smb_port, test_credentials, test_share):
    username, password = test_credentials
    smbclient.register_session(
        smb_host, username=username, password=password, port=smb_port
    )
    filename = f"del_{uuid.uuid4().hex[:8]}.txt"
    path = _unc(smb_host, test_share, filename)
    with smbclient.open_file(path, mode="w", port=smb_port) as fh:
        fh.write("to be deleted")
    smbclient.remove(path, port=smb_port)
    assert filename not in smbclient.listdir(_unc(smb_host, test_share), port=smb_port)


def test_ntlm_mkdir_and_rmdir(smb_host, smb_port, test_credentials, test_share):
    username, password = test_credentials
    smbclient.register_session(
        smb_host, username=username, password=password, port=smb_port
    )
    dirname = f"dir_{uuid.uuid4().hex[:8]}"
    dirpath = _unc(smb_host, test_share, dirname)
    smbclient.mkdir(dirpath, port=smb_port)
    assert dirname in smbclient.listdir(_unc(smb_host, test_share), port=smb_port)
    smbclient.rmdir(dirpath, port=smb_port)
    assert dirname not in smbclient.listdir(_unc(smb_host, test_share), port=smb_port)
