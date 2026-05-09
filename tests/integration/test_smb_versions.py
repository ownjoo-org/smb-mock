"""
SMB protocol version negotiation tests.

Verifies that the server:
  - Refuses SMBv1 (not offered)
  - Negotiates SMBv2 or higher with a default client
  - Can negotiate SMBv3 when the client advertises it
"""
import uuid

import pytest

pytest.importorskip("smbprotocol", reason="smbprotocol not installed")

from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session

from tests.integration.conftest import TEST_PASSWORD, TEST_USER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _connect(host: str, port: int) -> Connection:
    conn = Connection(uuid.uuid4(), host, port)
    conn.connect()
    return conn


def _auth(conn: Connection) -> Session:
    session = Session(conn, username=TEST_USER, password=TEST_PASSWORD)
    session.connect()
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_negotiates_smb2_or_higher(smb_host, smb_port):
    conn = _connect(smb_host, smb_port)
    try:
        assert conn.dialect >= Dialects.SMB_2_0_2, (
            f"Expected SMBv2+, got dialect 0x{conn.dialect:04x}"
        )
    finally:
        conn.disconnect()


def test_does_not_negotiate_smb1(smb_host, smb_port):
    conn = _connect(smb_host, smb_port)
    try:
        assert conn.dialect != 0x0100, "Server negotiated SMBv1 — should be disabled"
    finally:
        conn.disconnect()


def test_can_negotiate_smb3(smb_host, smb_port):
    """smbprotocol advertises SMB 3.1.1 by default; server should match."""
    conn = _connect(smb_host, smb_port)
    try:
        assert conn.dialect >= Dialects.SMB_3_0_0, (
            f"Expected SMBv3+, got dialect 0x{conn.dialect:04x}"
        )
    finally:
        conn.disconnect()


def test_authenticated_session_on_smb3(smb_host, smb_port, test_credentials):
    username, password = test_credentials
    conn = _connect(smb_host, smb_port)
    try:
        assert conn.dialect >= Dialects.SMB_3_0_0
        session = Session(conn, username=username, password=password)
        session.connect()
        assert session.session_id is not None
    finally:
        conn.disconnect()


def test_multiple_concurrent_connections(smb_host, smb_port, test_credentials):
    """Two independent connections should both succeed."""
    username, password = test_credentials
    conns = [_connect(smb_host, smb_port) for _ in range(2)]
    try:
        for conn in conns:
            session = Session(conn, username=username, password=password)
            session.connect()
            assert session.session_id is not None
    finally:
        for conn in conns:
            try:
                conn.disconnect()
            except Exception:
                pass
