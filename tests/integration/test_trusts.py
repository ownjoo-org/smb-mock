"""
Kerberos cross-realm trust tests.

Status: STUBBED — marked xfail until trust configuration is fully
implemented and a second KDC (or trusted realm) is available in the
test environment.

To run against a real trusted realm:
  1. Configure SMB_TRUST_0=TRUSTED.REALM:kdc.trusted.example.com:secret:one-way
     (or :two-way) in docker-compose or environment.
  2. Set TRUSTED_REALM, TRUSTED_USER, TRUSTED_PASSWORD env vars.
  3. Ensure the trusted KDC has the reciprocal principal configured.
  4. Remove the xfail markers from the tests you want to run.
"""
import os

import pytest

smbclient = pytest.importorskip("smbclient", reason="smbprotocol not installed")

from tests.integration.conftest import SMB_HOSTNAME

TRUSTED_REALM: str = os.environ.get("TRUSTED_REALM", "TRUSTED.LOCAL")
TRUSTED_USER: str = os.environ.get("TRUSTED_USER", "")
TRUSTED_PASSWORD: str = os.environ.get("TRUSTED_PASSWORD", "")


def _unc(share: str, *parts: str) -> str:
    base = rf"\\{SMB_HOSTNAME}\{share}"
    return "\\".join([base] + list(parts)) if parts else base


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason="Requires a configured trusted realm; set TRUSTED_REALM/USER/PASSWORD "
           "and SMB_TRUST_0 to activate.",
    strict=False,
)
def test_one_way_trust_user_can_list_share(krb5_conf_path, test_share):
    """
    A user from TRUSTED.REALM authenticates via cross-realm Kerberos
    and lists a share on our server.
    """
    if not TRUSTED_USER or not TRUSTED_PASSWORD:
        pytest.skip("TRUSTED_USER / TRUSTED_PASSWORD not set")

    # Obtain ticket for trusted-realm user (kinit handled externally or via
    # a fixture extended for this test).
    smbclient.register_session(
        SMB_HOSTNAME,
        auth_protocol="kerberos",
        port=445,
    )
    entries = smbclient.listdir(_unc(test_share))
    assert isinstance(entries, list)


@pytest.mark.xfail(
    reason="Requires a configured two-way trusted realm.",
    strict=False,
)
def test_two_way_trust_bidirectional_auth(krb5_conf_path, test_share):
    """
    Two-way trust: users from each realm can authenticate against the
    other realm's resources.
    """
    pytest.skip("two-way trust test not yet implemented")
