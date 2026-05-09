import unittest

from samba.config import (
    User,
    Share,
    Trust,
    SambaConfig,
    parse_user,
    parse_share,
    parse_trust,
    load_config_from_env,
    generate_smb_conf,
    generate_krb5_conf,
)


class TestParseUser(unittest.TestCase):
    def test_valid(self):
        user = parse_user("alice:password123")
        self.assertEqual(user.name, "alice")
        self.assertEqual(user.password, "password123")

    def test_password_with_colon(self):
        user = parse_user("alice:pass:word")
        self.assertEqual(user.name, "alice")
        self.assertEqual(user.password, "pass:word")

    def test_empty_name_raises(self):
        with self.assertRaises(ValueError):
            parse_user(":password")

    def test_empty_password_raises(self):
        with self.assertRaises(ValueError):
            parse_user("alice:")

    def test_no_separator_raises(self):
        with self.assertRaises(ValueError):
            parse_user("alicepassword")


class TestParseShare(unittest.TestCase):
    def test_rw(self):
        share = parse_share("testshare:/smb-data/testshare:rw")
        self.assertEqual(share.name, "testshare")
        self.assertEqual(share.path, "/smb-data/testshare")
        self.assertFalse(share.readonly)

    def test_ro(self):
        share = parse_share("readonly:/smb-data/readonly:ro")
        self.assertTrue(share.readonly)

    def test_invalid_mode_raises(self):
        with self.assertRaises(ValueError):
            parse_share("testshare:/smb-data/testshare:rx")

    def test_too_few_parts_raises(self):
        with self.assertRaises(ValueError):
            parse_share("testshare:/smb-data/testshare")

    def test_too_many_parts_raises(self):
        with self.assertRaises(ValueError):
            parse_share("testshare:/smb-data/testshare:rw:extra")

    def test_empty_name_raises(self):
        with self.assertRaises(ValueError):
            parse_share(":/smb-data/testshare:rw")

    def test_empty_path_raises(self):
        with self.assertRaises(ValueError):
            parse_share("testshare::rw")


class TestParseTrust(unittest.TestCase):
    def test_one_way(self):
        trust = parse_trust("TRUSTED.REALM:kdc.trusted.example.com:sharedsecret:one-way")
        self.assertEqual(trust.realm, "TRUSTED.REALM")
        self.assertEqual(trust.kdc_host, "kdc.trusted.example.com")
        self.assertEqual(trust.shared_secret, "sharedsecret")
        self.assertEqual(trust.direction, "one-way")

    def test_two_way(self):
        trust = parse_trust("OTHER.REALM:kdc.other.com:secret:two-way")
        self.assertEqual(trust.direction, "two-way")

    def test_invalid_direction_raises(self):
        with self.assertRaises(ValueError):
            parse_trust("TRUSTED.REALM:kdc.example.com:secret:invalid")

    def test_too_few_parts_raises(self):
        with self.assertRaises(ValueError):
            parse_trust("TRUSTED.REALM:kdc.example.com:secret")

    def test_too_many_parts_raises(self):
        with self.assertRaises(ValueError):
            parse_trust("TRUSTED.REALM:kdc.example.com:secret:one-way:extra")


class TestLoadConfigFromEnv(unittest.TestCase):
    def test_defaults(self):
        config = load_config_from_env({})
        self.assertEqual(config.hostname, "smbserver.smbtest.local")
        self.assertEqual(config.workgroup, "SMBTEST")
        self.assertEqual(config.krb5_realm, "SMBTEST.LOCAL")
        self.assertEqual(config.kdc_host, "kdc")
        self.assertTrue(config.enable_anonymous)
        self.assertTrue(config.enable_ntlm)
        self.assertTrue(config.enable_kerberos)
        self.assertEqual(config.users, [])
        self.assertEqual(config.shares, [])
        self.assertEqual(config.trusts, [])

    def test_custom_hostname(self):
        config = load_config_from_env({"SMB_HOSTNAME": "myserver.mydomain.local"})
        self.assertEqual(config.hostname, "myserver.mydomain.local")

    def test_single_user(self):
        config = load_config_from_env({"SMB_USER_0": "alice:password123"})
        self.assertEqual(len(config.users), 1)
        self.assertEqual(config.users[0].name, "alice")
        self.assertEqual(config.users[0].password, "password123")

    def test_multiple_users_sequential(self):
        config = load_config_from_env({
            "SMB_USER_0": "alice:pass1",
            "SMB_USER_1": "bob:pass2",
            "SMB_USER_2": "charlie:pass3",
        })
        self.assertEqual(len(config.users), 3)
        self.assertEqual(config.users[0].name, "alice")
        self.assertEqual(config.users[1].name, "bob")
        self.assertEqual(config.users[2].name, "charlie")

    def test_users_stop_at_gap(self):
        config = load_config_from_env({
            "SMB_USER_0": "alice:pass1",
            "SMB_USER_2": "charlie:pass3",
        })
        self.assertEqual(len(config.users), 1)

    def test_multiple_shares(self):
        config = load_config_from_env({
            "SMB_SHARE_0": "testshare:/smb-data/testshare:rw",
            "SMB_SHARE_1": "readonly:/smb-data/readonly:ro",
        })
        self.assertEqual(len(config.shares), 2)
        self.assertFalse(config.shares[0].readonly)
        self.assertTrue(config.shares[1].readonly)

    def test_trust_configuration(self):
        config = load_config_from_env({
            "SMB_TRUST_0": "TRUSTED.REALM:kdc.example.com:secret:one-way"
        })
        self.assertEqual(len(config.trusts), 1)
        self.assertEqual(config.trusts[0].realm, "TRUSTED.REALM")

    def test_disable_anonymous(self):
        config = load_config_from_env({"SMB_ENABLE_ANONYMOUS": "false"})
        self.assertFalse(config.enable_anonymous)

    def test_disable_ntlm(self):
        config = load_config_from_env({"SMB_ENABLE_NTLM": "false"})
        self.assertFalse(config.enable_ntlm)

    def test_disable_kerberos(self):
        config = load_config_from_env({"SMB_ENABLE_KERBEROS": "false"})
        self.assertFalse(config.enable_kerberos)

    def test_empty_string_user_stops_loading(self):
        config = load_config_from_env({"SMB_USER_0": ""})
        self.assertEqual(config.users, [])

    def test_empty_string_share_stops_loading(self):
        config = load_config_from_env({"SMB_SHARE_0": ""})
        self.assertEqual(config.shares, [])

    def test_empty_string_trust_stops_loading(self):
        config = load_config_from_env({"SMB_TRUST_0": ""})
        self.assertEqual(config.trusts, [])

    def test_bool_case_insensitive(self):
        self.assertFalse(load_config_from_env({"SMB_ENABLE_ANONYMOUS": "False"}).enable_anonymous)
        self.assertFalse(load_config_from_env({"SMB_ENABLE_ANONYMOUS": "FALSE"}).enable_anonymous)
        self.assertTrue(load_config_from_env({"SMB_ENABLE_ANONYMOUS": "TRUE"}).enable_anonymous)
        self.assertTrue(load_config_from_env({"SMB_ENABLE_ANONYMOUS": "True"}).enable_anonymous)


class TestGenerateSmbConf(unittest.TestCase):
    def _cfg(self, **kwargs):
        return SambaConfig(**kwargs)

    def test_global_section_present(self):
        self.assertIn("[global]", generate_smb_conf(self._cfg()))

    def test_smb_protocol_versions(self):
        conf = generate_smb_conf(self._cfg())
        self.assertIn("server min protocol = SMB2", conf)
        self.assertIn("server max protocol = SMB3", conf)

    def test_realm_and_workgroup(self):
        conf = generate_smb_conf(self._cfg(krb5_realm="MYTEST.LOCAL", workgroup="MYTEST"))
        self.assertIn("realm = MYTEST.LOCAL", conf)
        self.assertIn("workgroup = MYTEST", conf)

    def test_netbios_name_derived_from_hostname(self):
        conf = generate_smb_conf(self._cfg(hostname="smbserver.smbtest.local"))
        self.assertIn("netbios name = SMBSERVER", conf)

    def test_netbios_name_uppercased(self):
        conf = generate_smb_conf(self._cfg(hostname="myhost.domain.local"))
        self.assertIn("netbios name = MYHOST", conf)

    def test_netbios_name_truncated_to_15_chars(self):
        conf = generate_smb_conf(self._cfg(hostname="verylonghostname123.domain.local"))
        self.assertIn("netbios name = VERYLONGHOSTNAM", conf)

    def test_ntlm_enabled(self):
        conf = generate_smb_conf(self._cfg(enable_ntlm=True))
        self.assertIn("ntlm auth = ntlmv2-only", conf)

    def test_ntlm_disabled(self):
        conf = generate_smb_conf(self._cfg(enable_ntlm=False))
        self.assertIn("ntlm auth = no", conf)
        self.assertNotIn("ntlmv2-only", conf)

    def test_kerberos_enabled(self):
        conf = generate_smb_conf(self._cfg(enable_kerberos=True))
        self.assertIn("kerberos method = dedicated keytab", conf)
        self.assertIn("dedicated keytab file = /etc/krb5.keytab", conf)

    def test_kerberos_disabled(self):
        conf = generate_smb_conf(self._cfg(enable_kerberos=False))
        self.assertNotIn("kerberos method", conf)
        self.assertNotIn("dedicated keytab file", conf)

    def test_anonymous_enabled(self):
        conf = generate_smb_conf(self._cfg(enable_anonymous=True))
        self.assertIn("map to guest = bad user", conf)

    def test_anonymous_disabled(self):
        conf = generate_smb_conf(self._cfg(enable_anonymous=False))
        self.assertNotIn("map to guest", conf)

    def test_share_rw_stanza(self):
        conf = generate_smb_conf(self._cfg(
            shares=[Share("testshare", "/smb-data/testshare", readonly=False)]
        ))
        self.assertIn("[testshare]", conf)
        self.assertIn("path = /smb-data/testshare", conf)
        self.assertIn("read only = No", conf)

    def test_share_ro_stanza(self):
        conf = generate_smb_conf(self._cfg(
            shares=[Share("readonly", "/smb-data/readonly", readonly=True)]
        ))
        self.assertIn("[readonly]", conf)
        self.assertIn("read only = Yes", conf)

    def test_share_guest_ok_when_anonymous_enabled(self):
        conf = generate_smb_conf(self._cfg(
            enable_anonymous=True,
            shares=[Share("testshare", "/smb-data/testshare", readonly=False)],
        ))
        self.assertIn("guest ok = Yes", conf)

    def test_share_guest_ok_when_anonymous_disabled(self):
        conf = generate_smb_conf(self._cfg(
            enable_anonymous=False,
            shares=[Share("testshare", "/smb-data/testshare", readonly=False)],
        ))
        self.assertIn("guest ok = No", conf)

    def test_multiple_shares(self):
        conf = generate_smb_conf(self._cfg(shares=[
            Share("share1", "/smb-data/share1", readonly=False),
            Share("share2", "/smb-data/share2", readonly=True),
        ]))
        self.assertIn("[share1]", conf)
        self.assertIn("[share2]", conf)

    def test_trust_adds_username_map_script(self):
        conf = generate_smb_conf(self._cfg(
            trusts=[Trust("TRUSTED.REALM", "kdc.example.com", "secret", "one-way")]
        ))
        self.assertIn("username map script", conf)

    def test_username_map_script_always_present(self):
        self.assertIn("username map script", generate_smb_conf(self._cfg()))

    def test_no_printers(self):
        conf = generate_smb_conf(self._cfg())
        self.assertIn("load printers = no", conf)
        self.assertIn("disable spoolss = yes", conf)

    def test_security_user(self):
        self.assertIn("security = user", generate_smb_conf(self._cfg()))


class TestGenerateKrb5ConfSamba(unittest.TestCase):
    def test_default_realm(self):
        conf = generate_krb5_conf(SambaConfig())
        self.assertIn("default_realm = SMBTEST.LOCAL", conf)

    def test_kdc_host(self):
        conf = generate_krb5_conf(SambaConfig(kdc_host="kdc"))
        self.assertIn("kdc = kdc:88", conf)

    def test_custom_kdc_host(self):
        conf = generate_krb5_conf(SambaConfig(kdc_host="mykdc.internal"))
        self.assertIn("kdc = mykdc.internal:88", conf)

    def test_domain_realm_mapping(self):
        conf = generate_krb5_conf(SambaConfig(
            hostname="smbserver.smbtest.local",
            krb5_realm="SMBTEST.LOCAL",
        ))
        self.assertIn(".smbtest.local = SMBTEST.LOCAL", conf)
        self.assertIn("smbtest.local = SMBTEST.LOCAL", conf)

    def test_trust_realm_added_to_realms(self):
        config = SambaConfig(
            trusts=[Trust("TRUSTED.REALM", "kdc.trusted.example.com", "secret", "one-way")]
        )
        conf = generate_krb5_conf(config)
        self.assertIn("TRUSTED.REALM", conf)
        self.assertIn("kdc.trusted.example.com", conf)

    def test_two_way_trust_adds_capaths(self):
        config = SambaConfig(
            krb5_realm="SMBTEST.LOCAL",
            trusts=[Trust("TRUSTED.REALM", "kdc.trusted.example.com", "secret", "two-way")],
        )
        conf = generate_krb5_conf(config)
        self.assertIn("[capaths]", conf)

    def test_one_way_trust_no_capaths(self):
        config = SambaConfig(
            trusts=[Trust("TRUSTED.REALM", "kdc.trusted.example.com", "secret", "one-way")]
        )
        conf = generate_krb5_conf(config)
        self.assertNotIn("[capaths]", conf)

    def test_no_trusts_no_capaths(self):
        self.assertNotIn("[capaths]", generate_krb5_conf(SambaConfig()))

    def test_realms_section_present(self):
        self.assertIn("[realms]", generate_krb5_conf(SambaConfig()))

    def test_domain_realm_section_present(self):
        self.assertIn("[domain_realm]", generate_krb5_conf(SambaConfig()))


if __name__ == "__main__":
    unittest.main()
