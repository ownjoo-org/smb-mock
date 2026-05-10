import unittest

from kdc.config import (
    KdcPrincipal,
    KdcTrust,
    KdcConfig,
    load_config_from_env,
    generate_kdc_conf,
    generate_krb5_conf,
    generate_kadm5_acl,
    get_principal_commands,
    KEYTAB_PATH,
)


class TestKeytabPath(unittest.TestCase):
    def test_default_keytab_path(self):
        import kdc.config as kdc_config
        import importlib, os
        env_backup = os.environ.pop("KDC_KEYTAB_PATH", None)
        try:
            importlib.reload(kdc_config)
            self.assertEqual(kdc_config.KEYTAB_PATH, "/shared/krb5.keytab")
        finally:
            if env_backup is not None:
                os.environ["KDC_KEYTAB_PATH"] = env_backup
            importlib.reload(kdc_config)

    def test_custom_keytab_path_from_env(self):
        import kdc.config as kdc_config
        import importlib, os
        os.environ["KDC_KEYTAB_PATH"] = "/tmp/custom.keytab"
        try:
            importlib.reload(kdc_config)
            self.assertEqual(kdc_config.KEYTAB_PATH, "/tmp/custom.keytab")
        finally:
            del os.environ["KDC_KEYTAB_PATH"]
            importlib.reload(kdc_config)


class TestKdcLoadConfigFromEnv(unittest.TestCase):
    def test_defaults(self):
        config = load_config_from_env({})
        self.assertEqual(config.realm, "SMBTEST.LOCAL")
        self.assertEqual(config.admin_password, "adminpass")
        self.assertEqual(config.smb_hostname, "smbserver.smbtest.local")
        self.assertEqual(config.users, [])
        self.assertEqual(config.trusts, [])

    def test_custom_realm(self):
        config = load_config_from_env({"KRB5_REALM": "CUSTOM.REALM"})
        self.assertEqual(config.realm, "CUSTOM.REALM")

    def test_custom_admin_password(self):
        config = load_config_from_env({"KRB5_ADMIN_PASSWORD": "supersecret"})
        self.assertEqual(config.admin_password, "supersecret")

    def test_custom_smb_hostname(self):
        config = load_config_from_env({"SMB_HOSTNAME": "myhost.corp.local"})
        self.assertEqual(config.smb_hostname, "myhost.corp.local")

    def test_users_from_env(self):
        config = load_config_from_env({
            "SMB_USER_0": "alice:password123",
            "SMB_USER_1": "bob:hunter2",
        })
        self.assertEqual(len(config.users), 2)
        self.assertEqual(config.users[0].name, "alice")
        self.assertEqual(config.users[0].password, "password123")
        self.assertEqual(config.users[1].name, "bob")

    def test_users_stop_at_gap(self):
        config = load_config_from_env({
            "SMB_USER_0": "alice:pass1",
            "SMB_USER_2": "charlie:pass3",
        })
        self.assertEqual(len(config.users), 1)

    def test_trusts_from_env(self):
        config = load_config_from_env({
            "SMB_TRUST_0": "TRUSTED.REALM:kdc.example.com:secret:one-way"
        })
        self.assertEqual(len(config.trusts), 1)
        self.assertEqual(config.trusts[0].realm, "TRUSTED.REALM")
        self.assertEqual(config.trusts[0].kdc_host, "kdc.example.com")
        self.assertEqual(config.trusts[0].shared_secret, "secret")
        self.assertEqual(config.trusts[0].direction, "one-way")

    def test_empty_string_user_stops_loading(self):
        config = load_config_from_env({"SMB_USER_0": ""})
        self.assertEqual(config.users, [])

    def test_empty_string_trust_stops_loading(self):
        config = load_config_from_env({"SMB_TRUST_0": ""})
        self.assertEqual(config.trusts, [])

    def test_multiple_trusts(self):
        config = load_config_from_env({
            "SMB_TRUST_0": "REALM1.LOCAL:kdc1.example.com:secret1:one-way",
            "SMB_TRUST_1": "REALM2.LOCAL:kdc2.example.com:secret2:two-way",
        })
        self.assertEqual(len(config.trusts), 2)


class TestGenerateKdcConf(unittest.TestCase):
    def test_realm_present(self):
        conf = generate_kdc_conf(KdcConfig(realm="SMBTEST.LOCAL"))
        self.assertIn("SMBTEST.LOCAL", conf)

    def test_kdc_port(self):
        conf = generate_kdc_conf(KdcConfig())
        self.assertIn("kdc_ports = 88", conf)

    def test_database_path(self):
        conf = generate_kdc_conf(KdcConfig())
        self.assertIn("database_name", conf)
        self.assertIn("/var/lib/krb5kdc/principal", conf)

    def test_aes256_enctype(self):
        conf = generate_kdc_conf(KdcConfig())
        self.assertIn("aes256-cts", conf)

    def test_aes128_enctype(self):
        conf = generate_kdc_conf(KdcConfig())
        self.assertIn("aes128-cts", conf)

    def test_realms_section_present(self):
        conf = generate_kdc_conf(KdcConfig())
        self.assertIn("[realms]", conf)

    def test_kdcdefaults_section_present(self):
        conf = generate_kdc_conf(KdcConfig())
        self.assertIn("[kdcdefaults]", conf)


class TestGenerateKrb5ConfKdc(unittest.TestCase):
    def test_default_realm(self):
        conf = generate_krb5_conf(KdcConfig())
        self.assertIn("default_realm = SMBTEST.LOCAL", conf)

    def test_kdc_is_localhost(self):
        conf = generate_krb5_conf(KdcConfig())
        self.assertIn("kdc = localhost:88", conf)

    def test_domain_realm_from_smb_hostname(self):
        conf = generate_krb5_conf(KdcConfig(
            realm="SMBTEST.LOCAL",
            smb_hostname="smbserver.smbtest.local",
        ))
        self.assertIn(".smbtest.local = SMBTEST.LOCAL", conf)
        self.assertIn("smbtest.local = SMBTEST.LOCAL", conf)

    def test_trust_realm_in_krb5_conf(self):
        config = KdcConfig(
            trusts=[KdcTrust("TRUSTED.REALM", "kdc.trusted.example.com", "secret", "one-way")]
        )
        conf = generate_krb5_conf(config)
        self.assertIn("TRUSTED.REALM", conf)
        self.assertIn("kdc.trusted.example.com", conf)

    def test_realms_section_present(self):
        self.assertIn("[realms]", generate_krb5_conf(KdcConfig()))

    def test_domain_realm_section_present(self):
        self.assertIn("[domain_realm]", generate_krb5_conf(KdcConfig()))


class TestGenerateKadm5Acl(unittest.TestCase):
    def test_admin_wildcard_has_all_permissions(self):
        acl = generate_kadm5_acl(KdcConfig(realm="SMBTEST.LOCAL"))
        self.assertIn("*/admin@SMBTEST.LOCAL", acl)

    def test_admin_granted_all_operations(self):
        acl = generate_kadm5_acl(KdcConfig(realm="SMBTEST.LOCAL"))
        # The permission field should be '*' (all operations)
        line = next(l for l in acl.splitlines() if "admin@SMBTEST.LOCAL" in l)
        self.assertIn("*", line)

    def test_custom_realm_in_acl(self):
        acl = generate_kadm5_acl(KdcConfig(realm="CORP.EXAMPLE.COM"))
        self.assertIn("CORP.EXAMPLE.COM", acl)


class TestGetPrincipalCommands(unittest.TestCase):
    def _cmds(self, **kwargs):
        return get_principal_commands(KdcConfig(**kwargs))

    def test_admin_principal_created(self):
        cmds = self._cmds(realm="SMBTEST.LOCAL", admin_password="adminpass")
        self.assertTrue(any("admin/admin@SMBTEST.LOCAL" in c for c in cmds))
        self.assertTrue(any("adminpass" in c for c in cmds))

    def test_cifs_principal_created(self):
        cmds = self._cmds(realm="SMBTEST.LOCAL", smb_hostname="smbserver.smbtest.local")
        self.assertTrue(any("cifs/smbserver.smbtest.local@SMBTEST.LOCAL" in c for c in cmds))

    def test_host_principal_created(self):
        cmds = self._cmds(realm="SMBTEST.LOCAL", smb_hostname="smbserver.smbtest.local")
        self.assertTrue(any("host/smbserver.smbtest.local@SMBTEST.LOCAL" in c for c in cmds))

    def test_cifs_and_host_use_randkey(self):
        cmds = self._cmds(realm="SMBTEST.LOCAL", smb_hostname="smbserver.smbtest.local")
        cifs_cmd = next(c for c in cmds if "cifs/smbserver.smbtest.local@SMBTEST.LOCAL" in c)
        host_cmd = next(c for c in cmds if "host/smbserver.smbtest.local@SMBTEST.LOCAL" in c)
        self.assertIn("-randkey", cifs_cmd)
        self.assertIn("-randkey", host_cmd)

    def test_user_principal_created(self):
        config = KdcConfig(
            realm="SMBTEST.LOCAL",
            users=[KdcPrincipal("alice", "password123")],
        )
        cmds = get_principal_commands(config)
        self.assertTrue(any("alice@SMBTEST.LOCAL" in c for c in cmds))
        self.assertTrue(any("password123" in c for c in cmds))

    def test_multiple_user_principals(self):
        config = KdcConfig(
            realm="SMBTEST.LOCAL",
            users=[
                KdcPrincipal("alice", "pass1"),
                KdcPrincipal("bob", "pass2"),
            ],
        )
        cmds = get_principal_commands(config)
        self.assertTrue(any("alice@SMBTEST.LOCAL" in c for c in cmds))
        self.assertTrue(any("bob@SMBTEST.LOCAL" in c for c in cmds))

    def test_one_way_trust_creates_inbound_principal(self):
        config = KdcConfig(
            realm="SMBTEST.LOCAL",
            trusts=[KdcTrust("TRUSTED.REALM", "kdc.example.com", "sharedsecret", "one-way")],
        )
        cmds = get_principal_commands(config)
        self.assertTrue(any("krbtgt/TRUSTED.REALM@SMBTEST.LOCAL" in c for c in cmds))

    def test_one_way_trust_does_not_create_outbound_principal(self):
        config = KdcConfig(
            realm="SMBTEST.LOCAL",
            trusts=[KdcTrust("TRUSTED.REALM", "kdc.example.com", "sharedsecret", "one-way")],
        )
        cmds = get_principal_commands(config)
        self.assertFalse(any("krbtgt/SMBTEST.LOCAL@TRUSTED.REALM" in c for c in cmds))

    def test_two_way_trust_creates_both_principals(self):
        config = KdcConfig(
            realm="SMBTEST.LOCAL",
            trusts=[KdcTrust("TRUSTED.REALM", "kdc.example.com", "sharedsecret", "two-way")],
        )
        cmds = get_principal_commands(config)
        self.assertTrue(any("krbtgt/TRUSTED.REALM@SMBTEST.LOCAL" in c for c in cmds))
        self.assertTrue(any("krbtgt/SMBTEST.LOCAL@TRUSTED.REALM" in c for c in cmds))

    def test_trust_principal_uses_shared_secret(self):
        config = KdcConfig(
            realm="SMBTEST.LOCAL",
            trusts=[KdcTrust("TRUSTED.REALM", "kdc.example.com", "mysecret", "one-way")],
        )
        cmds = get_principal_commands(config)
        trust_cmd = next(c for c in cmds if "krbtgt/TRUSTED.REALM@SMBTEST.LOCAL" in c)
        self.assertIn("mysecret", trust_cmd)

    def test_keytab_extracted_for_cifs(self):
        cmds = self._cmds(realm="SMBTEST.LOCAL", smb_hostname="smbserver.smbtest.local")
        self.assertTrue(any(
            "cifs/smbserver.smbtest.local@SMBTEST.LOCAL" in c and KEYTAB_PATH in c
            for c in cmds
        ))

    def test_keytab_extracted_for_host(self):
        cmds = self._cmds(realm="SMBTEST.LOCAL", smb_hostname="smbserver.smbtest.local")
        self.assertTrue(any(
            "host/smbserver.smbtest.local@SMBTEST.LOCAL" in c and KEYTAB_PATH in c
            for c in cmds
        ))

    def test_keytab_commands_use_ktadd(self):
        cmds = self._cmds(realm="SMBTEST.LOCAL", smb_hostname="smbserver.smbtest.local")
        keytab_cmds = [c for c in cmds if KEYTAB_PATH in c]
        self.assertTrue(all("ktadd" in c for c in keytab_cmds))

    def test_no_users_no_extra_principals(self):
        config = KdcConfig(realm="SMBTEST.LOCAL", users=[])
        cmds = get_principal_commands(config)
        user_cmds = [
            c for c in cmds
            if "addprinc" in c
            and "admin/admin" not in c
            and "cifs/" not in c
            and "host/" not in c
        ]
        self.assertEqual(user_cmds, [])


if __name__ == "__main__":
    unittest.main()
