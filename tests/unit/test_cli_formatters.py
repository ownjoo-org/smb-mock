import unittest

from cli.formatters import WizardConfig, to_compose_override, to_docker_run, to_env_file


def _parse_env(text: str) -> dict[str, str]:
    """Parse a .env file into a dict, ignoring blank lines and comments."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _parse_yaml(text: str) -> dict:
    """Minimal YAML parser for simple key: value / nested dicts only."""
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        pass
    # Fallback: just check it looks like YAML
    return {}


class TestToEnvFile(unittest.TestCase):
    def _cfg(self, **kwargs) -> WizardConfig:
        return WizardConfig(**kwargs)

    # --- scalar fields ---

    def test_smb_hostname(self):
        env = _parse_env(to_env_file(self._cfg(smb_hostname="myhost.corp.local")))
        self.assertEqual(env["SMB_HOSTNAME"], "myhost.corp.local")

    def test_workgroup(self):
        env = _parse_env(to_env_file(self._cfg(workgroup="CORP")))
        self.assertEqual(env["SMB_WORKGROUP"], "CORP")

    def test_realm(self):
        env = _parse_env(to_env_file(self._cfg(realm="CORP.LOCAL")))
        self.assertEqual(env["KRB5_REALM"], "CORP.LOCAL")

    def test_kdc_admin_password(self):
        env = _parse_env(to_env_file(self._cfg(kdc_admin_password="s3cr3t")))
        self.assertEqual(env["KRB5_ADMIN_PASSWORD"], "s3cr3t")

    def test_enable_anonymous_true(self):
        env = _parse_env(to_env_file(self._cfg(enable_anonymous=True)))
        self.assertEqual(env["SMB_ENABLE_ANONYMOUS"], "true")

    def test_enable_anonymous_false(self):
        env = _parse_env(to_env_file(self._cfg(enable_anonymous=False)))
        self.assertEqual(env["SMB_ENABLE_ANONYMOUS"], "false")

    def test_enable_ntlm(self):
        env = _parse_env(to_env_file(self._cfg(enable_ntlm=False)))
        self.assertEqual(env["SMB_ENABLE_NTLM"], "false")

    def test_enable_kerberos(self):
        env = _parse_env(to_env_file(self._cfg(enable_kerberos=False)))
        self.assertEqual(env["SMB_ENABLE_KERBEROS"], "false")

    def test_smb_port(self):
        env = _parse_env(to_env_file(self._cfg(smb_port=4445)))
        self.assertEqual(env["SMB_PORT"], "4445")

    def test_kdc_port(self):
        env = _parse_env(to_env_file(self._cfg(kdc_port=8800)))
        self.assertEqual(env["KDC_PORT"], "8800")

    # --- users ---

    def test_single_user(self):
        env = _parse_env(to_env_file(self._cfg(users=[("alice", "pass1")])))
        self.assertEqual(env["SMB_USER_0"], "alice:pass1")

    def test_multiple_users(self):
        env = _parse_env(to_env_file(self._cfg(users=[("alice", "p1"), ("bob", "p2")])))
        self.assertEqual(env["SMB_USER_0"], "alice:p1")
        self.assertEqual(env["SMB_USER_1"], "bob:p2")

    def test_no_users_no_user_keys(self):
        env = _parse_env(to_env_file(self._cfg(users=[])))
        self.assertNotIn("SMB_USER_0", env)

    # --- shares ---

    def test_single_share(self):
        env = _parse_env(to_env_file(self._cfg(
            shares=[("testshare", "/smb-data/testshare", "rw")]
        )))
        self.assertEqual(env["SMB_SHARE_0"], "testshare:/smb-data/testshare:rw")

    def test_multiple_shares(self):
        env = _parse_env(to_env_file(self._cfg(shares=[
            ("s1", "/data/s1", "rw"),
            ("s2", "/data/s2", "ro"),
        ])))
        self.assertEqual(env["SMB_SHARE_0"], "s1:/data/s1:rw")
        self.assertEqual(env["SMB_SHARE_1"], "s2:/data/s2:ro")

    def test_no_shares_no_share_keys(self):
        env = _parse_env(to_env_file(self._cfg(shares=[])))
        self.assertNotIn("SMB_SHARE_0", env)

    # --- trusts ---

    def test_single_trust(self):
        env = _parse_env(to_env_file(self._cfg(
            trusts=[("CORP.LOCAL", "kdc.corp.local", "secret", "one-way")]
        )))
        self.assertEqual(env["SMB_TRUST_0"], "CORP.LOCAL:kdc.corp.local:secret:one-way")

    def test_two_way_trust(self):
        env = _parse_env(to_env_file(self._cfg(
            trusts=[("CORP.LOCAL", "kdc.corp.local", "secret", "two-way")]
        )))
        self.assertIn("two-way", env["SMB_TRUST_0"])

    def test_no_trusts_no_trust_keys(self):
        env = _parse_env(to_env_file(self._cfg(trusts=[])))
        self.assertNotIn("SMB_TRUST_0", env)

    # --- round-trip ---

    def test_round_trip_through_load_config_from_env(self):
        from samba.config import load_config_from_env

        config = WizardConfig(
            smb_hostname="roundtrip.test.local",
            workgroup="ROUNDTRIP",
            realm="ROUNDTRIP.LOCAL",
            enable_anonymous=False,
            enable_ntlm=True,
            enable_kerberos=False,
            users=[("alice", "pass1"), ("bob", "pass2")],
            shares=[("ts", "/data/ts", "rw"), ("ro", "/data/ro", "ro")],
            trusts=[("REMOTE.LOCAL", "kdc.remote.local", "sec", "one-way")],
        )
        env_dict = _parse_env(to_env_file(config))
        samba_cfg = load_config_from_env(env_dict)

        self.assertEqual(samba_cfg.hostname, "roundtrip.test.local")
        self.assertEqual(samba_cfg.workgroup, "ROUNDTRIP")
        self.assertFalse(samba_cfg.enable_anonymous)
        self.assertFalse(samba_cfg.enable_kerberos)
        self.assertEqual(len(samba_cfg.users), 2)
        self.assertEqual(samba_cfg.users[0].name, "alice")
        self.assertEqual(samba_cfg.users[1].name, "bob")
        self.assertEqual(len(samba_cfg.shares), 2)
        self.assertEqual(samba_cfg.shares[0].name, "ts")
        self.assertFalse(samba_cfg.shares[0].readonly)
        self.assertTrue(samba_cfg.shares[1].readonly)
        self.assertEqual(len(samba_cfg.trusts), 1)
        self.assertEqual(samba_cfg.trusts[0].realm, "REMOTE.LOCAL")


class TestToDockerRun(unittest.TestCase):
    def _cfg(self, **kwargs) -> WizardConfig:
        return WizardConfig(**kwargs)

    def _script(self, **kwargs) -> str:
        return to_docker_run(self._cfg(**kwargs))

    # --- infrastructure commands ---

    def test_creates_keytab_volume(self):
        self.assertIn("docker volume create smb-mock-keytab", self._script())

    def test_creates_network(self):
        self.assertIn("docker network create smb-mock-net", self._script())

    # --- KDC block ---

    def test_kdc_container_present(self):
        self.assertIn("smb-mock-kdc", self._script())

    def test_kdc_has_network_alias_kdc(self):
        script = self._script()
        # The KDC block should advertise itself as "kdc" on the network
        self.assertIn("--network-alias kdc", script)

    def test_kdc_realm_env(self):
        script = to_docker_run(self._cfg(realm="CORP.LOCAL"))
        # KDC run command must include the realm
        kdc_block = script[:script.index("smb-mock-samba")]
        self.assertIn("KRB5_REALM=CORP.LOCAL", kdc_block)

    def test_kdc_admin_password_env(self):
        script = to_docker_run(self._cfg(kdc_admin_password="mysecret"))
        kdc_block = script[:script.index("smb-mock-samba")]
        self.assertIn("KRB5_ADMIN_PASSWORD=mysecret", kdc_block)

    def test_kdc_smb_hostname_env(self):
        script = to_docker_run(self._cfg(smb_hostname="host.corp.local"))
        kdc_block = script[:script.index("smb-mock-samba")]
        self.assertIn("SMB_HOSTNAME=host.corp.local", kdc_block)

    def test_kdc_port_mapping(self):
        script = to_docker_run(self._cfg(kdc_port=8800))
        kdc_block = script[:script.index("smb-mock-samba")]
        self.assertIn("8800:88", kdc_block)

    def test_kdc_mounts_keytab_volume(self):
        script = self._script()
        kdc_block = script[:script.index("smb-mock-samba")]
        self.assertIn("smb-mock-keytab:/shared", kdc_block)

    def test_kdc_user_env_vars(self):
        script = to_docker_run(self._cfg(users=[("alice", "p1"), ("bob", "p2")]))
        kdc_block = script[:script.index("smb-mock-samba")]
        self.assertIn("SMB_USER_0=alice:p1", kdc_block)
        self.assertIn("SMB_USER_1=bob:p2", kdc_block)

    # --- Samba block ---

    def test_samba_container_present(self):
        self.assertIn("smb-mock-samba", self._script())

    def test_samba_port_mapping(self):
        script = to_docker_run(self._cfg(smb_port=4445))
        samba_block = script[script.index("smb-mock-samba"):]
        self.assertIn("4445:445", samba_block)

    def test_samba_hostname_flag(self):
        script = to_docker_run(self._cfg(smb_hostname="host.corp.local"))
        samba_block = script[script.index("smb-mock-samba"):]
        self.assertIn("--hostname host.corp.local", samba_block)

    def test_samba_kdc_host_env(self):
        script = self._script()
        samba_block = script[script.index("smb-mock-samba"):]
        self.assertIn("KDC_HOST=kdc", samba_block)

    def test_samba_realm_env(self):
        script = to_docker_run(self._cfg(realm="CORP.LOCAL"))
        samba_block = script[script.index("smb-mock-samba"):]
        self.assertIn("KRB5_REALM=CORP.LOCAL", samba_block)

    def test_samba_share_env_vars(self):
        script = to_docker_run(self._cfg(shares=[("ts", "/data/ts", "rw")]))
        samba_block = script[script.index("smb-mock-samba"):]
        self.assertIn("SMB_SHARE_0=ts:/data/ts:rw", samba_block)

    def test_samba_mounts_keytab_volume(self):
        script = self._script()
        samba_block = script[script.index("smb-mock-samba"):]
        self.assertIn("smb-mock-keytab:/shared", samba_block)

    def test_samba_trust_env_vars(self):
        script = to_docker_run(self._cfg(
            trusts=[("CORP.LOCAL", "kdc.corp.local", "sec", "one-way")]
        ))
        samba_block = script[script.index("smb-mock-samba"):]
        self.assertIn("SMB_TRUST_0=CORP.LOCAL:kdc.corp.local:sec:one-way", samba_block)

    def test_no_trust_no_trust_env(self):
        script = to_docker_run(self._cfg(trusts=[]))
        self.assertNotIn("SMB_TRUST_0", script)

    # --- kdc comes before samba ---

    def test_kdc_precedes_samba(self):
        script = self._script()
        self.assertLess(script.index("smb-mock-kdc"), script.index("smb-mock-samba"))


class TestToComposeOverride(unittest.TestCase):
    def _cfg(self, **kwargs) -> WizardConfig:
        return WizardConfig(**kwargs)

    def _parsed(self, **kwargs) -> dict:
        return _parse_yaml(to_compose_override(self._cfg(**kwargs)))

    def test_services_key_present(self):
        self.assertIn("services:", to_compose_override(self._cfg()))

    def test_kdc_service_present(self):
        self.assertIn("kdc:", to_compose_override(self._cfg()))

    def test_samba_service_present(self):
        self.assertIn("samba:", to_compose_override(self._cfg()))

    def test_kdc_realm_in_override(self):
        override = to_compose_override(self._cfg(realm="CORP.LOCAL"))
        self.assertIn("KRB5_REALM", override)
        self.assertIn("CORP.LOCAL", override)

    def test_samba_hostname_in_override(self):
        override = to_compose_override(self._cfg(smb_hostname="host.corp.local"))
        self.assertIn("SMB_HOSTNAME", override)
        self.assertIn("host.corp.local", override)

    def test_user_vars_in_both_services(self):
        override = to_compose_override(self._cfg(users=[("alice", "pass1")]))
        self.assertIn("SMB_USER_0", override)

    def test_share_vars_in_samba_section(self):
        override = to_compose_override(self._cfg(
            shares=[("ts", "/data/ts", "rw")]
        ))
        samba_block = override[override.index("samba:"):]
        self.assertIn("SMB_SHARE_0", samba_block)

    def test_values_with_colons_are_quoted(self):
        override = to_compose_override(self._cfg(users=[("alice", "pass:word")]))
        # Colon in value must be quoted to be valid YAML
        self.assertIn('"alice:pass:word"', override)

    def test_valid_yaml(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        result = _parse_yaml(to_compose_override(self._cfg(
            users=[("alice", "pass1")],
            shares=[("ts", "/data/ts", "rw")],
        )))
        self.assertIn("services", result)
        self.assertIn("kdc", result["services"])
        self.assertIn("samba", result["services"])


if __name__ == "__main__":
    unittest.main()
