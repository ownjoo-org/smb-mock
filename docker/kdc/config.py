from __future__ import annotations

import os
from dataclasses import dataclass, field

KEYTAB_PATH = os.environ.get("KDC_KEYTAB_PATH", "/shared/krb5.keytab")


@dataclass
class KdcPrincipal:
    name: str
    password: str


@dataclass
class KdcTrust:
    realm: str
    kdc_host: str
    shared_secret: str
    direction: str  # "one-way" | "two-way"


@dataclass
class KdcConfig:
    realm: str = "SMBTEST.LOCAL"
    admin_password: str = "adminpass"
    smb_hostname: str = "smbserver.smbtest.local"
    users: list[KdcPrincipal] = field(default_factory=list)
    trusts: list[KdcTrust] = field(default_factory=list)


def _parse_principal(value: str) -> KdcPrincipal:
    name, _, password = value.partition(":")
    if not name or not password:
        raise ValueError(f"Invalid user format: {value!r}. Expected 'name:password'")
    return KdcPrincipal(name=name, password=password)


def _parse_trust(value: str) -> KdcTrust:
    parts = value.split(":")
    if len(parts) != 4:
        raise ValueError(
            f"Invalid trust format: {value!r}. Expected 'realm:kdc_host:secret:one-way|two-way'"
        )
    realm, kdc_host, shared_secret, direction = parts
    if direction not in ("one-way", "two-way"):
        raise ValueError(
            f"Invalid trust direction {direction!r} in: {value!r}"
        )
    return KdcTrust(realm=realm, kdc_host=kdc_host, shared_secret=shared_secret, direction=direction)


def load_config_from_env(env: dict | None = None) -> KdcConfig:
    if env is None:
        env = os.environ

    users: list[KdcPrincipal] = []
    i = 0
    while val := env.get(f"SMB_USER_{i}"):
        users.append(_parse_principal(val))
        i += 1

    trusts: list[KdcTrust] = []
    i = 0
    while val := env.get(f"SMB_TRUST_{i}"):
        trusts.append(_parse_trust(val))
        i += 1

    return KdcConfig(
        realm=env.get("KRB5_REALM", "SMBTEST.LOCAL"),
        admin_password=env.get("KRB5_ADMIN_PASSWORD", "adminpass"),
        smb_hostname=env.get("SMB_HOSTNAME", "smbserver.smbtest.local"),
        users=users,
        trusts=trusts,
    )


def generate_kdc_conf(config: KdcConfig) -> str:
    lines = [
        "[kdcdefaults]",
        "    kdc_ports = 88",
        "    kdc_tcp_ports = 88",
        "",
        "[realms]",
        f"    {config.realm} = {{",
        "        database_name = /var/lib/krb5kdc/principal",
        "        admin_keytab = /etc/krb5kdc/kadm5.keytab",
        "        acl_file = /etc/krb5kdc/kadm5.acl",
        "        key_stash_file = /etc/krb5kdc/stash",
        "        kdc_ports = 88",
        "        max_life = 10h 0m 0s",
        "        max_renewable_life = 7d 0h 0m 0s",
        "        master_key_type = aes256-cts",
        "        supported_enctypes = aes256-cts:normal aes128-cts:normal",
        "    }",
    ]
    return "\n".join(lines) + "\n"


def generate_krb5_conf(config: KdcConfig) -> str:
    parts = config.smb_hostname.split(".")
    domain = ".".join(parts[1:]).lower() if len(parts) > 1 else config.smb_hostname.lower()

    lines = [
        "[libdefaults]",
        f"    default_realm = {config.realm}",
        "    dns_lookup_realm = false",
        "    dns_lookup_kdc = false",
        "    forwardable = true",
        "",
        "[realms]",
        f"    {config.realm} = {{",
        "        kdc = localhost:88",
        "        admin_server = localhost:749",
        "    }",
    ]

    for trust in config.trusts:
        lines += [
            f"    {trust.realm} = {{",
            f"        kdc = {trust.kdc_host}:88",
            "    }",
        ]

    lines += [
        "",
        "[domain_realm]",
        f"    .{domain} = {config.realm}",
        f"    {domain} = {config.realm}",
    ]

    return "\n".join(lines) + "\n"


def generate_kadm5_acl(config: KdcConfig) -> str:
    return f"*/admin@{config.realm}\t*\n"


def get_principal_commands(config: KdcConfig) -> list[str]:
    cmds: list[str] = []

    cmds.append(f"addprinc -pw {config.admin_password} admin/admin@{config.realm}")
    cmds.append(f"addprinc -randkey host/{config.smb_hostname}@{config.realm}")
    cmds.append(f"addprinc -randkey cifs/{config.smb_hostname}@{config.realm}")

    for user in config.users:
        cmds.append(f"addprinc -pw {user.password} {user.name}@{config.realm}")

    for trust in config.trusts:
        cmds.append(f"addprinc -pw {trust.shared_secret} krbtgt/{trust.realm}@{config.realm}")
        if trust.direction == "two-way":
            cmds.append(
                f"addprinc -pw {trust.shared_secret} krbtgt/{config.realm}@{trust.realm}"
            )

    cmds.append(f"ktadd -k {KEYTAB_PATH} cifs/{config.smb_hostname}@{config.realm}")
    cmds.append(f"ktadd -k {KEYTAB_PATH} host/{config.smb_hostname}@{config.realm}")

    return cmds
