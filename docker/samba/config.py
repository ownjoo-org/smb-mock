from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class User:
    name: str
    password: str


@dataclass
class Share:
    name: str
    path: str
    readonly: bool


@dataclass
class Trust:
    realm: str
    kdc_host: str
    shared_secret: str
    direction: str  # "one-way" | "two-way"


@dataclass
class SambaConfig:
    hostname: str = "smbserver.smbtest.local"
    workgroup: str = "SMBTEST"
    krb5_realm: str = "SMBTEST.LOCAL"
    kdc_host: str = "kdc"
    enable_anonymous: bool = True
    enable_ntlm: bool = True
    enable_kerberos: bool = True
    users: list[User] = field(default_factory=list)
    shares: list[Share] = field(default_factory=list)
    trusts: list[Trust] = field(default_factory=list)


def parse_user(value: str) -> User:
    name, _, password = value.partition(":")
    if not name or not password:
        raise ValueError(f"Invalid user format: {value!r}. Expected 'name:password'")
    return User(name=name, password=password)


def parse_share(value: str) -> Share:
    parts = value.split(":")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid share format: {value!r}. Expected 'name:path:rw|ro'"
        )
    name, path, mode = parts
    if not name:
        raise ValueError(f"Share name must not be empty in: {value!r}")
    if not path:
        raise ValueError(f"Share path must not be empty in: {value!r}")
    if mode not in ("rw", "ro"):
        raise ValueError(f"Invalid share mode {mode!r} in: {value!r}. Expected 'rw' or 'ro'")
    return Share(name=name, path=path, readonly=(mode == "ro"))


def parse_trust(value: str) -> Trust:
    parts = value.split(":")
    if len(parts) != 4:
        raise ValueError(
            f"Invalid trust format: {value!r}. Expected 'realm:kdc_host:secret:one-way|two-way'"
        )
    realm, kdc_host, shared_secret, direction = parts
    if direction not in ("one-way", "two-way"):
        raise ValueError(
            f"Invalid trust direction {direction!r} in: {value!r}. Expected 'one-way' or 'two-way'"
        )
    return Trust(realm=realm, kdc_host=kdc_host, shared_secret=shared_secret, direction=direction)


def _parse_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def load_config_from_env(env: dict | None = None) -> SambaConfig:
    if env is None:
        env = os.environ

    users: list[User] = []
    i = 0
    while val := env.get(f"SMB_USER_{i}"):
        users.append(parse_user(val))
        i += 1

    shares: list[Share] = []
    i = 0
    while val := env.get(f"SMB_SHARE_{i}"):
        shares.append(parse_share(val))
        i += 1

    trusts: list[Trust] = []
    i = 0
    while val := env.get(f"SMB_TRUST_{i}"):
        trusts.append(parse_trust(val))
        i += 1

    return SambaConfig(
        hostname=env.get("SMB_HOSTNAME", "smbserver.smbtest.local"),
        workgroup=env.get("SMB_WORKGROUP", "SMBTEST"),
        krb5_realm=env.get("KRB5_REALM", "SMBTEST.LOCAL"),
        kdc_host=env.get("KDC_HOST", "kdc"),
        enable_anonymous=_parse_bool(env.get("SMB_ENABLE_ANONYMOUS", "true")),
        enable_ntlm=_parse_bool(env.get("SMB_ENABLE_NTLM", "true")),
        enable_kerberos=_parse_bool(env.get("SMB_ENABLE_KERBEROS", "true")),
        users=users,
        shares=shares,
        trusts=trusts,
    )


def _netbios_name(hostname: str) -> str:
    return hostname.split(".")[0].upper()[:15]


def _domain_from_hostname(hostname: str) -> str:
    parts = hostname.split(".")
    return ".".join(parts[1:]).lower() if len(parts) > 1 else hostname.lower()


def generate_smb_conf(config: SambaConfig) -> str:
    netbios = _netbios_name(config.hostname)
    ntlm = "ntlmv2-only" if config.enable_ntlm else "no"

    lines = [
        "[global]",
        f"    netbios name = {netbios}",
        "    server string = SMB Mock Server",
        f"    workgroup = {config.workgroup}",
        f"    realm = {config.krb5_realm}",
        "",
        "    server min protocol = SMB2",
        "    server max protocol = SMB3",
        "",
        "    security = user",
        f"    ntlm auth = {ntlm}",
    ]

    if config.enable_kerberos:
        lines += [
            "",
            "    kerberos method = dedicated keytab",
            "    dedicated keytab file = /etc/krb5.keytab",
        ]

    if config.enable_anonymous:
        lines += [
            "",
            "    map to guest = bad user",
            "    guest account = nobody",
        ]

    lines += [
        "",
        "    username map script = /etc/samba/username_map.sh",
    ]

    lines += [
        "",
        "    load printers = no",
        "    printcap name = /dev/null",
        "    disable spoolss = yes",
        "",
        "    log level = 1",
        "    log file = /var/log/samba/log.%m",
        "    max log size = 50",
    ]

    for share in config.shares:
        read_only = "Yes" if share.readonly else "No"
        guest_ok = "Yes" if config.enable_anonymous else "No"
        lines += [
            "",
            f"[{share.name}]",
            f"    path = {share.path}",
            f"    read only = {read_only}",
            "    browseable = Yes",
            f"    guest ok = {guest_ok}",
            "    create mask = 0664",
            "    directory mask = 0775",
        ]

    return "\n".join(lines) + "\n"


def generate_krb5_conf(config: SambaConfig) -> str:
    domain = _domain_from_hostname(config.hostname)

    lines = [
        "[libdefaults]",
        f"    default_realm = {config.krb5_realm}",
        "    dns_lookup_realm = false",
        "    dns_lookup_kdc = false",
        "    forwardable = true",
        "",
        "[realms]",
        f"    {config.krb5_realm} = {{",
        f"        kdc = {config.kdc_host}:88",
        f"        admin_server = {config.kdc_host}:749",
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
        f"    .{domain} = {config.krb5_realm}",
        f"    {domain} = {config.krb5_realm}",
    ]

    two_way = [t for t in config.trusts if t.direction == "two-way"]
    if two_way:
        lines += ["", "[capaths]"]
        for trust in two_way:
            lines += [
                f"    {config.krb5_realm} = {{",
                f"        {trust.realm} = .",
                "    }",
                f"    {trust.realm} = {{",
                f"        {config.krb5_realm} = .",
                "    }",
            ]

    return "\n".join(lines) + "\n"
