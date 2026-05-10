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
    # Protocol
    min_protocol: str = "SMB2"
    max_protocol: str = "SMB3"
    # Signing — None means derive from enable_anonymous (auto/mandatory)
    server_signing: str | None = None
    # Auth — None means derive from enable_ntlm (ntlmv2-only/no)
    ntlm_auth: str | None = None
    # Share defaults
    browseable: bool = False
    create_mask: str = "0664"
    dir_mask: str = "0775"
    # Logging
    log_level: int = 0
    max_log_size: int = 50
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
        min_protocol=env.get("SMB_MIN_PROTOCOL", "SMB2"),
        max_protocol=env.get("SMB_MAX_PROTOCOL", "SMB3"),
        server_signing=env.get("SMB_SERVER_SIGNING") or None,
        ntlm_auth=env.get("SMB_NTLM_AUTH") or None,
        browseable=_parse_bool(env.get("SMB_BROWSEABLE", "false")),
        create_mask=env.get("SMB_CREATE_MASK", "0664"),
        dir_mask=env.get("SMB_DIR_MASK", "0775"),
        log_level=int(env.get("SMB_LOG_LEVEL", "0")),
        max_log_size=int(env.get("SMB_MAX_LOG_SIZE", "50")),
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

    # Auth: explicit override takes priority; otherwise derive from enable_ntlm
    ntlm = config.ntlm_auth if config.ntlm_auth is not None else (
        "ntlmv2-only" if config.enable_ntlm else "no"
    )

    # Signing: explicit override takes priority; otherwise derive from enable_anonymous.
    # mandatory when no anonymous access (prevents MITM downgrade);
    # auto when anonymous is enabled (guest sessions cannot sign).
    signing = config.server_signing if config.server_signing is not None else (
        "auto" if config.enable_anonymous else "mandatory"
    )

    browseable = "Yes" if config.browseable else "No"

    lines = [
        "[global]",
        f"    netbios name = {netbios}",
        "    server string =",          # blank — do not leak software identity
        f"    workgroup = {config.workgroup}",
        f"    realm = {config.krb5_realm}",
        "",
        f"    server min protocol = {config.min_protocol}",
        f"    server max protocol = {config.max_protocol}",
        f"    server signing = {signing}",
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
    else:
        # Refuse unauthenticated info queries (workgroup, NetBIOS name lookups)
        lines += [
            "",
            "    restrict anonymous = 2",
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
        f"    log level = {config.log_level}",
        "    log file = /var/log/samba/log.%m",
        f"    max log size = {config.max_log_size}",
    ]

    user_names = [u.name for u in config.users] if config.users else None

    for share in config.shares:
        read_only = "Yes" if share.readonly else "No"
        guest_ok = "Yes" if config.enable_anonymous else "No"
        lines += [
            "",
            f"[{share.name}]",
            f"    path = {share.path}",
            f"    read only = {read_only}",
            f"    browseable = {browseable}",
            f"    guest ok = {guest_ok}",
            f"    create mask = {config.create_mask}",
            f"    directory mask = {config.dir_mask}",
        ]
        # Restrict non-public shares to explicitly provisioned users
        if not config.enable_anonymous and user_names:
            lines.append(f"    valid users = {' '.join(user_names)}")

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
