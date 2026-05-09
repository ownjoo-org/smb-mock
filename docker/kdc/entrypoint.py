#!/usr/bin/env python3
"""KDC container entrypoint.

Writes Kerberos config files, initialises the principal database,
creates all required principals and exports the Samba service keytab,
then execs krb5kdc in the foreground (PID 1).
"""
import os
import subprocess
import sys

from config import (
    KEYTAB_PATH,
    KdcConfig,
    generate_kadm5_acl,
    generate_kdc_conf,
    generate_krb5_conf,
    get_principal_commands,
    load_config_from_env,
)

KRB5_CONF = "/etc/krb5.conf"
KDC_CONF = "/etc/krb5kdc/kdc.conf"
KADM5_ACL = "/etc/krb5kdc/kadm5.acl"


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    print(f"  wrote {path}", flush=True)


def _run(args: list[str], **kwargs) -> None:
    safe = " ".join(
        "***" if prev in ("-pw", "-P") else a
        for prev, a in zip([""] + args, args)
    )
    print(f"+ {safe}", flush=True)
    subprocess.run(args, check=True, **kwargs)


def _kadmin(cmd: str) -> None:
    # Mask passwords from log output
    verb = cmd.split()[0]
    display = cmd if verb in ("ktadd", "listprincs") else f"{verb} ***"
    print(f"  kadmin.local: {display}", flush=True)
    _run(["kadmin.local", "-q", cmd])


def main() -> None:
    print("==> smb-mock KDC starting", flush=True)
    config: KdcConfig = load_config_from_env()

    print(f"    realm       : {config.realm}", flush=True)
    print(f"    smb_hostname: {config.smb_hostname}", flush=True)
    print(f"    users       : {[u.name for u in config.users]}", flush=True)
    print(f"    trusts      : {[t.realm for t in config.trusts]}", flush=True)

    print("\n==> Writing config files", flush=True)
    _write(KRB5_CONF, generate_krb5_conf(config))
    _write(KDC_CONF, generate_kdc_conf(config))
    _write(KADM5_ACL, generate_kadm5_acl(config))

    os.makedirs("/var/lib/krb5kdc", exist_ok=True)
    os.makedirs(os.path.dirname(KEYTAB_PATH), exist_ok=True)

    print(f"\n==> Initialising KDC database (realm: {config.realm})", flush=True)
    _run([
        "kdb5_util", "create",
        "-s",
        "-P", config.admin_password,
        "-r", config.realm,
    ])

    print("\n==> Creating principals", flush=True)
    for cmd in get_principal_commands(config):
        _kadmin(cmd)

    print(f"\n==> Keytab written to {KEYTAB_PATH}", flush=True)

    print("\n==> Starting kadmind (background)", flush=True)
    subprocess.Popen(["kadmind", "-nofork"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    print("==> Exec krb5kdc (foreground / PID 1)", flush=True)
    os.execvp("krb5kdc", ["krb5kdc", "-n"])


if __name__ == "__main__":
    main()
