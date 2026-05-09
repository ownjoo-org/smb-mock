#!/usr/bin/env python3
"""Samba container entrypoint.

Writes smb.conf + krb5.conf, creates Linux users, sets Samba passwords,
waits for the KDC keytab (when Kerberos is enabled), then execs smbd
in the foreground (PID 1).
"""
import os
import shutil
import subprocess
import sys
import time

from config import (
    SambaConfig,
    generate_krb5_conf,
    generate_smb_conf,
    load_config_from_env,
)

SMB_CONF = "/etc/samba/smb.conf"
KRB5_CONF = "/etc/krb5.conf"
KEYTAB_SRC = "/shared/krb5.keytab"
KEYTAB_DST = "/etc/krb5.keytab"
USERNAME_MAP_SCRIPT = "/etc/samba/username_map.sh"
KEYTAB_WAIT_SECONDS = 120


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    print(f"  wrote {path}", flush=True)


def _run(args: list[str], **kwargs) -> None:
    print(f"+ {' '.join(args)}", flush=True)
    subprocess.run(args, check=True, **kwargs)


def _wait_for_file(path: str, timeout: int = KEYTAB_WAIT_SECONDS) -> None:
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise TimeoutError(
                f"Timed out after {timeout}s waiting for {path}. "
                "Is the KDC container running?"
            )
        print(f"  waiting for {path} ...", flush=True)
        time.sleep(2)


def _create_user(name: str, password: str) -> None:
    if subprocess.run(["id", name], capture_output=True).returncode != 0:
        _run(["adduser", "-D", "-H", "-s", "/bin/false", name])

    proc = subprocess.run(
        ["smbpasswd", "-a", "-s", name],
        input=f"{password}\n{password}\n",
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        print(f"  smbpasswd stderr: {proc.stderr}", flush=True)
        raise RuntimeError(f"smbpasswd failed for user {name!r}")
    print(f"  samba user {name!r} configured", flush=True)


def _write_username_map_script() -> None:
    script = (
        "#!/bin/sh\n"
        "# Strip @REALM suffix so cross-realm principals map to local users.\n"
        'echo "${1%%@*}"\n'
    )
    _write(USERNAME_MAP_SCRIPT, script)
    os.chmod(USERNAME_MAP_SCRIPT, 0o755)


def main() -> None:
    print("==> smb-mock Samba starting", flush=True)
    config: SambaConfig = load_config_from_env()

    print(f"    hostname  : {config.hostname}", flush=True)
    print(f"    realm     : {config.krb5_realm}", flush=True)
    print(f"    kdc_host  : {config.kdc_host}", flush=True)
    print(f"    anonymous : {config.enable_anonymous}", flush=True)
    print(f"    ntlm      : {config.enable_ntlm}", flush=True)
    print(f"    kerberos  : {config.enable_kerberos}", flush=True)
    print(f"    users     : {[u.name for u in config.users]}", flush=True)
    print(f"    shares    : {[s.name for s in config.shares]}", flush=True)
    print(f"    trusts    : {[t.realm for t in config.trusts]}", flush=True)

    print("\n==> Writing config files", flush=True)
    _write(SMB_CONF, generate_smb_conf(config))
    _write(KRB5_CONF, generate_krb5_conf(config))

    _write_username_map_script()

    print("\n==> Creating share directories", flush=True)
    for share in config.shares:
        os.makedirs(share.path, exist_ok=True)
        # smbd impersonates the connecting user at the OS level, so the
        # directory must be world-traversable.  Access control is enforced
        # by smb.conf (read only, valid users, guest ok) not by Unix perms.
        os.chmod(share.path, 0o777)
        print(f"  {share.path}", flush=True)

    print("\n==> Creating Samba users", flush=True)
    for user in config.users:
        _create_user(user.name, user.password)

    if config.enable_kerberos:
        print(f"\n==> Waiting for keytab at {KEYTAB_SRC}", flush=True)
        _wait_for_file(KEYTAB_SRC)
        shutil.copy2(KEYTAB_SRC, KEYTAB_DST)
        os.chmod(KEYTAB_DST, 0o600)
        print(f"  keytab installed at {KEYTAB_DST}", flush=True)

    os.makedirs("/var/log/samba", exist_ok=True)
    os.makedirs("/run/samba", exist_ok=True)

    print("\n==> Exec smbd (foreground / PID 1)", flush=True)
    os.execvp("smbd", ["smbd", "-F", "--no-process-group", f"--configfile={SMB_CONF}"])


if __name__ == "__main__":
    main()
