#!/usr/bin/env python3
"""KDC container entrypoint.

Writes Kerberos config files, initialises the principal database,
creates all required principals and exports the Samba service keytab,
then execs krb5kdc in the foreground (PID 1).
"""
import base64
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

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
KEYTAB_HTTP_PORT = int(os.environ.get("KDC_HTTP_PORT", "8088"))
KDC_CONF = "/etc/krb5kdc/kdc.conf"
KADM5_ACL = "/etc/krb5kdc/kadm5.acl"


def _start_keytab_server(keytab_path: str, port: int, token: str | None) -> None:
    """Serve the keytab over HTTP so consumers don't need a shared volume.

    If token is set, GET /keytab requires 'Authorization: Bearer <token>'.
    GET /healthz is always unauthenticated (used by Docker HEALTHCHECK).
    """
    keytab_bytes = open(keytab_path, "rb").read()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # silence per-request access log

        def _authorized(self) -> bool:
            if token is None:
                return True
            return self.headers.get("Authorization", "") == f"Bearer {token}"

        def do_GET(self):
            if self.path == "/keytab":
                if not self._authorized():
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Bearer realm="keytab"')
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(keytab_bytes)))
                self.end_headers()
                self.wfile.write(keytab_bytes)
            elif self.path == "/healthz":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_response(404)
                self.end_headers()

    threading.Thread(
        target=HTTPServer(("", port), _Handler).serve_forever,
        daemon=True,
    ).start()
    if token:
        print(f"  keytab HTTP server listening on :{port} (bearer token auth enabled)", flush=True)
    else:
        print(f"  keytab HTTP server listening on :{port} (no auth — set KDC_HTTP_TOKEN to require bearer token)", flush=True)


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

    b64 = base64.b64encode(open(KEYTAB_PATH, "rb").read()).decode()
    print(f"KEYTAB_B64:{b64}", flush=True)

    _start_keytab_server(KEYTAB_PATH, KEYTAB_HTTP_PORT, os.environ.get("KDC_HTTP_TOKEN") or None)

    # kadmind is only needed inside the Docker network (keytab handoff).
    # Both stdout and stderr are suppressed — it has no external port exposure.
    print("\n==> Starting kadmind (background, internal only)", flush=True)
    subprocess.Popen(["kadmind", "-nofork"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("==> Exec krb5kdc (foreground / PID 1)", flush=True)
    os.execvp("krb5kdc", ["krb5kdc", "-n"])


if __name__ == "__main__":
    main()
