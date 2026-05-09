#!/usr/bin/env python3
"""
smb-mock configuration wizard.

Interactive prompts → generates one or more of:
  • .env file          (for docker-compose)
  • docker run script  (for direct docker usage)
  • compose override   (docker-compose.override.yml)

Usage:
    python cli/wizard.py
    python cli/wizard.py --output myconfig.env --format all
"""
from __future__ import annotations

import sys

import click

from cli.formatters import WizardConfig, to_compose_override, to_docker_run, to_env_file


# ---------------------------------------------------------------------------
# Validation helpers (reuse parse logic from config modules)
# ---------------------------------------------------------------------------
def _validate_user(value: str) -> tuple[str, str] | None:
    """Return (name, password) or None on empty input."""
    if not value:
        return None
    parts = value.split(":", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise click.BadParameter(f"Expected name:password, got {value!r}")
    return parts[0], parts[1]


def _validate_share(name: str, path: str, mode: str) -> tuple[str, str, str]:
    if not name or not path:
        raise click.BadParameter("Share name and path must not be empty")
    if mode not in ("rw", "ro"):
        raise click.BadParameter(f"Mode must be 'rw' or 'ro', got {mode!r}")
    return name, path, mode


def _validate_trust(realm: str, kdc_host: str, secret: str, direction: str) -> tuple[str, str, str, str]:
    if not realm or not kdc_host or not secret:
        raise click.BadParameter("realm, kdc_host, and secret must not be empty")
    if direction not in ("one-way", "two-way"):
        raise click.BadParameter(f"Direction must be 'one-way' or 'two-way', got {direction!r}")
    return realm, kdc_host, secret, direction


# ---------------------------------------------------------------------------
# Section helpers
# ---------------------------------------------------------------------------
def _prompt_users() -> list[tuple[str, str]]:
    users: list[tuple[str, str]] = []
    click.echo("")
    click.echo("  Users  (press Enter with no name to finish)")
    i = 0
    while True:
        name = click.prompt(f"    [{i}] username", default="", show_default=False)
        if not name:
            break
        password = click.prompt(f"    [{i}] password", hide_input=True, confirmation_prompt=True)
        users.append((name, password))
        i += 1
    return users


def _prompt_shares() -> list[tuple[str, str, str]]:
    shares: list[tuple[str, str, str]] = []
    click.echo("")
    click.echo("  Shares  (press Enter with no name to finish)")
    i = 0
    while True:
        name = click.prompt(f"    [{i}] share name", default="", show_default=False)
        if not name:
            break
        default_path = f"/smb-data/{name}"
        path = click.prompt(f"    [{i}] path in container", default=default_path)
        mode = click.prompt(
            f"    [{i}] mode",
            type=click.Choice(["rw", "ro"]),
            default="rw",
            show_choices=True,
        )
        shares.append(_validate_share(name, path, mode))
        i += 1
    return shares


def _prompt_trusts(realm: str) -> list[tuple[str, str, str, str]]:
    trusts: list[tuple[str, str, str, str]] = []
    click.echo("")
    click.echo("  Kerberos trusts  (press Enter with no realm to finish)")
    click.echo(f"  Note: the remote KDC must add a reciprocal trust for {realm}")
    i = 0
    while True:
        trust_realm = click.prompt(f"    [{i}] trusted realm", default="", show_default=False)
        if not trust_realm:
            break
        kdc_host = click.prompt(f"    [{i}] KDC hostname/IP for {trust_realm}")
        secret = click.prompt(
            f"    [{i}] shared secret",
            hide_input=True,
            confirmation_prompt=True,
        )
        direction = click.prompt(
            f"    [{i}] direction",
            type=click.Choice(["one-way", "two-way"]),
            default="one-way",
            show_choices=True,
        )
        trusts.append(_validate_trust(trust_realm, kdc_host, secret, direction))
        i += 1
    return trusts


# ---------------------------------------------------------------------------
# Main command
# ---------------------------------------------------------------------------
@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--output", "-o",
    default=".env",
    show_default=True,
    help="Path to write the .env file (used with --format env or all).",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["env", "docker-run", "compose-override", "all"]),
    default=None,
    help="Output format.  Prompted interactively if not supplied.",
)
@click.option(
    "--non-interactive", "-n",
    is_flag=True,
    default=False,
    help="Accept all defaults without prompting (useful for scripting).",
)
def wizard(output: str, output_format: str | None, non_interactive: bool) -> None:
    """Interactive wizard to generate smb-mock container configuration."""

    click.echo("")
    click.echo("╔══════════════════════════════════════╗")
    click.echo("║      smb-mock  Configuration Wizard  ║")
    click.echo("╚══════════════════════════════════════╝")
    click.echo("")

    if non_interactive:
        config = WizardConfig()
        click.echo("  Using all defaults (--non-interactive).")
    else:
        # ── Identity ────────────────────────────────────────────────────────
        click.echo("── Identity ─────────────────────────────────────────────────")
        hostname = click.prompt(
            "  SMB server FQDN",
            default="smbserver.smbtest.local",
        )
        workgroup = click.prompt("  Workgroup (NetBIOS domain)", default="SMBTEST")
        realm = click.prompt("  Kerberos realm", default="SMBTEST.LOCAL")

        # ── Auth ─────────────────────────────────────────────────────────────
        click.echo("")
        click.echo("── Authentication ───────────────────────────────────────────")
        enable_anonymous = click.confirm("  Allow anonymous/guest access?", default=True)
        enable_ntlm = click.confirm("  Enable NTLMv2?", default=True)
        enable_kerberos = click.confirm("  Enable Kerberos/SPNEGO?", default=True)

        kdc_admin_password = "adminpass"
        if enable_kerberos:
            kdc_admin_password = click.prompt(
                "  KDC admin password",
                default="adminpass",
                hide_input=True,
                confirmation_prompt=True,
            )

        # ── Port mappings ────────────────────────────────────────────────────
        click.echo("")
        click.echo("── Port mappings (host → container) ─────────────────────────")
        smb_port = click.prompt("  SMB  (host port → 445)", default=445, type=int)
        kdc_port = 88
        if enable_kerberos:
            kdc_port = click.prompt("  KDC  (host port → 88)", default=88, type=int)

        # ── Users ────────────────────────────────────────────────────────────
        click.echo("")
        click.echo("── Users ────────────────────────────────────────────────────")
        users = _prompt_users()

        # ── Shares ───────────────────────────────────────────────────────────
        click.echo("")
        click.echo("── Shares ───────────────────────────────────────────────────")
        shares = _prompt_shares()

        # ── Trusts ───────────────────────────────────────────────────────────
        trusts: list[tuple[str, str, str, str]] = []
        if enable_kerberos:
            click.echo("")
            click.echo("── Kerberos trusts ──────────────────────────────────────────")
            if click.confirm("  Configure cross-realm trust relationships?", default=False):
                trusts = _prompt_trusts(realm)

        config = WizardConfig(
            smb_hostname=hostname,
            workgroup=workgroup,
            realm=realm,
            kdc_admin_password=kdc_admin_password,
            enable_anonymous=enable_anonymous,
            enable_ntlm=enable_ntlm,
            enable_kerberos=enable_kerberos,
            smb_port=smb_port,
            kdc_port=kdc_port,
            users=users,
            shares=shares,
            trusts=trusts,
        )

    # ── Output format ────────────────────────────────────────────────────────
    if output_format is None:
        click.echo("")
        click.echo("── Output ───────────────────────────────────────────────────")
        output_format = click.prompt(
            "  Generate",
            type=click.Choice(["env", "docker-run", "compose-override", "all"]),
            default="env",
            show_choices=True,
        )

    click.echo("")

    if output_format in ("env", "all"):
        content = to_env_file(config)
        with open(output, "w") as fh:
            fh.write(content)
        click.echo(f"  ✓  .env written to {output}")

    if output_format in ("compose-override", "all"):
        override_path = "docker-compose.override.yml"
        with open(override_path, "w") as fh:
            fh.write(to_compose_override(config))
        click.echo(f"  ✓  compose override written to {override_path}")

    if output_format in ("docker-run", "all"):
        click.echo("")
        click.echo("── docker run script ────────────────────────────────────────")
        click.echo(to_docker_run(config))

    if config.enable_kerberos:
        click.echo("")
        click.echo("  ⚠   Kerberos requires hostname resolution on each client:")
        click.echo(f"      Add to /etc/hosts (or OS equivalent):")
        click.echo(f"        127.0.0.1  {config.smb_hostname}")


if __name__ == "__main__":
    wizard()
