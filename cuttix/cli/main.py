"""Cuttix CLI — entry point."""
from __future__ import annotations

import sys

import click

import cuttix
from cuttix.config import load_config
from cuttix.utils.logger import setup_logging


BANNER = r"""
   ___       _   _   _
  / __\_   _| |_| |_(_)_  __
 / /  | | | | __| __| \ \/ /
/ /___| |_| | |_| |_| |>  <
\____/ \__,_|\__|\__|_/_/\_\
"""

DISCLAIMER = """\
WARNING: This tool includes ARP spoofing capabilities.
Use ONLY on networks you own or have written authorization to test.
Unauthorized use is illegal (French Penal Code Art. 323-1 to 323-3).

Type 'accept' to continue: """


def _get_interface(ctx: click.Context) -> str:
    """Resolve the interface from config or auto-detect."""
    cfg = ctx.obj["config"]
    iface = cfg.interface
    if iface and iface != "auto":
        return iface

    from cuttix.utils.network import get_default_interface
    detected = get_default_interface()
    if detected:
        return detected

    from scapy.all import conf  # type: ignore[import]
    return conf.iface


@click.group()
@click.version_option(version=cuttix.__version__, prog_name="cuttix")
@click.option("--config", "config_path", type=click.Path(exists=True), default=None,
              help="Path to cuttix.toml config file")
@click.option("--log-level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default=None, help="Override log level")
@click.option("--interface", "-i", default=None, help="Network interface to use")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, log_level: str | None,
        interface: str | None) -> None:
    """Cuttix — LAN administration and audit toolkit."""
    from pathlib import Path

    config = load_config(Path(config_path) if config_path else None)

    if log_level:
        config.log_level = log_level
    if interface:
        config.interface = interface

    setup_logging(level=config.log_level, log_file=config.log_file or None)

    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@cli.command()
@click.option("--network", "-n", default=None, help="Target CIDR (e.g. 192.168.1.0/24)")
@click.option("--timeout", "-t", type=float, default=2.0, help="ARP timeout in seconds")
@click.option("--retries", "-r", type=int, default=2, help="Number of ARP retries")
@click.pass_context
def scan(ctx: click.Context, network: str | None, timeout: float, retries: int) -> None:
    """Scan the local network for hosts."""
    from cuttix.core.event_bus import EventBus
    from cuttix.modules.scanner import NetworkScanner

    iface = _get_interface(ctx)
    bus = EventBus()

    try:
        scanner = NetworkScanner(interface=iface, event_bus=bus)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Scanning on {scanner.interface}...")
    if network:
        click.echo(f"Target: {network}")

    try:
        hosts = scanner.scan(network=network, timeout=timeout, retries=retries)
    except Exception as exc:
        click.echo(f"Scan failed: {exc}", err=True)
        sys.exit(1)

    if not hosts:
        click.echo("No hosts found.")
        return

    click.echo(f"\nFound {len(hosts)} host(s):\n")
    click.echo(f"{'IP':<18} {'MAC':<20} {'Vendor':<25} {'Hostname'}")
    click.echo("-" * 80)

    for h in sorted(hosts, key=lambda x: tuple(int(p) for p in x.ip.split("."))):
        vendor = (h.vendor or "")[:24]
        hostname = h.hostname or ""
        gw = " (gateway)" if h.is_gateway else ""
        click.echo(f"{h.ip:<18} {h.mac:<20} {vendor:<25} {hostname}{gw}")


@cli.command()
@click.argument("target_ip")
@click.option("--timeout", "-t", type=int, default=0,
              help="Auto-restore after N minutes (0 = manual)")
@click.pass_context
def cut(ctx: click.Context, target_ip: str, timeout: int) -> None:
    """Cut a host's network access via ARP spoofing."""
    from cuttix.core.audit_log import AuditLog
    from cuttix.core.event_bus import EventBus
    from cuttix.db.database import Database
    from cuttix.modules.arp_control import ARPController
    from cuttix.utils.validators import is_valid_ip

    if not is_valid_ip(target_ip):
        click.echo(f"Invalid IP: {target_ip}", err=True)
        sys.exit(1)

    # disclaimer check
    db = Database()
    db.connect()

    if not db.is_disclaimer_accepted():
        click.echo(DISCLAIMER, nl=False)
        resp = input()
        if resp.strip().lower() != "accept":
            click.echo("Aborted.")
            sys.exit(0)
        db.accept_disclaimer()

    iface = _get_interface(ctx)
    bus = EventBus()
    audit = AuditLog()

    try:
        ctl = ARPController(
            interface=iface,
            event_bus=bus,
            audit_log=audit,
        )
    except Exception as exc:
        click.echo(f"Init error: {exc}", err=True)
        sys.exit(1)

    try:
        ctl.cut_access(target_ip, auto_restore_minutes=timeout)
    except Exception as exc:
        click.echo(f"Cut failed: {exc}", err=True)
        sys.exit(1)

    if timeout:
        click.echo(f"Cut {target_ip} — auto-restore in {timeout} min")
    else:
        click.echo(f"Cut {target_ip} — use 'cuttix restore {target_ip}' to undo")

    # keep alive so the spoof loop continues
    click.echo("Press Ctrl+C to restore and exit.")
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        pass  # signal handler takes care of restore


@cli.command()
@click.argument("target_ip")
@click.pass_context
def restore(ctx: click.Context, target_ip: str) -> None:
    """Restore a host's network access."""
    from cuttix.core.audit_log import AuditLog
    from cuttix.core.event_bus import EventBus
    from cuttix.modules.arp_control import ARPController
    from cuttix.utils.validators import is_valid_ip

    if not is_valid_ip(target_ip):
        click.echo(f"Invalid IP: {target_ip}", err=True)
        sys.exit(1)

    iface = _get_interface(ctx)
    bus = EventBus()
    audit = AuditLog()

    try:
        # the constructor recovers orphaned state automatically
        ctl = ARPController(
            interface=iface,
            event_bus=bus,
            audit_log=audit,
        )
        ctl.restore_access(target_ip)
    except Exception as exc:
        click.echo(f"Restore failed: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Restored {target_ip}")


@cli.command()
@click.argument("target_ip")
@click.option("--top", type=int, default=100, help="Scan top N ports")
@click.pass_context
def ports(ctx: click.Context, target_ip: str, top: int) -> None:
    """Scan ports on a target host."""
    click.echo("Port Scanner not yet implemented (Milestone 3)")


@cli.command()
@click.option("--filter", "bpf_filter", default="", help="BPF filter string")
@click.pass_context
def capture(ctx: click.Context, bpf_filter: str) -> None:
    """Capture network packets."""
    click.echo("Packet Capture not yet implemented (Milestone 3)")


@cli.command()
@click.pass_context
def watch(ctx: click.Context) -> None:
    """Start IDS monitoring."""
    click.echo("IDS not yet implemented (Milestone 4)")


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "pdf"]),
              default="json", help="Report format")
@click.option("-o", "--output", type=click.Path(), default=None,
              help="Output file path")
@click.pass_context
def report(ctx: click.Context, fmt: str, output: str | None) -> None:
    """Generate a network audit report."""
    click.echo("Report Generator not yet implemented (Milestone 4)")


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show current cuttix status."""
    from cuttix.modules.arp_state import ARPStateFile

    click.echo(BANNER)
    click.echo(f"Version: {cuttix.__version__}")

    state = ARPStateFile()
    entries = state.load()
    if entries:
        click.echo(f"Active spoofs: {len(entries)}")
        for e in entries:
            click.echo(f"  {e.target_ip} ({e.target_mac}) since {e.started_at}")
    else:
        click.echo("Active spoofs: 0")

    click.echo("Status:  idle")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
