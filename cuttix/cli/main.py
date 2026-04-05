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
@click.option("--ports", "-p", "port_spec", default=None,
              help="Port spec: 80,443 or 1-1024 or profile:web")
@click.option("--technique", type=click.Choice(["connect", "syn"]),
              default="connect", help="Scan technique")
@click.option("--workers", "-w", type=int, default=20, help="Concurrent threads")
@click.option("--rate", type=int, default=0, help="Max ports/sec (0 = unlimited)")
@click.pass_context
def ports(ctx: click.Context, target_ip: str, top: int, port_spec: str | None,
          technique: str, workers: int, rate: int) -> None:
    """Scan ports on a target host."""
    from cuttix.core.event_bus import EventBus
    from cuttix.modules.port_scanner import TCPPortScanner, get_profile_ports
    from cuttix.utils.validators import is_valid_ip, parse_port_range

    if not is_valid_ip(target_ip):
        click.echo(f"Invalid IP: {target_ip}", err=True)
        sys.exit(1)

    cfg = ctx.obj["config"]
    bus = EventBus()
    scanner = TCPPortScanner(
        event_bus=bus,
        max_workers=workers,
        timeout=cfg.port_scanner.timeout_per_port,
        rate_limit=rate,
    )

    port_list = None
    if port_spec:
        if port_spec.startswith("profile:"):
            profile = port_spec.split(":", 1)[1]
            port_list = get_profile_ports(profile)
            if not port_list:
                click.echo(f"Unknown profile: {profile}", err=True)
                sys.exit(1)
            click.echo(f"Profile '{profile}': {len(port_list)} ports")
        else:
            try:
                port_list = parse_port_range(port_spec)
            except ValueError as exc:
                click.echo(f"Bad port spec: {exc}", err=True)
                sys.exit(1)

    click.echo(f"Scanning {target_ip} ({technique})...")
    try:
        if port_list:
            result = scanner.scan_host(target_ip, ports=port_list, technique=technique)
        else:
            result = scanner.scan_top_ports(target_ip, top_n=top)
    except Exception as exc:
        click.echo(f"Scan failed: {exc}", err=True)
        sys.exit(1)

    open_ports = result.open_ports
    if not open_ports:
        click.echo(f"No open ports found on {target_ip}")
        return

    click.echo(f"\n{len(open_ports)} open port(s) on {target_ip}:\n")
    click.echo(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER'}")
    click.echo("-" * 70)

    for p in open_ports:
        svc = p.service or ""
        banner = (p.banner or "")[:40]
        click.echo(f"{p.port:<10} {p.state:<10} {svc:<15} {banner}")


@cli.command()
@click.option("--filter", "bpf_filter", default="", help="BPF filter string")
@click.option("--count", "-c", type=int, default=0, help="Stop after N packets (0 = unlimited)")
@click.pass_context
def capture(ctx: click.Context, bpf_filter: str, count: int) -> None:
    """Capture network packets."""
    from cuttix.core.event_bus import EventBus
    from cuttix.modules.packet_capture import LiveCapture

    iface = _get_interface(ctx)
    bus = EventBus()

    cap = LiveCapture(interface=iface, event_bus=bus)

    pkt_count = [0]

    def on_packet(pkt):
        pkt_count[0] += 1
        src = pkt.src_ip or pkt.src_mac or "?"
        dst = pkt.dst_ip or pkt.dst_mac or "?"
        click.echo(
            f"{pkt.timestamp:%H:%M:%S}  {pkt.protocol:<6} "
            f"{src} → {dst}  {pkt.info}"
        )
        if count > 0 and pkt_count[0] >= count:
            cap.stop()

    try:
        cap.start(bpf_filter=bpf_filter, callback=on_packet)
    except RuntimeError as exc:
        click.echo(f"Capture failed: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Capturing on {iface} ({cap.backend})")
    if bpf_filter:
        click.echo(f"Filter: {bpf_filter}")
    click.echo("Press Ctrl+C to stop.\n")

    try:
        while cap.is_running():
            import time
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        cap.stop()

    stats = cap.stats.snapshot()
    click.echo(f"\n{stats['total_packets']} packets captured in {stats['elapsed_seconds']}s")


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
  