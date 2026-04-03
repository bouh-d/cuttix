"""Cuttix CLI — entry point."""
from __future__ import annotations

import click
import sys

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
@click.pass_context
def scan(ctx: click.Context) -> None:
    """Scan the local network for hosts."""
    click.echo("Scanner not yet implemented (Milestone 2)")
    # TODO: wire up NetworkScanner here


@cli.command()
@click.argument("target_ip")
@click.option("--timeout", "-t", type=int, default=0,
              help="Auto-restore after N minutes (0 = manual)")
@click.pass_context
def cut(ctx: click.Context, target_ip: str, timeout: int) -> None:
    """Cut a host's network access via ARP spoofing."""
    click.echo("ARP Control not yet implemented (Milestone 2)")


@cli.command()
@click.argument("target_ip")
@click.pass_context
def restore(ctx: click.Context, target_ip: str) -> None:
    """Restore a host's network access."""
    click.echo("ARP Control not yet implemented (Milestone 2)")


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
    click.echo(BANNER)
    click.echo(f"Version: {cuttix.__version__}")
    click.echo("Status:  idle")
    # TODO: show active spoof count, scan results, etc.


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
