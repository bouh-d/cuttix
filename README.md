# Cuttix

**LAN administration and audit toolkit — scan, control, capture, detect.**

Cuttix discovers every device on your local network, fingerprints them,
scans their open ports, captures traffic, detects ARP spoofing and rogue
DHCP servers, and can cut a misbehaving host off the LAN with a single
command. It ships with both a Click-based CLI and a PyQt6 desktop GUI.

[![CI](https://github.com/bouh-d/cuttix/actions/workflows/ci.yml/badge.svg)](https://github.com/bouh-d/cuttix/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-GPLv3-green)
![Tests](https://img.shields.io/badge/tests-262%20passing-brightgreen)

> ⚠️ Cuttix includes intrusive features (ARP spoofing, packet capture)
> that are illegal to use without authorization. Read
> [`LEGAL_DISCLAIMER.md`](LEGAL_DISCLAIMER.md) before running it.

---

## Features

- **Host discovery** — ARP sweep + passive listen, MAC vendor lookup,
  reverse DNS, OS fingerprinting.
- **Port scanner** — TCP connect and SYN scans, service banner grabbing,
  concurrent workers, rate limiting.
- **ARP controller** — cut or isolate a host on demand, with automatic
  periodic re-poisoning and clean restore. Every action is written to
  an HMAC-signed audit log.
- **Packet capture** — live pcap, BPF filters, dpkt/scapy decoders,
  statistics over time.
- **Network IDS** — ARP spoof, rogue DHCP, port scan, MAC flooding and
  "new device" detection, fed by the same event bus as the scanner.
- **Audit reports** — JSON, CSV and PDF output with vulnerability
  summary and remediation suggestions.
- **Desktop GUI** — dashboard, host table, network map, packet viewer,
  live bandwidth chart, IDS alert feed, dark/light themes.

## Quick start

Install from source with the full feature set:

```bash
git clone https://github.com/bouh-d/cuttix.git
cd cuttix
pip install -e '.[all]'
```

Scan your current subnet:

```bash
sudo cuttix scan
```

Watch the network continuously with IDS enabled:

```bash
sudo cuttix watch --interval 30
```

Generate a PDF audit report of everything stored so far:

```bash
cuttix report --format pdf --output audit.pdf
```

Launch the desktop GUI:

```bash
sudo cuttix gui
```

For the full command list: `cuttix --help`.

## Install

### From source (recommended during the 1.x series)

```bash
git clone https://github.com/bouh-d/cuttix.git
cd cuttix
make dev           # editable install + dev tooling
```

The default `pip install -e .` installs only the CLI. Extras:

| Extra    | What it adds                         |
|----------|--------------------------------------|
| `gui`    | PyQt6 desktop app (`cuttix gui`)     |
| `capture`| dpkt-based packet decoder            |
| `pdf`    | reportlab (PDF audit reports)        |
| `dev`    | pytest, ruff, mypy, bandit, build    |
| `release`| pyinstaller for standalone binaries  |
| `all`    | `gui + capture + pdf`                |

### Standalone binary

Single-file binaries (no Python required) are published on the
[Releases page](https://github.com/bouh-d/cuttix/releases) for Linux
and Windows. See [Building a binary](#building-a-binary).

## Usage

### CLI

```
Usage: cuttix [OPTIONS] COMMAND [ARGS]...

  Cuttix — LAN administration and audit toolkit.

Commands:
  scan      One-shot host discovery on the current subnet.
  watch     Continuous scan loop with IDS alerts.
  ports     Scan ports on one or more targets.
  capture   Live packet capture with BPF filter.
  cut       ARP-spoof a target so it loses connectivity.
  restore   Restore a previously cut host.
  report    Generate an audit report (json / csv / pdf).
  gui       Launch the desktop GUI.
```

Most subcommands accept `-n / --network` (e.g. `10.0.0.0/24`) and
`-i / --interface`.

### GUI

`cuttix gui` opens a 7-pane desktop app:

| Pane        | What it does                                          |
|-------------|-------------------------------------------------------|
| Dashboard   | KPI cards driven by the event bus                     |
| Hosts       | Filterable host inventory with sortable columns       |
| Network Map | Star-topology view, gateway in the centre             |
| Packets     | Live capture table with hex-dump detail pane          |
| Bandwidth   | Per-host throughput chart (sliding 60-second window)  |
| Control     | Cut / restore hosts, with confirmation dialogs        |
| Alerts      | IDS feed, colour-coded by severity                    |

Toggle the dark/light theme with `Ctrl+T`. The preference is stored in
`~/.config/cuttix/ui_state.json`.

## Architecture

```
┌──────────────┐   events   ┌──────────────┐   Qt signals   ┌────────┐
│  Scanner /   │ ─────────► │   EventBus   │ ─────────────► │ Widgets│
│ ARP / IDS /  │            │              │                └────────┘
│  Capture …   │ ◄───────── │ subscribers  │ ◄──────────── StateStore
└──────────────┘            └──────────────┘
```

Every module publishes domain events (`HOST_DISCOVERED`,
`ARP_SPOOF_DETECTED`, `PACKET_CAPTURED`, …) to a central thread-safe
`EventBus`. The CLI subscribes a simple echo handler; the GUI
subscribes a `StateStore` that bridges the bus into Qt signals on the
main thread. This keeps modules stateless, testable, and swappable.

```
cuttix/
├── cli/               Click entry points
├── core/              event bus, config, exceptions, database
├── models/            dataclasses (Host, Alert, PacketInfo, …)
├── modules/           scanner, arp_control, ids, port_scanner,
│                      packet_capture, report
├── gui/               PyQt6 app — state, widgets, workers, themes
└── utils/             logger, network helpers, validators, audit_log
```

## Development

```bash
make dev         # editable install with dev extras
make test        # run the unit + integration tests (262 tests)
make lint        # ruff check + format check
make type-check  # mypy
make security    # bandit + pip-audit
```

### Tests

262 tests covering scanner, port scanner, ARP controller, packet
capture, IDS, report generator, database, event bus, GUI state store,
bandwidth aggregator and theme manager. Qt tests are guarded by
`pytest.importorskip("PyQt6.QtCore")` so headless CI keeps working.

```bash
QT_QPA_PLATFORM=offscreen pytest
```

### Building a binary

The `release` extra pulls in PyInstaller. A spec file lives at
[`scripts/cuttix.spec`](scripts/cuttix.spec):

```bash
pip install -e '.[release,all]'
pyinstaller scripts/cuttix.spec
# → dist/cuttix  (single-file binary)
```

The CI workflow at `.github/workflows/release.yml` builds Linux and
Windows binaries on every tagged release and uploads them as GitHub
release assets.

## Roadmap

- [x] M1 — foundations (event bus, config, DB, CLI skeleton)
- [x] M2 — scanner + ARP control
- [x] M3 — port scanner + packet capture
- [x] M4 — IDS + audit reports
- [x] M5 — GUI shell (PyQt6)
- [x] M6 — GUI complete (map, packets, bandwidth, themes)
- [x] M7 — release (packaging, PyInstaller, CI)
- [ ] v1.1 — Windows service mode, Prometheus exporter

## License

GPLv3 — see [`LICENSE`](LICENSE). This means derivative works must also
be open-sourced under GPLv3.

## Acknowledgements

Cuttix stands on the shoulders of [scapy](https://scapy.net/),
[click](https://click.palletsprojects.com/),
[PyQt6](https://www.riverbankcomputing.com/software/pyqt/),
[reportlab](https://www.reportlab.com/),
and the [IEEE OUI registry](https://standards-oui.ieee.org/).
