# Changelog

All notable changes to Cuttix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-04-08

First stable release. Covers milestones M1 through M7.

### Added
- **Core foundations** (M1): thread-safe `EventBus`, typed event
  registry, TOML-based `AppConfig`, `Database` wrapper with schema
  migrations, CLI skeleton built on Click.
- **Host discovery** (M2): `NetworkScanner` with ARP sweep, MAC vendor
  lookup from the IEEE OUI registry, reverse DNS, and optional OS
  fingerprinting.
- **ARP control** (M2): `ARPController` that can cut, isolate, and
  restore hosts, with auto-restore timers and an HMAC-signed audit log
  that cannot be disabled.
- **Port scanner** (M3): TCP connect + SYN scans, banner grabbing,
  concurrent worker pool, rate limiting, dangerous-port annotations.
- **Packet capture** (M3): `LiveCapture` with BPF filters, scapy and
  dpkt decoders, running statistics, CSV/pcap export.
- **Network IDS** (M4): detectors for ARP spoofing, rogue DHCP, port
  scans, MAC flooding, and new-device events, with a JSON whitelist.
- **Audit reports** (M4): JSON, CSV and PDF output via reportlab, with
  vulnerability summary and remediation suggestions.
- **GUI shell** (M5): PyQt6 main window with sidebar routing, plus
  Dashboard, Host Table, Control Panel and Alert Feed views. Wired
  through a thread-safe `StateStore` that bridges the EventBus into
  Qt signals.
- **GUI complete** (M6): Network Map (star topology on
  `QGraphicsScene`), Packet Viewer with hex-dump detail pane,
  Bandwidth chart with per-host sliding-window aggregator, and a
  persisted dark/light theme toggle.
- **Packaging** (M7): `pyproject.toml` ready for PyPI with extras for
  GUI / capture / PDF / dev / release, PyInstaller spec, GitHub
  Actions workflows for CI and tagged releases, and a refreshed
  Makefile.

### Tests
- 262 unit and integration tests across all modules; GUI tests run
  headless via `QT_QPA_PLATFORM=offscreen`.

### Known limitations
- Packet capture requires root on Linux and admin privileges on
  Windows.
- OS fingerprinting is best-effort, based on TTL + open-port heuristics.
- PyInstaller binaries embed scapy and PyQt6; size is ~120 MB.

[1.0.0]: https://github.com/bouh-d/cuttix/releases/tag/v1.0.0
