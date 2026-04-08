# Contributing to Cuttix

Thanks for your interest! Cuttix is a portfolio project maintained
as a personal learning ground, but outside contributions are very
welcome. This file describes the basics of getting a change merged.

## Ground rules

- **Legality first.** Do not submit features that only make sense in
  an attack context (e.g. DNS poisoning against production), unless
  they come with strong safeguards and a clear lab-only use case.
- **No network actions without an audit trail.** Anything that alters
  the state of the LAN (ARP spoofing, rogue DHCP responses, …) must
  write to the HMAC-signed audit log.
- **Tests for every module.** New modules should ship with unit tests
  and, where possible, an integration test that exercises the
  event-bus wiring.
- **Keep the GUI testable headless.** Pure logic goes in
  `cuttix.gui.state` / `cuttix.gui.bandwidth` / `cuttix.gui.themes`;
  Qt widgets stay thin and should not carry state that can't be
  introspected through the store.

## Development setup

```bash
git clone https://github.com/bouh-d/cuttix.git
cd cuttix
make dev
```

Run the full checks before sending a PR:

```bash
make lint
make type-check
make test
```

## Commit style

Conventional commits — one of `feat`, `fix`, `refactor`, `test`,
`docs`, `chore`, `ci`. The milestone commits use `feat: Mx — …`.

## Reporting security issues

If you think you have found a vulnerability in Cuttix, please do
**not** open a public issue. Open a GitHub security advisory instead,
or email the maintainer listed in `pyproject.toml`.
