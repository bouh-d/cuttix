"""Cuttix GUI package.

Do not auto-import widgets here — QtWidgets needs a display and
libEGL which may not be available in test/headless environments.
Import `cuttix.gui.app` or `cuttix.gui.state` directly as needed.
"""
from __future__ import annotations

__all__ = ["run"]


def run(argv: list[str] | None = None) -> int:
    """Launch the Cuttix GUI. Imported lazily to avoid Qt on non-GUI paths."""
    from cuttix.gui.app import main
    return main(argv)
