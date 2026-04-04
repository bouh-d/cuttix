from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)


def is_root() -> bool:
    if sys.platform == "win32":
        # windows: check admin via ctypes
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[union-attr]
        except Exception:
            return False
    return os.getuid() == 0


def check_privileges(require_root: bool = True) -> str:
    """Check and optionally reduce privileges.

    Returns a string describing the privilege mode:
    - "non_root": running without root (some features unavailable)
    - "capabilities": root dropped to CAP_NET_RAW + CAP_NET_ADMIN
    - "full_root": still full root (with warning)
    """
    if not is_root():
        if require_root:
            logger.warning("Not running as root — ARP scan/spoof and packet capture won't work")
        return "non_root"

    if sys.platform == "win32":
        # no capability model on windows, just stay admin
        return "full_root"

    # try to drop to capabilities only
    try:
        import prctl  # type: ignore[import-untyped]
        prctl.cap_effective.limit(prctl.CAP_NET_RAW, prctl.CAP_NET_ADMIN)
        logger.info("Dropped to CAP_NET_RAW + CAP_NET_ADMIN")
        return "capabilities"
    except ImportError:
        pass

    # fallback: full root — warn visibly
    logger.warning(
        "\n"
        "========================================================\n"
        "  Running as FULL ROOT. Install python-prctl to reduce:\n"
        "  pip install python-prctl\n"
        "  Or use: setcap cap_net_raw,cap_net_admin+eip $(which python3)\n"
        "========================================================"
    )
    return "full_root"


def get_sudo_uid() -> int | None:
    """Get the UID of the user who ran sudo, if applicable."""
    uid_str = os.environ.get("SUDO_UID")
    if uid_str is not None:
        try:
            return int(uid_str)
        except ValueError:
            pass
    return None
