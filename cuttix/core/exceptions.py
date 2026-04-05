"""All custom exceptions in one place."""


class CuttixError(Exception):
    """Base for all cuttix errors."""


# -- privilege --
class PrivilegeError(CuttixError):
    """Need root/admin but don't have it."""


# -- network --
class InterfaceError(CuttixError):
    """Network interface not found or not usable."""


class InvalidNetworkError(CuttixError):
    """Bad CIDR or network string."""


# -- scanner --
class HostNotFoundError(CuttixError):
    """Can't resolve MAC for a given IP."""


# -- arp control --
class SecurityError(CuttixError):
    """Refused for safety reasons (self-spoof, gateway-spoof, etc)."""


class AlreadySpoofedError(CuttixError):
    """Target is already being spoofed."""


class NotSpoofedError(CuttixError):
    """Tried to restore a host that isn't spoofed."""


# -- config --
class ConfigError(CuttixError):
    """Invalid or unreadable configuration."""
