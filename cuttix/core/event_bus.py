from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class EventType(Enum):
    # Scanner
    HOST_DISCOVERED = auto()
    HOST_LOST = auto()
    HOST_UPDATED = auto()
    ARP_CONFLICT = auto()
    # ARP Control
    HOST_CUT = auto()
    HOST_RESTORED = auto()
    # Port Scanner
    PORTS_SCANNED = auto()
    SERVICE_FOUND = auto()
    # OS Fingerprint
    OS_IDENTIFIED = auto()
    # Packet Capture
    PACKET_CAPTURED = auto()
    DNS_QUERY = auto()
    CLEARTEXT_DETECTED = auto()
    # Bandwidth
    THRESHOLD_EXCEEDED = auto()
    # IDS
    ARP_SPOOF_DETECTED = auto()
    ROGUE_DHCP = auto()
    PORT_SCAN_DETECTED = auto()
    NEW_DEVICE = auto()
    MAC_FLOODING = auto()
    # System
    MODULE_ERROR = auto()
    SCAN_CYCLE_COMPLETE = auto()


@dataclass(frozen=True)
class Event:
    type: EventType
    data: Any
    source: str
    timestamp: float = field(default_factory=time.time)
    correlation_id: str | None = None


# type alias
EventHandler = Callable[[Event], None]


class EventBus:
    """Synchronous pub/sub with per-handler isolation.

    Handlers that crash don't affect other handlers.
    Handlers that take > 50ms get a warning logged.
    A module won't receive events it published itself (anti-loop).
    """

    SLOW_HANDLER_MS = 50

    def __init__(self) -> None:
        self._handlers: dict[EventType, list[tuple[str, EventHandler]]] = defaultdict(list)
        self._lock = threading.Lock()
        self._stats: dict[EventType, int] = defaultdict(int)

    def subscribe(self, event_type: EventType, handler: EventHandler, subscriber: str) -> None:
        with self._lock:
            self._handlers[event_type].append((subscriber, handler))
            logger.debug("EventBus: %s subscribed to %s", subscriber, event_type.name)

    def unsubscribe(self, event_type: EventType, subscriber: str) -> None:
        with self._lock:
            self._handlers[event_type] = [
                (name, h) for name, h in self._handlers[event_type] if name != subscriber
            ]

    def unsubscribe_all(self, subscriber: str) -> None:
        """Remove all subscriptions for a module."""
        with self._lock:
            for evt_type in self._handlers:
                self._handlers[evt_type] = [
                    (name, h) for name, h in self._handlers[evt_type] if name != subscriber
                ]

    def publish(self, event: Event) -> None:
        self._stats[event.type] += 1

        with self._lock:
            handlers = list(self._handlers.get(event.type, []))

        for subscriber, handler in handlers:
            # anti-loop: skip if the subscriber is the one who emitted
            if subscriber == event.source:
                continue

            t0 = time.monotonic()
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "EventBus: handler '%s' crashed on %s — other handlers unaffected",
                    subscriber,
                    event.type.name,
                )
                # emit MODULE_ERROR but don't recurse
                if event.type != EventType.MODULE_ERROR:
                    self._emit_error(subscriber, event)
            else:
                elapsed = (time.monotonic() - t0) * 1000
                if elapsed > self.SLOW_HANDLER_MS:
                    logger.warning(
                        "EventBus: slow handler '%s' took %.1fms on %s (limit: %dms)",
                        subscriber,
                        elapsed,
                        event.type.name,
                        self.SLOW_HANDLER_MS,
                    )

    def get_stats(self) -> dict[str, int]:
        return {k.name: v for k, v in self._stats.items()}

    def _emit_error(self, failed_module: str, original: Event) -> None:
        err = Event(
            type=EventType.MODULE_ERROR,
            data={"module": failed_module, "event_type": original.type.name},
            source="event_bus",
        )
        # direct dispatch, no publish() to avoid recursion
        with self._lock:
            handlers = list(self._handlers.get(EventType.MODULE_ERROR, []))
        for name, handler in handlers:
            try:
                handler(err)
            except Exception:
                logger.exception("EventBus: MODULE_ERROR handler '%s' also crashed", name)
