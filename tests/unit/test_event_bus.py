from __future__ import annotations

import threading

from cuttix.core.event_bus import Event, EventType


class TestEventBusBasics:
    def test_subscribe_and_publish(self, event_bus):
        received = []
        event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: received.append(e), "test")

        event = Event(type=EventType.HOST_DISCOVERED, data={"ip": "10.0.0.1"}, source="scanner")
        event_bus.publish(event)

        assert len(received) == 1
        assert received[0].data["ip"] == "10.0.0.1"

    def test_unsubscribe(self, event_bus):
        received = []
        event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: received.append(e), "test")
        event_bus.unsubscribe(EventType.HOST_DISCOVERED, "test")

        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="scanner"))
        assert len(received) == 0

    def test_multiple_subscribers(self, event_bus):
        results = {"a": [], "b": []}
        event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: results["a"].append(e), "mod_a")
        event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: results["b"].append(e), "mod_b")

        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="scanner"))
        assert len(results["a"]) == 1
        assert len(results["b"]) == 1

    def test_different_event_types_isolated(self, event_bus):
        received = []
        event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: received.append(e), "test")

        # publish a different event type
        event_bus.publish(Event(type=EventType.HOST_LOST, data={}, source="scanner"))
        assert len(received) == 0


class TestAntiLoop:
    def test_source_does_not_receive_own_events(self, event_bus):
        received = []
        event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: received.append(e), "scanner")

        # scanner publishes, scanner should NOT receive it
        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="scanner"))
        assert len(received) == 0

    def test_other_modules_still_receive(self, event_bus):
        received = []
        event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: received.append(e), "ids")

        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="scanner"))
        assert len(received) == 1


class TestHandlerIsolation:
    def test_crashing_handler_doesnt_block_others(self, event_bus):
        results = []

        def bad_handler(e):
            raise RuntimeError("boom")

        def good_handler(e):
            results.append(e)

        event_bus.subscribe(EventType.HOST_DISCOVERED, bad_handler, "bad_module")
        event_bus.subscribe(EventType.HOST_DISCOVERED, good_handler, "good_module")

        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="scanner"))
        # good_handler still got called despite bad_handler crashing
        assert len(results) == 1

    def test_crash_emits_module_error(self, event_bus):
        errors = []
        event_bus.subscribe(EventType.MODULE_ERROR, lambda e: errors.append(e), "monitor")

        def crasher(e):
            raise ValueError("oops")

        event_bus.subscribe(EventType.HOST_DISCOVERED, crasher, "buggy")
        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="scanner"))

        assert len(errors) == 1
        assert errors[0].data["module"] == "buggy"

    def test_module_error_handler_crash_doesnt_recurse(self, event_bus):
        """If even the MODULE_ERROR handler crashes, we don't infinite loop."""

        def double_crash(e):
            raise RuntimeError("error handler also crashed")

        event_bus.subscribe(EventType.MODULE_ERROR, double_crash, "fragile")
        event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: 1 / 0, "divider")

        # should not raise or infinite loop
        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="scanner"))


class TestStats:
    def test_stats_count_events(self, event_bus):
        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="a"))
        event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="a"))
        event_bus.publish(Event(type=EventType.HOST_LOST, data={}, source="a"))

        stats = event_bus.get_stats()
        assert stats["HOST_DISCOVERED"] == 2
        assert stats["HOST_LOST"] == 1


class TestThreadSafety:
    def test_concurrent_subscribe_publish(self, event_bus):
        """Multiple threads subscribing and publishing shouldn't crash."""
        results = []
        errors = []

        def publisher():
            for _ in range(50):
                try:
                    event_bus.publish(Event(type=EventType.HOST_DISCOVERED, data={}, source="p"))
                except Exception as e:
                    errors.append(e)

        def subscriber():
            for i in range(50):
                try:
                    event_bus.subscribe(
                        EventType.HOST_DISCOVERED,
                        lambda e: results.append(1),
                        f"sub_{threading.current_thread().name}_{i}",
                    )
                except Exception as e:
                    errors.append(e)

        threads = [
            threading.Thread(target=publisher),
            threading.Thread(target=subscriber),
            threading.Thread(target=publisher),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0
