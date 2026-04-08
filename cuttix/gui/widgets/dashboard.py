"""Dashboard view — KPI cards summarizing network state."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from cuttix.gui.state import StateStore, Stats


class KPICard(QFrame):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("kpiCard")
        self.setFrameShape(QFrame.Shape.StyledPanel)

        self._value = QLabel("0")
        self._value.setObjectName("kpiValue")
        self._value.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._title = QLabel(title)
        self._title.setObjectName("kpiTitle")
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.addWidget(self._value)
        layout.addWidget(self._title)

    def set_value(self, value: int | str) -> None:
        self._value.setText(str(value))


class DashboardView(QWidget):
    """Grid of KPI cards driven by StateStore signals."""

    def __init__(self, store: StateStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = store

        self._hosts = KPICard("Hosts discovered")
        self._alerts = KPICard("Alerts")
        self._critical = KPICard("Critical")
        self._spoofed = KPICard("Spoofed now")
        self._packets = KPICard("Packets captured")
        self._status = KPICard("Scan status")

        grid = QGridLayout(self)
        grid.setContentsMargins(20, 20, 20, 20)
        grid.setSpacing(16)
        grid.addWidget(self._hosts, 0, 0)
        grid.addWidget(self._alerts, 0, 1)
        grid.addWidget(self._critical, 0, 2)
        grid.addWidget(self._spoofed, 1, 0)
        grid.addWidget(self._packets, 1, 1)
        grid.addWidget(self._status, 1, 2)
        grid.setRowStretch(2, 1)

        self._store.stats_changed.connect(self._on_stats)
        self._on_stats(self._store.get_stats())

    def _on_stats(self, stats: Stats) -> None:
        self._hosts.set_value(stats.host_count)
        self._alerts.set_value(stats.alert_count)
        self._critical.set_value(stats.critical_alerts)
        self._spoofed.set_value(stats.spoofed_count)
        self._packets.set_value(stats.packets_total)
        self._status.set_value("scanning…" if stats.scan_in_progress else "idle")
