"""Cuttix main window — sidebar nav + stacked view router."""
from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import (
    QHBoxLayout, QListWidget, QListWidgetItem, QMainWindow, QStackedWidget,
    QStatusBar, QWidget,
)

from cuttix.gui.state import StateStore, Stats
from cuttix.gui.widgets import (
    AlertFeedView, ControlPanelView, DashboardView, HostTableView,
)


class MainWindow(QMainWindow):
    NAV_ITEMS = [
        ("Dashboard", "dashboard"),
        ("Hosts", "hosts"),
        ("Control", "control"),
        ("Alerts", "alerts"),
    ]

    def __init__(self, store: StateStore, arp_controller: Any,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = store

        self.setWindowTitle("Cuttix — LAN administration and audit toolkit")
        self.resize(1200, 760)
        self.setMinimumSize(QSize(960, 560))

        # sidebar
        self._sidebar = QListWidget()
        self._sidebar.setObjectName("sidebar")
        self._sidebar.setFixedWidth(180)
        for label, _key in self.NAV_ITEMS:
            self._sidebar.addItem(QListWidgetItem(label))
        self._sidebar.setCurrentRow(0)
        self._sidebar.currentRowChanged.connect(self._route)

        # stacked views
        self._stack = QStackedWidget()
        self._dashboard = DashboardView(store)
        self._hosts = HostTableView(store)
        self._control = ControlPanelView(store, arp_controller)
        self._alerts = AlertFeedView(store)
        self._stack.addWidget(self._dashboard)
        self._stack.addWidget(self._hosts)
        self._stack.addWidget(self._control)
        self._stack.addWidget(self._alerts)

        # root layout
        root = QWidget(self)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self._sidebar)
        h.addWidget(self._stack, stretch=1)
        self.setCentralWidget(root)

        # status bar
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready")

        store.stats_changed.connect(self._update_status)
        store.error_raised.connect(self._on_error)
        self._update_status(store.get_stats())

    def _route(self, row: int) -> None:
        self._stack.setCurrentIndex(row)

    def _update_status(self, stats: Stats) -> None:
        self._status.showMessage(
            f"Hosts: {stats.host_count}  |  "
            f"Alerts: {stats.alert_count}  |  "
            f"Spoofed: {stats.spoofed_count}"
        )

    def _on_error(self, title: str, message: str) -> None:
        self._status.showMessage(f"[{title}] {message}", 8000)
