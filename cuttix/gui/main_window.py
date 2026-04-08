"""Cuttix main window — sidebar nav + stacked view router + theme toggle."""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QSize
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QToolBar,
    QWidget,
)

from cuttix.gui.state import StateStore, Stats
from cuttix.gui.themes import ThemeManager
from cuttix.gui.widgets import (
    AlertFeedView,
    BandwidthChartView,
    ControlPanelView,
    DashboardView,
    HostTableView,
    NetworkMapView,
    PacketViewerView,
)


class MainWindow(QMainWindow):
    NAV_ITEMS = [
        ("Dashboard", "dashboard"),
        ("Hosts", "hosts"),
        ("Network Map", "map"),
        ("Packets", "packets"),
        ("Bandwidth", "bandwidth"),
        ("Control", "control"),
        ("Alerts", "alerts"),
    ]

    def __init__(
        self,
        store: StateStore,
        arp_controller: Any,
        theme_manager: ThemeManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._theme = theme_manager or ThemeManager()

        self.setWindowTitle("Cuttix — LAN administration and audit toolkit")
        self.resize(1280, 800)
        self.setMinimumSize(QSize(960, 560))

        # sidebar
        self._sidebar = QListWidget()
        self._sidebar.setObjectName("sidebar")
        self._sidebar.setFixedWidth(180)
        for label, _key in self.NAV_ITEMS:
            self._sidebar.addItem(QListWidgetItem(label))
        self._sidebar.setCurrentRow(0)
        self._sidebar.currentRowChanged.connect(self._route)

        # stacked views (order MUST match NAV_ITEMS)
        self._stack = QStackedWidget()
        self._dashboard = DashboardView(store)
        self._hosts = HostTableView(store)
        self._map = NetworkMapView(store)
        self._packets = PacketViewerView(store)
        self._bandwidth = BandwidthChartView(store)
        self._control = ControlPanelView(store, arp_controller)
        self._alerts = AlertFeedView(store)
        for view in (
            self._dashboard,
            self._hosts,
            self._map,
            self._packets,
            self._bandwidth,
            self._control,
            self._alerts,
        ):
            self._stack.addWidget(view)

        # root layout
        root = QWidget(self)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self._sidebar)
        h.addWidget(self._stack, stretch=1)
        self.setCentralWidget(root)

        # toolbar with theme toggle
        toolbar = QToolBar("Main", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        self._theme_action = QAction(self._theme_label(), self)
        self._theme_action.setShortcut(QKeySequence("Ctrl+T"))
        self._theme_action.triggered.connect(self._toggle_theme)
        toolbar.addAction(self._theme_action)

        # status bar
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready")

        store.stats_changed.connect(self._update_status)
        store.error_raised.connect(self._on_error)
        self._update_status(store.get_stats())

    # -- routing --

    def _route(self, row: int) -> None:
        self._stack.setCurrentIndex(row)

    # -- status / errors --

    def _update_status(self, stats: Stats) -> None:
        self._status.showMessage(
            f"Hosts: {stats.host_count}  |  "
            f"Alerts: {stats.alert_count}  |  "
            f"Spoofed: {stats.spoofed_count}  |  "
            f"Packets: {stats.packets_total}"
        )

    def _on_error(self, title: str, message: str) -> None:
        self._status.showMessage(f"[{title}] {message}", 8000)

    # -- theme --

    def _toggle_theme(self) -> None:
        from PyQt6.QtWidgets import QApplication

        new_theme = self._theme.toggle()
        instance = QApplication.instance()
        if instance is not None:
            instance.setStyleSheet(self._theme.stylesheet(new_theme))
        self._theme_action.setText(self._theme_label())

    def _theme_label(self) -> str:
        return "Switch to light" if self._theme.current == "dark" else "Switch to dark"
