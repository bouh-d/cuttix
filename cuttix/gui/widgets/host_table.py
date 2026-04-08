"""Host table view — sortable, filterable inventory of discovered hosts."""

from __future__ import annotations

from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cuttix.gui.state import StateStore
from cuttix.models.host import Host


class HostTableView(QWidget):
    """Table of all discovered hosts, updated live by the StateStore."""

    COLUMNS = ["IP", "MAC", "Vendor", "Hostname", "OS", "Last seen", "Status"]

    def __init__(self, store: StateStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = store
        self._row_of: dict[str, int] = {}  # mac → row index

        # toolbar
        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Filter by IP, MAC, vendor…")
        self._filter.textChanged.connect(self._apply_filter)

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._reload_all)

        tb = QHBoxLayout()
        tb.addWidget(QLabel("Hosts"))
        tb.addStretch()
        tb.addWidget(self._filter, stretch=2)
        tb.addWidget(self._refresh_btn)

        # table
        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addLayout(tb)
        layout.addWidget(self._table)

        # wire store signals
        store.host_added.connect(self._on_host_added)
        store.host_updated.connect(self._on_host_updated)
        store.host_removed.connect(self._on_host_removed)
        store.host_cut.connect(self._mark_spoof_status)
        store.host_restored.connect(self._mark_spoof_status)

        self._reload_all()

    # -- slots --

    def _reload_all(self) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        self._row_of.clear()
        for host in self._store.get_hosts():
            self._insert_host(host)
        self._table.setSortingEnabled(True)
        self._apply_filter(self._filter.text())

    def _on_host_added(self, host: Host) -> None:
        self._insert_host(host)

    def _on_host_updated(self, host: Host) -> None:
        row = self._row_of.get(host.mac.lower())
        if row is None:
            self._insert_host(host)
            return
        self._write_row(row, host)

    def _on_host_removed(self, mac: str) -> None:
        row = self._row_of.pop(mac.lower(), None)
        if row is not None:
            self._table.removeRow(row)
            # rebuild row_of indices since removing shifts rows
            self._rebuild_row_index()

    def _mark_spoof_status(self, ip: str) -> None:
        for row in range(self._table.rowCount()):
            ip_item = self._table.item(row, 0)
            if ip_item and ip_item.text() == ip:
                status = "SPOOFED" if self._store.is_spoofed(ip) else "active"
                item = self._table.item(row, 6)
                if item:
                    item.setText(status)
                    if status == "SPOOFED":
                        item.setForeground(QBrush(QColor("#e74c3c")))

    # -- internals --

    def _insert_host(self, host: Host) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._row_of[host.mac.lower()] = row
        self._write_row(row, host)

    def _write_row(self, row: int, host: Host) -> None:
        status = "SPOOFED" if self._store.is_spoofed(host.ip) else "active"
        values = [
            host.ip,
            host.mac,
            host.vendor or "",
            host.hostname or "",
            host.os_guess or "",
            host.last_seen.strftime("%H:%M:%S") if host.last_seen else "",
            status,
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            if col == 6 and val == "SPOOFED":
                item.setForeground(QBrush(QColor("#e74c3c")))
            self._table.setItem(row, col, item)

    def _rebuild_row_index(self) -> None:
        self._row_of.clear()
        for row in range(self._table.rowCount()):
            mac_item = self._table.item(row, 1)
            if mac_item:
                self._row_of[mac_item.text().lower()] = row

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for row in range(self._table.rowCount()):
            match = not needle
            if not match:
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    if item and needle in item.text().lower():
                        match = True
                        break
            self._table.setRowHidden(row, not match)

    def selected_host(self) -> Host | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        mac_item = self._table.item(row, 1)
        if not mac_item:
            return None
        return self._store.get_host(mac_item.text())
