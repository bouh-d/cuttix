"""Alert feed view — real-time stream of IDS alerts."""

from __future__ import annotations

from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cuttix.gui.state import StateStore
from cuttix.models.alert import Alert

_SEV_COLOR = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#27ae60",
}


class AlertFeedView(QWidget):
    """Scrolling table of IDS alerts, newest on top."""

    COLUMNS = ["Time", "Severity", "Type", "Source", "Description"]
    MAX_ROWS = 500

    def __init__(self, store: StateStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = store

        self._clear_btn = QPushButton("Clear alerts")
        self._clear_btn.clicked.connect(self._on_clear)

        tb = QHBoxLayout()
        tb.addWidget(QLabel("IDS Alerts"))
        tb.addStretch()
        tb.addWidget(self._clear_btn)

        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addLayout(tb)
        layout.addWidget(self._table)

        store.alert_raised.connect(self._on_alert)
        for a in store.get_alerts():
            self._append(a)

    def _on_alert(self, alert: Alert) -> None:
        self._append(alert)

    def _on_clear(self) -> None:
        self._table.setRowCount(0)
        self._store.clear_alerts()

    def _append(self, alert: Alert) -> None:
        # newest on top
        self._table.insertRow(0)

        t = alert.created_at.strftime("%H:%M:%S")
        sev = alert.severity.value
        atype = alert.alert_type.name
        src = alert.source_ip or ""
        desc = alert.description

        items = [
            QTableWidgetItem(t),
            QTableWidgetItem(sev.upper()),
            QTableWidgetItem(atype),
            QTableWidgetItem(src),
            QTableWidgetItem(desc),
        ]
        # color severity column
        color = QColor(_SEV_COLOR.get(sev, "#95a5a6"))
        items[1].setForeground(QBrush(color))

        for col, item in enumerate(items):
            self._table.setItem(0, col, item)

        # cap at MAX_ROWS
        while self._table.rowCount() > self.MAX_ROWS:
            self._table.removeRow(self._table.rowCount() - 1)
