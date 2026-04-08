"""Packet Viewer — live capture table + detail pane.

Subscribes to ``StateStore.packet_captured`` and appends rows to a
ring-buffer table. Clicking a row populates a detail pane with the
fully-decoded fields. Includes a BPF-style text filter that hides
rows whose ``info``/``protocol``/``src``/``dst`` don't match.

Throttling: incoming packets can be very high volume, so we batch
them in a small list and flush via a QTimer at most ~10x per second.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from cuttix.gui.state import StateStore
from cuttix.models.packet import PacketInfo

COLUMNS = ["Time", "Source", "Destination", "Proto", "Length", "Info"]
MAX_ROWS = 2000
FLUSH_INTERVAL_MS = 100


class PacketViewerView(QWidget):
    def __init__(self, store: StateStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = store
        self._buffer: list[PacketInfo] = []
        self._packets_in_table: list[PacketInfo] = []
        self._paused = False

        # filter row
        self._filter = QLineEdit()
        self._filter.setPlaceholderText("filter (substring match on any column)…")
        self._filter.textChanged.connect(self._reapply_filter)

        self._pause_btn = QPushButton("Pause")
        self._pause_btn.setCheckable(True)
        self._pause_btn.toggled.connect(self._toggle_pause)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.clicked.connect(self._clear)

        top = QHBoxLayout()
        top.addWidget(QLabel("Filter:"))
        top.addWidget(self._filter, stretch=1)
        top.addWidget(self._pause_btn)
        top.addWidget(self._clear_btn)

        # table
        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(len(COLUMNS) - 1, QHeaderView.ResizeMode.Stretch)
        self._table.itemSelectionChanged.connect(self._on_selection)

        # detail pane
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setPlaceholderText("Select a packet to see details.")

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._table)
        splitter.addWidget(self._detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addLayout(top)
        layout.addWidget(splitter, stretch=1)

        # subscribe + flush timer
        store.packet_captured.connect(self._enqueue)
        self._timer = QTimer(self)
        self._timer.setInterval(FLUSH_INTERVAL_MS)
        self._timer.timeout.connect(self._flush)
        self._timer.start()

    # -- intake --

    def _enqueue(self, pkt) -> None:
        if self._paused or not isinstance(pkt, PacketInfo):
            return
        self._buffer.append(pkt)
        # cap the buffer aggressively in case the timer is starved
        if len(self._buffer) > MAX_ROWS:
            self._buffer = self._buffer[-MAX_ROWS:]

    def _flush(self) -> None:
        if not self._buffer:
            return
        batch, self._buffer = self._buffer, []
        for pkt in batch:
            self._append_row(pkt)
        # cap rows in the table itself
        excess = self._table.rowCount() - MAX_ROWS
        if excess > 0:
            for _ in range(excess):
                self._table.removeRow(0)
                self._packets_in_table.pop(0)

    def _append_row(self, pkt: PacketInfo) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._packets_in_table.append(pkt)
        items = [
            pkt.timestamp.strftime("%H:%M:%S.%f")[:-3] if pkt.timestamp else "",
            self._endpoint(pkt.src_ip, pkt.src_port),
            self._endpoint(pkt.dst_ip, pkt.dst_port),
            pkt.protocol or "",
            str(pkt.length or 0),
            pkt.info or "",
        ]
        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._table.setItem(row, col, item)
        self._apply_filter_to_row(row)

    @staticmethod
    def _endpoint(ip: str | None, port: int | None) -> str:
        if not ip:
            return ""
        if port:
            return f"{ip}:{port}"
        return ip

    # -- filtering --

    def _reapply_filter(self, _text: str | None = None) -> None:
        for row in range(self._table.rowCount()):
            self._apply_filter_to_row(row)

    def _apply_filter_to_row(self, row: int) -> None:
        needle = self._filter.text().strip().lower()
        if not needle:
            self._table.setRowHidden(row, False)
            return
        for col in range(self._table.columnCount()):
            item = self._table.item(row, col)
            if item and needle in item.text().lower():
                self._table.setRowHidden(row, False)
                return
        self._table.setRowHidden(row, True)

    # -- controls --

    def _toggle_pause(self, paused: bool) -> None:
        self._paused = paused
        self._pause_btn.setText("Resume" if paused else "Pause")

    def _clear(self) -> None:
        self._table.setRowCount(0)
        self._packets_in_table.clear()
        self._buffer.clear()
        self._detail.clear()

    # -- detail pane --

    def _on_selection(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if 0 <= idx < len(self._packets_in_table):
            self._render_detail(self._packets_in_table[idx])

    def _render_detail(self, pkt: PacketInfo) -> None:
        ts = pkt.timestamp.isoformat() if pkt.timestamp else "-"
        lines = [
            f"Timestamp     : {ts}",
            f"Protocol      : {pkt.protocol}",
            f"Length        : {pkt.length} bytes",
            "",
            f"Source MAC    : {pkt.src_mac or '-'}",
            f"Source IP     : {pkt.src_ip or '-'}",
            f"Source port   : {pkt.src_port if pkt.src_port else '-'}",
            "",
            f"Dest. MAC     : {pkt.dst_mac or '-'}",
            f"Dest. IP      : {pkt.dst_ip or '-'}",
            f"Dest. port    : {pkt.dst_port if pkt.dst_port else '-'}",
            "",
            f"Info          : {pkt.info or '-'}",
        ]
        if pkt.raw:
            lines.extend(["", f"Raw bytes     : {len(pkt.raw)}", self._hex_dump(pkt.raw)])
        self._detail.setPlainText("\n".join(lines))

    @staticmethod
    def _hex_dump(data: bytes, max_bytes: int = 256) -> str:
        snippet = data[:max_bytes]
        out: list[str] = []
        for offset in range(0, len(snippet), 16):
            chunk = snippet[offset : offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            out.append(f"{offset:04x}  {hex_part:<48}  {ascii_part}")
        if len(data) > max_bytes:
            out.append(f"... ({len(data) - max_bytes} more bytes)")
        return "\n".join(out)
