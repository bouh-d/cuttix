"""Network Map view — star-topology rendering of the LAN.

The gateway sits at the centre, every other host is positioned around
it on a circle. Hosts are color-coded by status (active, spoofed by us,
flagged by the IDS). The layout is recomputed whenever the host
inventory changes; we use a deterministic angle assignment based on
sorted MAC so the layout doesn't shuffle on every refresh.

This is intentionally a from-scratch QGraphicsScene rather than a
networkx/matplotlib import — keeps the dependency footprint small.
"""

from __future__ import annotations

import math

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from cuttix.gui.state import StateStore
from cuttix.models.host import Host

GATEWAY_RADIUS = 36
HOST_RADIUS = 22
RING_RADIUS = 220


class NetworkMapView(QWidget):
    """Auto-laid-out star topology of discovered hosts."""

    def __init__(self, store: StateStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = store

        self._scene = QGraphicsScene(self)
        self._view = QGraphicsView(self._scene, self)
        self._view.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self._view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self._view.setBackgroundBrush(QBrush(QColor("#181820")))

        self._title = QLabel("Network topology")
        font = QFont()
        font.setPointSize(13)
        font.setBold(True)
        self._title.setFont(font)

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._redraw)

        header = QHBoxLayout()
        header.addWidget(self._title)
        header.addStretch(1)
        header.addWidget(self._refresh_btn)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addLayout(header)
        layout.addWidget(self._view, stretch=1)

        store.host_added.connect(self._on_inventory_changed)
        store.host_removed.connect(self._on_inventory_changed)
        store.host_updated.connect(self._on_inventory_changed)
        store.host_cut.connect(self._on_inventory_changed)
        store.host_restored.connect(self._on_inventory_changed)

        self._redraw()

    # -- slots --

    def _on_inventory_changed(self, *_args) -> None:
        self._redraw()

    # -- rendering --

    def _redraw(self) -> None:
        self._scene.clear()
        hosts = sorted(self._store.get_hosts(), key=lambda h: h.mac)
        if not hosts:
            self._draw_empty_state()
            return

        gateway = self._pick_gateway(hosts)
        peripherals = [h for h in hosts if h is not gateway]

        # gateway in centre
        center = QPointF(0, 0)
        self._draw_node(center, gateway, GATEWAY_RADIUS, is_gateway=True)

        # peripherals on a ring
        if peripherals:
            angle_step = (2 * math.pi) / len(peripherals)
            for i, host in enumerate(peripherals):
                angle = -math.pi / 2 + i * angle_step
                px = math.cos(angle) * RING_RADIUS
                py = math.sin(angle) * RING_RADIUS
                pos = QPointF(px, py)
                self._draw_link(center, pos, spoofed=self._store.is_spoofed(host.ip))
                self._draw_node(pos, host, HOST_RADIUS, is_gateway=False)

        bounds = self._scene.itemsBoundingRect().adjusted(-40, -40, 40, 40)
        self._scene.setSceneRect(bounds)
        self._view.fitInView(bounds, Qt.AspectRatioMode.KeepAspectRatio)

    def _draw_empty_state(self) -> None:
        msg = QGraphicsSimpleTextItem("No hosts discovered yet — run a scan.")
        msg.setBrush(QBrush(QColor("#6c7480")))
        font = QFont()
        font.setPointSize(11)
        msg.setFont(font)
        self._scene.addItem(msg)
        rect = msg.boundingRect()
        msg.setPos(-rect.width() / 2, -rect.height() / 2)
        self._scene.setSceneRect(QRectF(-200, -100, 400, 200))

    def _draw_link(self, a: QPointF, b: QPointF, spoofed: bool) -> None:
        line = QGraphicsLineItem(a.x(), a.y(), b.x(), b.y())
        color = QColor("#e74c3c") if spoofed else QColor("#3a3a44")
        pen = QPen(color, 2)
        if spoofed:
            pen.setStyle(Qt.PenStyle.DashLine)
        line.setPen(pen)
        line.setZValue(-1)
        self._scene.addItem(line)

    def _draw_node(self, pos: QPointF, host: Host, radius: int, is_gateway: bool) -> None:
        rect = QRectF(pos.x() - radius, pos.y() - radius, radius * 2, radius * 2)
        node = QGraphicsEllipseItem(rect)
        node.setBrush(QBrush(self._color_for(host, is_gateway)))
        node.setPen(QPen(QColor("#1e1e24"), 2))
        node.setToolTip(self._tooltip(host))
        self._scene.addItem(node)

        # label below the node
        label_text = host.hostname or host.ip
        label = QGraphicsSimpleTextItem(label_text)
        label.setBrush(QBrush(QColor("#ecf0f1")))
        font = QFont()
        font.setPointSize(8)
        label.setFont(font)
        lbr = label.boundingRect()
        label.setPos(pos.x() - lbr.width() / 2, pos.y() + radius + 4)
        self._scene.addItem(label)

    def _color_for(self, host: Host, is_gateway: bool) -> QColor:
        if self._store.is_spoofed(host.ip):
            return QColor("#e74c3c")
        if is_gateway:
            return QColor("#f39c12")
        return QColor("#3498db")

    @staticmethod
    def _pick_gateway(hosts: list[Host]) -> Host:
        for h in hosts:
            if h.is_gateway:
                return h

        # fall back to the lowest IP last octet (typical .1)
        def _last_octet(ip: str) -> int:
            try:
                return int(ip.rsplit(".", 1)[-1])
            except ValueError:
                return 999

        return min(hosts, key=lambda h: _last_octet(h.ip))

    @staticmethod
    def _tooltip(host: Host) -> str:
        bits = [
            f"IP: {host.ip}",
            f"MAC: {host.mac}",
        ]
        if host.vendor:
            bits.append(f"Vendor: {host.vendor}")
        if host.hostname:
            bits.append(f"Hostname: {host.hostname}")
        if host.os_guess:
            bits.append(f"OS: {host.os_guess}")
        return "\n".join(bits)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        if self._scene.items():
            self._view.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
