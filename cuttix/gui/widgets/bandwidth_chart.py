"""Bandwidth chart view — custom-painted time-series of bytes/sec.

Polls the StateStore's BandwidthAggregator on a timer (default 1Hz) and
redraws a small line chart for the selected host (or "All hosts").
We deliberately avoid pulling in matplotlib/pyqtgraph; a hand-rolled
QPainter draw is plenty for a 60-point series.
"""

from __future__ import annotations

from PyQt6.QtCore import QPointF, QRect, Qt, QTimer
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from cuttix.gui.bandwidth import BandwidthAggregator, BandwidthPoint
from cuttix.gui.state import StateStore

CHART_PAD_LEFT = 56
CHART_PAD_RIGHT = 16
CHART_PAD_TOP = 16
CHART_PAD_BOTTOM = 28


class _ChartCanvas(QWidget):
    """The drawing area itself, repainted on demand by the parent view."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._series: list[BandwidthPoint] = []
        self.setMinimumHeight(220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setAutoFillBackground(False)

    def set_series(self, points: list[BandwidthPoint]) -> None:
        self._series = points
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = self.rect()
        painter.fillRect(rect, QBrush(QColor("#181820")))

        plot = QRect(
            rect.left() + CHART_PAD_LEFT,
            rect.top() + CHART_PAD_TOP,
            rect.width() - CHART_PAD_LEFT - CHART_PAD_RIGHT,
            rect.height() - CHART_PAD_TOP - CHART_PAD_BOTTOM,
        )

        # axes
        axis_pen = QPen(QColor("#3a3a44"), 1)
        painter.setPen(axis_pen)
        painter.drawLine(plot.left(), plot.top(), plot.left(), plot.bottom())
        painter.drawLine(plot.left(), plot.bottom(), plot.right(), plot.bottom())

        if not self._series:
            self._draw_empty(painter, plot)
            return

        # determine y scale (round up to nearest "nice" number)
        max_val = max(p.total for p in self._series) or 1
        y_max = self._nice_ceiling(max_val)

        # gridlines + y labels
        grid_pen = QPen(QColor("#26262e"), 1, Qt.PenStyle.DashLine)
        label_color = QColor("#6c7480")
        font = QFont()
        font.setPointSize(8)
        painter.setFont(font)
        for i in range(1, 5):
            y = plot.bottom() - (plot.height() * i / 4)
            painter.setPen(grid_pen)
            painter.drawLine(plot.left(), int(y), plot.right(), int(y))
            label = BandwidthAggregator.format_rate(y_max * i / 4)
            painter.setPen(QPen(label_color))
            painter.drawText(
                rect.left(),
                int(y) - 8,
                CHART_PAD_LEFT - 6,
                16,
                int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                label,
            )

        # plot points
        n = len(self._series)
        if n == 1:
            x = plot.left() + plot.width() / 2
            y = plot.bottom() - (self._series[0].total / y_max) * plot.height()
            painter.setPen(QPen(QColor("#3498db"), 2))
            painter.drawEllipse(QPointF(x, y), 3, 3)
            self._draw_x_label(painter, plot, "now")
            return

        step = plot.width() / (n - 1)
        line_pen = QPen(QColor("#3498db"), 2)
        line_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        line_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(line_pen)

        prev: QPointF | None = None
        for i, point in enumerate(self._series):
            x = plot.left() + i * step
            y = plot.bottom() - (point.total / y_max) * plot.height()
            current = QPointF(x, y)
            if prev is not None:
                painter.drawLine(prev, current)
            prev = current

        # x-axis labels: leftmost = "-Ns", rightmost = "now"
        seconds_back = self._series[-1].timestamp - self._series[0].timestamp
        self._draw_x_label(painter, plot, f"-{seconds_back}s", align_left=True)
        self._draw_x_label(painter, plot, "now")

    def _draw_empty(self, painter: QPainter, plot: QRect) -> None:
        painter.setPen(QPen(QColor("#6c7480")))
        font = QFont()
        font.setPointSize(10)
        painter.setFont(font)
        painter.drawText(plot, int(Qt.AlignmentFlag.AlignCenter), "No traffic captured yet.")

    def _draw_x_label(
        self, painter: QPainter, plot: QRect, text: str, align_left: bool = False
    ) -> None:
        painter.setPen(QPen(QColor("#6c7480")))
        font = QFont()
        font.setPointSize(8)
        painter.setFont(font)
        if align_left:
            painter.drawText(
                plot.left() - 4, plot.bottom() + 4, 60, 18, int(Qt.AlignmentFlag.AlignLeft), text
            )
        else:
            painter.drawText(
                plot.right() - 56, plot.bottom() + 4, 60, 18, int(Qt.AlignmentFlag.AlignRight), text
            )

    @staticmethod
    def _nice_ceiling(val: float) -> float:
        """Round ``val`` up to the next 1/2/5 * 10**k."""
        if val <= 0:
            return 1.0
        import math

        exponent = math.floor(math.log10(val))
        base = 10**exponent
        for mult in (1, 2, 5, 10):
            ceiling = mult * base
            if ceiling >= val:
                return ceiling
        return 10 * base


class BandwidthChartView(QWidget):
    """Container with a host selector + the chart canvas + a rate readout."""

    REFRESH_MS_DEFAULT = 1000

    def __init__(
        self, store: StateStore, refresh_ms: int = REFRESH_MS_DEFAULT, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._selected_host: str | None = None  # None = global

        self._title = QLabel("Bandwidth")
        title_font = QFont()
        title_font.setPointSize(13)
        title_font.setBold(True)
        self._title.setFont(title_font)

        self._host_picker = QComboBox()
        self._host_picker.addItem("All hosts", userData=None)
        self._host_picker.currentIndexChanged.connect(self._on_host_changed)

        self._rate_label = QLabel("0 B/s")
        self._rate_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        rate_font = QFont()
        rate_font.setPointSize(11)
        self._rate_label.setFont(rate_font)

        header = QHBoxLayout()
        header.addWidget(self._title)
        header.addSpacing(20)
        header.addWidget(QLabel("Host:"))
        header.addWidget(self._host_picker)
        header.addStretch(1)
        header.addWidget(self._rate_label)

        self._canvas = _ChartCanvas()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addLayout(header)
        layout.addWidget(self._canvas, stretch=1)

        store.host_added.connect(self._refresh_host_list)
        store.host_removed.connect(self._refresh_host_list)

        self._timer = QTimer(self)
        self._timer.setInterval(max(refresh_ms, 100))
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self._tick()

    # -- slots --

    def _on_host_changed(self, index: int) -> None:
        self._selected_host = self._host_picker.itemData(index)
        self._tick()

    def _refresh_host_list(self, *_args) -> None:
        # remember the current selection so we can restore it
        current = self._selected_host
        self._host_picker.blockSignals(True)
        self._host_picker.clear()
        self._host_picker.addItem("All hosts", userData=None)
        for host in sorted(self._store.get_hosts(), key=lambda h: h.ip):
            label = f"{host.ip}"
            if host.hostname:
                label = f"{host.hostname} ({host.ip})"
            self._host_picker.addItem(label, userData=host.ip)
        # try to restore selection
        if current:
            for i in range(self._host_picker.count()):
                if self._host_picker.itemData(i) == current:
                    self._host_picker.setCurrentIndex(i)
                    break
        self._host_picker.blockSignals(False)

    def _tick(self) -> None:
        agg = self._store.bandwidth
        series = agg.snapshot(self._selected_host)
        self._canvas.set_series(series)
        rate = agg.current_rate(self._selected_host)
        self._rate_label.setText(BandwidthAggregator.format_rate(rate))
