"""Control panel — cut / restore hosts via ARP spoofing."""

from __future__ import annotations

from typing import Any

from PyQt6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from cuttix.gui.state import StateStore


class ControlPanelView(QWidget):
    """Manual ARP control UI — target input, action buttons, active list."""

    def __init__(self, store: StateStore, controller: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._store = store
        self._ctrl = controller

        # target input box
        form = QFormLayout()
        self._target_ip = QLineEdit()
        self._target_ip.setPlaceholderText("192.168.1.50")
        form.addRow("Target IP:", self._target_ip)

        self._cut_btn = QPushButton("Cut (ARP spoof)")
        self._cut_btn.clicked.connect(self._on_cut)
        self._restore_btn = QPushButton("Restore")
        self._restore_btn.clicked.connect(self._on_restore)

        btns = QHBoxLayout()
        btns.addWidget(self._cut_btn)
        btns.addWidget(self._restore_btn)

        input_group = QGroupBox("Manual target")
        input_layout = QVBoxLayout(input_group)
        input_layout.addLayout(form)
        input_layout.addLayout(btns)

        # active spoofs list
        self._active = QListWidget()
        self._restore_all_btn = QPushButton("Restore all")
        self._restore_all_btn.clicked.connect(self._on_restore_all)

        active_group = QGroupBox("Active spoofs")
        active_layout = QVBoxLayout(active_group)
        active_layout.addWidget(self._active)
        active_layout.addWidget(self._restore_all_btn)

        # legal disclaimer
        disclaimer = QLabel(
            "Use ONLY on networks you own or have written authorization to test.\n"
            "Unauthorized use is illegal (French Penal Code Art. 323-1 to 323-3)."
        )
        disclaimer.setWordWrap(True)
        disclaimer.setObjectName("legalDisclaimer")

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(16)
        root.addWidget(disclaimer)
        root.addWidget(input_group)
        root.addWidget(active_group, stretch=1)

        # wire store
        store.host_cut.connect(self._on_host_cut)
        store.host_restored.connect(self._on_host_restored)

    # -- actions --

    def _on_cut(self) -> None:
        ip = self._target_ip.text().strip()
        if not ip:
            return
        if not self._confirm(
            "Cut target",
            f"Send ARP spoof packets targeting {ip}?\n\n"
            "This disrupts the host's network access until you restore it.",
        ):
            return
        try:
            self._ctrl.cut(ip)
        except Exception as exc:
            self._error(f"Could not cut {ip}", str(exc))

    def _on_restore(self) -> None:
        ip = self._target_ip.text().strip()
        if not ip:
            return
        try:
            self._ctrl.restore(ip)
        except Exception as exc:
            self._error(f"Could not restore {ip}", str(exc))

    def _on_restore_all(self) -> None:
        if not self._confirm("Restore all", "Restore ALL active targets?"):
            return
        try:
            self._ctrl.restore_all()
        except Exception as exc:
            self._error("Restore all failed", str(exc))

    def _on_host_cut(self, ip: str) -> None:
        for i in range(self._active.count()):
            if self._active.item(i).text() == ip:
                return
        self._active.addItem(QListWidgetItem(ip))

    def _on_host_restored(self, ip: str) -> None:
        for i in range(self._active.count()):
            if self._active.item(i).text() == ip:
                self._active.takeItem(i)
                return

    # -- helpers --

    def _confirm(self, title: str, msg: str) -> bool:
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        return box.exec() == QMessageBox.StandardButton.Yes

    def _error(self, title: str, msg: str) -> None:
        QMessageBox.critical(self, title, msg)
