"""Dark stylesheet — placeholder until Gemini-generated design lands.

Kept in one string so it's easy to swap for a polished theme later.
"""

from __future__ import annotations

DARK_QSS = """
* {
    font-family: "Segoe UI", "SF Pro Display", "Inter", sans-serif;
    font-size: 10pt;
    color: #ecf0f1;
}

QMainWindow, QWidget {
    background-color: #1e1e24;
}

QLabel {
    color: #ecf0f1;
}

#legalDisclaimer {
    color: #f39c12;
    font-size: 9pt;
    padding: 8px;
    border: 1px solid #f39c12;
    border-radius: 4px;
    background-color: #2a2a32;
}

QFrame#kpiCard {
    background-color: #2a2a32;
    border: 1px solid #3a3a44;
    border-radius: 8px;
    min-height: 80px;
}
QLabel#kpiValue {
    font-size: 28pt;
    font-weight: 600;
    color: #ecf0f1;
}
QLabel#kpiTitle {
    font-size: 9pt;
    color: #95a5a6;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

QTableWidget {
    background-color: #252530;
    alternate-background-color: #2a2a32;
    gridline-color: #3a3a44;
    border: 1px solid #3a3a44;
    selection-background-color: #3498db;
    selection-color: #ffffff;
}
QTableWidget::item {
    padding: 6px;
}
QHeaderView::section {
    background-color: #1e1e24;
    color: #95a5a6;
    padding: 8px;
    border: none;
    border-right: 1px solid #3a3a44;
    border-bottom: 1px solid #3a3a44;
    font-weight: 600;
}

QPushButton {
    background-color: #3498db;
    color: #ffffff;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #2980b9;
}
QPushButton:pressed {
    background-color: #1f6491;
}
QPushButton:disabled {
    background-color: #555;
    color: #999;
}

QLineEdit {
    background-color: #2a2a32;
    border: 1px solid #3a3a44;
    padding: 6px 10px;
    border-radius: 4px;
    color: #ecf0f1;
}
QLineEdit:focus {
    border-color: #3498db;
}

QGroupBox {
    border: 1px solid #3a3a44;
    border-radius: 6px;
    padding: 12px;
    margin-top: 12px;
    color: #95a5a6;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
}

QListWidget {
    background-color: #252530;
    border: 1px solid #3a3a44;
    border-radius: 4px;
}
QListWidget::item {
    padding: 8px;
}
QListWidget::item:selected {
    background-color: #3498db;
}

QStatusBar {
    background-color: #1e1e24;
    color: #95a5a6;
    border-top: 1px solid #3a3a44;
}

/* sidebar nav */
QListWidget#sidebar {
    background-color: #17171c;
    border: none;
    border-right: 1px solid #3a3a44;
    padding: 8px 0;
    font-size: 11pt;
}
QListWidget#sidebar::item {
    padding: 12px 20px;
    border-left: 3px solid transparent;
}
QListWidget#sidebar::item:selected {
    background-color: #252530;
    border-left: 3px solid #3498db;
    color: #ffffff;
}
QListWidget#sidebar::item:hover {
    background-color: #1e1e24;
}
"""
