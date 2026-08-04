"""
SentinelShark - Modern Cyber Dark Mode QSS Stylesheet
Designed for high-performance desktop NIDS aesthetics.
"""

DARK_THEME_QSS = """
/* Global Window & Widget Defaults */
QWidget {
    background-color: #0f172a;
    color: #f8fafc;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #0f172a;
}

/* Menu Bar & Menus */
QMenuBar {
    background-color: #1e293b;
    color: #f8fafc;
    border-bottom: 1px solid #334155;
    padding: 2px 4px;
}

QMenuBar::item {
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #334155;
    color: #38bdf8;
}

QMenu {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
    padding: 4px;
    border-radius: 6px;
}

QMenu::item {
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}

/* ToolBar & Controls */
QToolBar {
    background-color: #1e293b;
    border-bottom: 1px solid #334155;
    padding: 6px;
    spacing: 8px;
}

QToolButton {
    background-color: #334155;
    color: #f8fafc;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 6px 12px;
    font-weight: 600;
}

QToolButton:hover {
    background-color: #0284c7;
    border-color: #38bdf8;
    color: #ffffff;
}

QToolButton:pressed {
    background-color: #0369a1;
}

/* Inputs & ComboBoxes */
QLineEdit, QComboBox, QSpinBox {
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: #0284c7;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #38bdf8;
}

QComboBox::drop-down {
    border: 0px;
    width: 20px;
}

/* Push Buttons */
QPushButton {
    background-color: #0284c7;
    color: #ffffff;
    border: 1px solid #0369a1;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #0369a1;
    border-color: #38bdf8;
}

QPushButton:pressed {
    background-color: #075985;
    border-color: #0284c7;
}

QPushButton:disabled {
    background-color: #1e293b;
    color: #64748b;
    border: 1px solid #334155;
}

QPushButton#startBtn {
    background-color: #16a34a;
    border: 1px solid #15803d;
    color: #ffffff;
}

QPushButton#startBtn:hover {
    background-color: #22c55e;
    border-color: #4ade80;
}

QPushButton#startBtn:pressed {
    background-color: #15803d;
    border-color: #16a34a;
}

QPushButton#startBtn:disabled {
    background-color: #1e293b;
    color: #475569;
    border: 1px solid #334155;
}

QPushButton#stopBtn {
    background-color: #dc2626;
    border: 1px solid #b91c1c;
    color: #ffffff;
}

QPushButton#stopBtn:hover {
    background-color: #ef4444;
    border-color: #f87171;
}

QPushButton#stopBtn:pressed {
    background-color: #b91c1c;
    border-color: #dc2626;
}

QPushButton#stopBtn:disabled {
    background-color: #1e293b;
    color: #475569;
    border: 1px solid #334155;
}

QPushButton:checked {
    background-color: #f59e0b;
    color: #0f172a;
    border: 1px solid #d97706;
    font-weight: 700;
}

QPushButton#mockBtn:checked {
    background-color: #f59e0b;
    color: #0f172a;
    border: 1px solid #d97706;
    font-weight: 700;
}

QPushButton#mockBtn:checked:hover {
    background-color: #fbbf24;
    border-color: #f59e0b;
}

/* Tables & Tree Widgets */
QTableWidget, QTreeWidget {
    background-color: #1e293b;
    color: #f8fafc;
    gridline-color: #334155;
    border: 1px solid #334155;
    border-radius: 8px;
    alternate-background-color: #162032;
}

QTableWidget::item, QTreeWidget::item {
    padding: 6px 8px;
}

QTableWidget::item:selected, QTreeWidget::item:selected {
    background-color: #0284c7;
    color: #ffffff;
}

QHeaderView::section {
    background-color: #0f172a;
    color: #38bdf8;
    font-weight: 700;
    padding: 8px;
    border: none;
    border-right: 1px solid #334155;
    border-bottom: 2px solid #38bdf8;
}

/* Text Editors & Hex Inspector */
QTextEdit, QPlainTextEdit {
    background-color: #090d16;
    color: #38bdf8;
    font-family: "JetBrains Mono", "Fira Code", "Courier New", monospace;
    font-size: 12px;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px;
}

/* Splitter Handles */
QSplitter::handle {
    background-color: #334155;
    height: 4px;
    width: 4px;
}

QSplitter::handle:hover {
    background-color: #38bdf8;
}

/* Status Bar */
QStatusBar {
    background-color: #1e293b;
    color: #94a3b8;
    border-top: 1px solid #334155;
}

QStatusBar::item {
    border: none;
}

/* Group Boxes & Cards */
QGroupBox {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    margin-top: 12px;
    font-weight: 700;
    color: #38bdf8;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
}

/* Progress Bar */
QProgressBar {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    text-align: center;
    color: #ffffff;
}

QProgressBar::chunk {
    background-color: #0284c7;
    border-radius: 6px;
}
"""
