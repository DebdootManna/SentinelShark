"""
SentinelShark - Modern Cyber Dark Mode QSS Stylesheet
Designed for high-performance desktop NIDS aesthetics based on the Redesigned UI.
"""

DARK_THEME_QSS = """
/* Global Window & Widget Defaults */
QWidget {
    background-color: #0B1220;
    color: #E2E8F0;
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #0B1220;
}

/* Menu Bar & Menus */
QMenuBar {
    background-color: #0A101C;
    color: #94A3B8;
    border-bottom: 1px solid #1E293B;
    padding: 2px 8px;
    font-weight: 500;
}

QMenuBar::item {
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #131C2B;
    color: #22D3EE;
}

QMenu {
    background-color: #131C2B;
    color: #E2E8F0;
    border: 1px solid #1E293B;
    padding: 4px;
    border-radius: 6px;
}

QMenu::item {
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #1E293B;
    color: #22D3EE;
}

/* ToolBar & Controls */
QToolBar {
    background-color: #131C2B;
    border-bottom: 1px solid #1E293B;
    padding: 8px 16px;
    spacing: 8px;
}

QToolButton {
    background-color: #131C2B;
    color: #94A3B8;
    border: 1px solid #1E293B;
    border-radius: 8px;
    padding: 5px 12px;
    font-weight: 600;
}

QToolButton:hover {
    background-color: #1E293B;
    color: #22D3EE;
}

/* Inputs & ComboBoxes */
QLineEdit, QComboBox, QSpinBox {
    background-color: #0B1220;
    color: #E2E8F0;
    border: 1px solid #1E293B;
    border-radius: 8px;
    padding: 5px 12px;
    selection-background-color: #1D4ED8;
    font-family: "JetBrains Mono", monospace;
    font-size: 13px;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #22D3EE;
}

QComboBox::drop-down {
    border: 0px;
    width: 20px;
}

/* Push Buttons */
QPushButton {
    background-color: rgba(37, 99, 235, 0.15);
    color: #3B82F6;
    border: 1px solid #2563EB;
    border-radius: 8px;
    padding: 5px 14px;
    font-weight: 600;
    font-size: 13px;
}

QPushButton:hover {
    background-color: rgba(37, 99, 235, 0.3);
    color: #60A5FA;
    border-color: #3B82F6;
}

QPushButton:pressed {
    background-color: rgba(37, 99, 235, 0.4);
}

QPushButton:disabled {
    background-color: rgba(30, 41, 59, 0.5);
    color: #475569;
    border: 1px solid #1E293B;
}

QPushButton#startBtn {
    background-color: #22C55E;
    border: 1px solid #22C55E;
    color: #ffffff;
    border-radius: 12px;
    padding: 5px 16px;
    font-weight: 700;
}

QPushButton#startBtn:hover {
    background-color: #16A34A;
    border-color: #16A34A;
}

QPushButton#startBtn:disabled {
    background-color: rgba(6, 78, 59, 0.4);
    border: 1px solid #22C55E;
    color: #22C55E;
    font-weight: 700;
    border-radius: 12px;
}

QPushButton#stopBtn {
    background-color: rgba(127, 29, 29, 0.6);
    border: 1px solid #EF4444;
    color: #EF4444;
    border-radius: 12px;
    padding: 5px 16px;
    font-weight: 700;
}

QPushButton#stopBtn:hover {
    background-color: #DC2626;
    color: #ffffff;
}

QPushButton#stopBtn:disabled {
    background-color: rgba(30, 41, 59, 0.4);
    border: 1px solid #1E293B;
    color: #475569;
    border-radius: 12px;
    font-weight: 600;
}

QPushButton#clearBtn {
    background-color: transparent;
    border: 1px solid #1E293B;
    color: #94A3B8;
}

QPushButton#clearBtn:hover {
    background-color: #1E293B;
    color: #E2E8F0;
}

QPushButton#mockBtn:checked {
    background-color: rgba(37, 99, 235, 0.25);
    color: #3B82F6;
    border: 1px solid #3B82F6;
    font-weight: 600;
}

QPushButton#mockBtn:unchecked {
    background-color: transparent;
    color: #94A3B8;
    border: 1px solid #1E293B;
}

/* Tables & Tree Widgets */
QTableWidget, QTreeWidget {
    background-color: #131C2B;
    color: #E2E8F0;
    gridline-color: rgba(30, 41, 59, 0.5);
    border: 1px solid #1E293B;
    border-radius: 0px;
    alternate-background-color: #0F1622;
}

QTableWidget::item, QTreeWidget::item {
    padding: 4px 8px;
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
}

QTableWidget::item:selected, QTreeWidget::item:selected {
    background-color: rgba(29, 78, 216, 0.35);
    color: #ffffff;
}

QHeaderView::section {
    background-color: #0A101C;
    color: #22D3EE;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.06em;
    padding: 6px 8px;
    border: none;
    border-right: 1px solid #1E293B;
    border-bottom: 1px solid #1E293B;
    font-family: "JetBrains Mono", monospace;
    text-transform: uppercase;
}

/* Text Editors & Hex Inspector */
QTextEdit, QPlainTextEdit {
    background-color: #000810;
    color: #22D3EE;
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
    border: 1px solid #1E293B;
    border-radius: 0px;
    padding: 8px;
}

/* Splitter Handles */
QSplitter::handle {
    background-color: #1E293B;
    border-radius: 2px;
}

QSplitter::handle:hover {
    background-color: #22D3EE;
}

QSplitter::handle:horizontal {
    width: 6px;
}

QSplitter::handle:vertical {
    height: 6px;
}

/* ScrollBars */
QScrollBar:vertical {
    background-color: #0B1220;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #1E293B;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #22D3EE;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #0B1220;
    height: 8px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background-color: #1E293B;
    min-width: 20px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #22D3EE;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* Status Bar */
QStatusBar {
    background-color: #060C14;
    color: #94A3B8;
    border-top: 1px solid #1E293B;
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
}

QStatusBar::item {
    border: none;
}

/* Group Boxes & Cards */
QGroupBox {
    background-color: #131C2B;
    border: 1px solid #1E293B;
    border-radius: 10px;
    margin-top: 16px;
    padding-top: 20px;
    font-weight: 700;
    color: #22D3EE;
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    text-transform: uppercase;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    top: 0px;
    padding: 0 6px;
}

/* Progress Bar */
QProgressBar {
    background-color: #1E293B;
    border: none;
    border-radius: 2px;
    text-align: center;
    color: #E2E8F0;
    height: 4px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #22D3EE, stop:1 #2DD4BF);
    border-radius: 2px;
}
"""
