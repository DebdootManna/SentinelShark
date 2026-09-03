"""
SentinelShark EDR — Dark Mode QSS Stylesheet
Migrated to Figma EDR design tokens (GitHub-dark palette).
Color tokens aligned with: SentinelShark UI Redesign (new)/src/App.tsx
"""

DARK_THEME_QSS = """
/* ════════════════════════════════════════════════════════════════════════
   Global Window & Widget Defaults — Figma EDR Design Tokens
   ════════════════════════════════════════════════════════════════════════ */
QWidget {
    background-color: #0D1117;
    color: #E6EDF3;
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #0D1117;
}

/* ── Menu Bar & Menus ──────────────────────────────────────────────────── */
QMenuBar {
    background-color: #161B22;
    color: #8B949E;
    border-bottom: 1px solid #30363D;
    padding: 2px 8px;
    font-weight: 500;
}

QMenuBar::item {
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #1C2128;
    color: #58A6FF;
}

QMenu {
    background-color: #161B22;
    color: #E6EDF3;
    border: 1px solid #30363D;
    padding: 4px;
    border-radius: 6px;
}

QMenu::item {
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #1C2128;
    color: #58A6FF;
}

/* ── ToolBar & Controls ────────────────────────────────────────────────── */
QToolBar {
    background-color: #161B22;
    border-bottom: 1px solid #30363D;
    padding: 8px 16px;
    spacing: 8px;
}

QToolButton {
    background-color: #161B22;
    color: #8B949E;
    border: 1px solid #30363D;
    border-radius: 8px;
    padding: 5px 12px;
    font-weight: 600;
}

QToolButton:hover {
    background-color: #1C2128;
    color: #58A6FF;
}

/* ── Inputs & ComboBoxes ───────────────────────────────────────────────── */
QLineEdit, QComboBox, QSpinBox {
    background-color: #0D1117;
    color: #E6EDF3;
    border: 1px solid #30363D;
    border-radius: 8px;
    padding: 5px 12px;
    selection-background-color: #1F3A5F;
    font-family: "JetBrains Mono", monospace;
    font-size: 13px;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #58A6FF;
}

QComboBox::drop-down {
    border: 0px;
    width: 20px;
}

/* ── Push Buttons (Default) ────────────────────────────────────────────── */
QPushButton {
    background-color: rgba(88, 166, 255, 0.1);
    color: #58A6FF;
    border: 1px solid #1F3A5F;
    border-radius: 8px;
    padding: 5px 14px;
    font-weight: 600;
    font-size: 13px;
}

QPushButton:hover {
    background-color: rgba(88, 166, 255, 0.2);
    color: #79C0FF;
    border-color: #58A6FF;
}

QPushButton:pressed {
    background-color: rgba(88, 166, 255, 0.3);
}

QPushButton:disabled {
    background-color: rgba(33, 38, 45, 0.5);
    color: #484F58;
    border: 1px solid #21262D;
}

/* ── Start / Stop / Clear / Mock Buttons ───────────────────────────────── */
QPushButton#startBtn {
    background-color: #2EA043;
    border: 1px solid #2EA043;
    color: #ffffff;
    border-radius: 12px;
    padding: 5px 16px;
    font-weight: 700;
}

QPushButton#startBtn:hover {
    background-color: #238636;
    border-color: #238636;
}

QPushButton#startBtn:disabled {
    background-color: rgba(46, 160, 67, 0.25);
    border: 1px solid #2EA043;
    color: #2EA043;
    font-weight: 700;
    border-radius: 12px;
}

QPushButton#stopBtn {
    background-color: rgba(248, 81, 73, 0.15);
    border: 1px solid #F85149;
    color: #F85149;
    border-radius: 12px;
    padding: 5px 16px;
    font-weight: 700;
}

QPushButton#stopBtn:hover {
    background-color: #DA3633;
    color: #ffffff;
}

QPushButton#stopBtn:disabled {
    background-color: rgba(33, 38, 45, 0.4);
    border: 1px solid #21262D;
    color: #484F58;
    border-radius: 12px;
    font-weight: 600;
}

QPushButton#clearBtn {
    background-color: transparent;
    border: 1px solid #30363D;
    color: #8B949E;
}

QPushButton#clearBtn:hover {
    background-color: #1C2128;
    color: #E6EDF3;
}

QPushButton#mockBtn:checked {
    background-color: rgba(88, 166, 255, 0.15);
    color: #58A6FF;
    border: 1px solid #58A6FF;
    font-weight: 600;
}

QPushButton#mockBtn:unchecked {
    background-color: transparent;
    color: #8B949E;
    border: 1px solid #30363D;
}

/* ── IR Action Bar Buttons ─────────────────────────────────────────────── */
QPushButton#killBtn {
    background-color: #3D1A1A;
    color: #F85149;
    border: 1px solid rgba(248, 81, 73, 0.38);
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.02em;
}

QPushButton#killBtn:hover {
    background-color: #5A1E1E;
    border-color: #F85149;
}

QPushButton#killBtn:disabled {
    background-color: rgba(33, 38, 45, 0.4);
    color: #484F58;
    border: 1px solid #21262D;
}

QPushButton#blockBtn {
    background-color: #3D2E0A;
    color: #D29922;
    border: 1px solid rgba(210, 153, 34, 0.38);
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.02em;
}

QPushButton#blockBtn:hover {
    background-color: #5A4010;
    border-color: #D29922;
}

QPushButton#quarantineBtn {
    background-color: transparent;
    color: #E6EDF3;
    border: 1px solid #30363D;
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: 600;
    font-size: 11px;
    letter-spacing: 0.02em;
}

QPushButton#quarantineBtn:hover {
    background-color: #1C2128;
    border-color: #484F58;
}

QPushButton#copyUdmBtn {
    background-color: transparent;
    color: #8B949E;
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: 500;
    font-size: 11px;
}

QPushButton#copyUdmBtn:hover {
    color: #E6EDF3;
    border-color: #30363D;
}

/* ── Tables & Tree Widgets ─────────────────────────────────────────────── */
QTableWidget, QTreeWidget {
    background-color: #0D1117;
    color: #E6EDF3;
    gridline-color: rgba(48, 54, 61, 0.5);
    border: 1px solid #30363D;
    border-radius: 0px;
    alternate-background-color: #161B22;
}

QTableWidget::item, QTreeWidget::item {
    padding: 4px 8px;
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
}

QTableWidget::item:selected, QTreeWidget::item:selected {
    background-color: rgba(31, 58, 95, 0.55);
    color: #ffffff;
}

QHeaderView::section {
    background-color: #161B22;
    color: #8B949E;
    font-weight: 700;
    font-size: 9px;
    letter-spacing: 0.08em;
    padding: 5px 10px;
    border: none;
    border-right: 1px solid #21262D;
    border-bottom: 1px solid #30363D;
    font-family: "JetBrains Mono", monospace;
    text-transform: uppercase;
}

/* ── Text Editors & Hex Inspector ──────────────────────────────────────── */
QTextEdit, QPlainTextEdit {
    background-color: #080C11;
    color: #58A6FF;
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
    border: 1px solid #30363D;
    border-radius: 0px;
    padding: 8px;
}

/* ── Splitter Handles ──────────────────────────────────────────────────── */
QSplitter::handle {
    background-color: #30363D;
    border-radius: 2px;
}

QSplitter::handle:hover {
    background-color: #58A6FF;
}

QSplitter::handle:horizontal {
    width: 6px;
}

QSplitter::handle:vertical {
    height: 6px;
}

/* ── ScrollBars ────────────────────────────────────────────────────────── */
QScrollBar:vertical {
    background-color: #0D1117;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #30363D;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #58A6FF;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #0D1117;
    height: 8px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background-color: #30363D;
    min-width: 20px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #58A6FF;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* ── Status Bar ────────────────────────────────────────────────────────── */
QStatusBar {
    background-color: #161B22;
    color: #8B949E;
    border-top: 1px solid #30363D;
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
}

QStatusBar::item {
    border: none;
}

/* ── Group Boxes & Cards ───────────────────────────────────────────────── */
QGroupBox {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 10px;
    margin-top: 16px;
    padding-top: 20px;
    font-weight: 700;
    color: #58A6FF;
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

/* ── Progress Bar ──────────────────────────────────────────────────────── */
QProgressBar {
    background-color: #21262D;
    border: none;
    border-radius: 2px;
    text-align: center;
    color: #E6EDF3;
    height: 4px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #58A6FF, stop:1 #3FB950);
    border-radius: 2px;
}
"""
