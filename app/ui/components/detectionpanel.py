import json
from typing import Dict, Any, Optional
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFrame, QSizePolicy, QApplication
)


# Figma color tokens
C = {
    "bg": "#0D1117", "surface": "#161B22", "border": "#30363D",
    "borderSubtle": "#21262D", "accent": "#58A6FF", "accentDim": "#1F3A5F",
    "danger": "#F85149", "dangerDim": "#3D1A1A", "dangerBorder": "#5A1E1E",
    "warning": "#D29922", "warningDim": "#3D2E0A", "warningBorder": "#5A4010",
    "safe": "#2EA043", "safeDim": "#122A19", "safeBorder": "#1A4025",
    "high": "#FF7B72", "highDim": "#2D1F1A", "highBorder": "#4A2A20",
    "text": "#E6EDF3", "textMuted": "#8B949E", "textDimmer": "#484F58",
}

SEVERITY_STYLES = {
    "critical": {"bg": C["dangerDim"], "fg": C["danger"], "border": C["dangerBorder"], "icon": "⚠", "label": "CRITICAL THREAT DETECTED"},
    "high":     {"bg": C["highDim"],   "fg": C["high"],   "border": C["highBorder"],   "icon": "⚡", "label": "HIGH SEVERITY EVENT"},
    "medium":   {"bg": C["warningDim"],"fg": C["warning"],"border": C["warningBorder"],"icon": "ℹ",  "label": "MEDIUM SEVERITY EVENT"},
    "safe":     {"bg": C["safeDim"],   "fg": C["safe"],   "border": C["safeBorder"],   "icon": "✓", "label": "LOW / SAFE EVENT"},
}


class DetectionDetailPanel(QWidget):
    """
    Center panel showing detection details, UDM JSON preview, and IR action bar.
    Matches the Figma EDR design.
    """

    # Signals for IR actions
    kill_requested = pyqtSignal(int)        # pid
    block_requested = pyqtSignal(str)       # ip
    quarantine_requested = pyqtSignal(str)  # file_path
    copy_udm_requested = pyqtSignal()       # copies UDM to clipboard

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_pkt: Optional[Dict[str, Any]] = None
        self.current_udm: Optional[Dict[str, Any]] = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Panel Header
        header = QFrame()
        header.setStyleSheet(f"""
            QFrame {{
                background-color: {C['surface']};
                border-bottom: 1px solid {C['border']};
                padding: 8px 14px;
            }}
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 8, 14, 8)
        header_lbl = QLabel("📋  DETECTION DETAIL")
        header_lbl.setStyleSheet(f"""
            font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
            text-transform: uppercase; color: {C['textMuted']};
            background: transparent; border: none;
        """)
        header_layout.addWidget(header_lbl)
        header_layout.addStretch()
        layout.addWidget(header)

        # Scrollable content area
        self.content_area = QWidget()
        self.content_layout = QVBoxLayout(self.content_area)
        self.content_layout.setContentsMargins(16, 12, 16, 12)
        self.content_layout.setSpacing(14)

        # Alert Header Card
        self.alert_card = QFrame()
        self.alert_card.setObjectName("alertCard")
        self.alert_card_layout = QVBoxLayout(self.alert_card)
        self.alert_card_layout.setContentsMargins(14, 10, 14, 10)
        self.alert_card_layout.setSpacing(8)

        # Top row: severity label + MITRE tag
        self.alert_top = QHBoxLayout()
        self.alert_severity_lbl = QLabel()
        self.alert_severity_lbl.setStyleSheet(f"font-size: 12px; font-weight: 700; background: transparent; border: none;")
        self.alert_mitre_lbl = QLabel()
        self.alert_mitre_lbl.setStyleSheet(f"""
            font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 3px;
            background-color: {C['accentDim']}; color: {C['accent']};
            border: 1px solid #2A4A7A; font-family: 'JetBrains Mono', monospace;
            letter-spacing: 0.04em;
        """)
        self.alert_top.addWidget(self.alert_severity_lbl)
        self.alert_top.addStretch()
        self.alert_top.addWidget(self.alert_mitre_lbl)
        self.alert_card_layout.addLayout(self.alert_top)

        # Info text
        self.alert_info_lbl = QLabel()
        self.alert_info_lbl.setWordWrap(True)
        self.alert_info_lbl.setStyleSheet(f"font-size: 11px; color: {C['text']}; background: transparent; border: none;")
        self.alert_card_layout.addWidget(self.alert_info_lbl)

        # Key-value row
        self.alert_kv_layout = QHBoxLayout()
        self.alert_kv_layout.setSpacing(16)
        self.kv_labels = {}
        for key in ["Time", "Src", "Dst", "Proto", "Port"]:
            container = QWidget()
            container.setStyleSheet("background: transparent; border: none;")
            vl = QVBoxLayout(container)
            vl.setContentsMargins(0, 0, 0, 0)
            vl.setSpacing(2)
            kl = QLabel(key.upper())
            kl.setStyleSheet(f"font-size: 9px; color: {C['textDimmer']}; text-transform: uppercase; letter-spacing: 0.06em; background: transparent; border: none;")
            vv = QLabel("—")
            vv.setStyleSheet(f"font-size: 10px; color: {C['text']}; font-family: 'JetBrains Mono', monospace; background: transparent; border: none;")
            vl.addWidget(kl)
            vl.addWidget(vv)
            self.alert_kv_layout.addWidget(container)
            self.kv_labels[key.lower()] = vv

        self.alert_card_layout.addLayout(self.alert_kv_layout)
        self.content_layout.addWidget(self.alert_card)

        # UDM JSON Preview
        udm_header = QLabel("UDM EVENT JSON")
        udm_header.setStyleSheet(f"""
            font-size: 9px; font-weight: 700; letter-spacing: 0.08em;
            text-transform: uppercase; color: {C['textMuted']};
        """)
        self.content_layout.addWidget(udm_header)

        self.udm_text = QTextEdit()
        self.udm_text.setReadOnly(True)
        self.udm_text.setMaximumHeight(220)
        self.udm_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: #080C11;
                color: {C['textMuted']};
                font-family: 'JetBrains Mono', monospace;
                font-size: 9px;
                border: 1px solid {C['border']};
                border-radius: 4px;
                padding: 10px 12px;
                line-height: 1.7;
            }}
        """)
        self.content_layout.addWidget(self.udm_text)

        # Empty state
        self.empty_lbl = QLabel("Select a packet to view detection details")
        self.empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_lbl.setStyleSheet(f"color: {C['textDimmer']}; font-size: 12px; padding: 40px;")
        self.content_layout.addWidget(self.empty_lbl)

        self.content_layout.addStretch()
        layout.addWidget(self.content_area, stretch=1)

        # IR Action Bar (bottom)
        self.action_bar = QFrame()
        self.action_bar.setStyleSheet(f"""
            QFrame {{
                background-color: {C['surface']};
                border-top: 1px solid {C['border']};
            }}
        """)
        action_layout = QHBoxLayout(self.action_bar)
        action_layout.setContentsMargins(14, 10, 14, 10)
        action_layout.setSpacing(8)

        ir_label = QLabel("IR ACTIONS")
        ir_label.setStyleSheet(f"""
            font-size: 9px; font-weight: 700; letter-spacing: 0.08em;
            text-transform: uppercase; color: {C['textDimmer']};
            background: transparent; border: none;
        """)
        action_layout.addWidget(ir_label)

        self.kill_btn = QPushButton("⛔ Kill Process")
        self.kill_btn.setObjectName("killBtn")
        self.kill_btn.setEnabled(False)
        self.kill_btn.clicked.connect(self._on_kill)
        action_layout.addWidget(self.kill_btn)

        self.block_btn = QPushButton("🛡️ Block Remote IP")
        self.block_btn.setObjectName("blockBtn")
        self.block_btn.setEnabled(False)
        self.block_btn.clicked.connect(self._on_block)
        action_layout.addWidget(self.block_btn)

        self.quarantine_btn = QPushButton("📦 Quarantine Binary")
        self.quarantine_btn.setObjectName("quarantineBtn")
        self.quarantine_btn.setEnabled(False)
        self.quarantine_btn.clicked.connect(self._on_quarantine)
        action_layout.addWidget(self.quarantine_btn)

        self.copy_udm_btn = QPushButton("📋 Copy UDM JSON")
        self.copy_udm_btn.setObjectName("copyUdmBtn")
        self.copy_udm_btn.setEnabled(False)
        self.copy_udm_btn.clicked.connect(self._on_copy_udm)
        action_layout.addWidget(self.copy_udm_btn)

        action_layout.addStretch()
        layout.addWidget(self.action_bar)

    def display_packet(self, pkt: Optional[Dict[str, Any]]):
        """Update the detection detail panel for the selected packet."""
        self.current_pkt = pkt

        if not pkt:
            self.alert_card.setVisible(False)
            self.udm_text.setVisible(False)
            self.empty_lbl.setVisible(True)
            self.kill_btn.setEnabled(False)
            self.block_btn.setEnabled(False)
            self.quarantine_btn.setEnabled(False)
            self.copy_udm_btn.setEnabled(False)
            return

        self.empty_lbl.setVisible(False)
        self.alert_card.setVisible(True)
        self.udm_text.setVisible(True)

        severity = pkt.get("severity", "safe")
        style = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["safe"])

        # Style the alert card
        self.alert_card.setStyleSheet(f"""
            QFrame#alertCard {{
                background-color: {style['bg']};
                border: 1px solid {style['border']};
                border-radius: 6px;
            }}
        """)

        self.alert_severity_lbl.setText(f"{style['icon']} {style['label']}")
        self.alert_severity_lbl.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {style['fg']}; background: transparent; border: none;")

        mitre_tags = pkt.get("mitre_tags", [])
        if mitre_tags:
            self.alert_mitre_lbl.setText(", ".join(mitre_tags))
            self.alert_mitre_lbl.setVisible(True)
        else:
            self.alert_mitre_lbl.setVisible(False)

        self.alert_info_lbl.setText(pkt.get("info", ""))

        # Key-value fields
        self.kv_labels.get("time", QLabel()).setText(pkt.get("time", "—"))
        self.kv_labels.get("src", QLabel()).setText(pkt.get("src", "—"))
        self.kv_labels.get("dst", QLabel()).setText(pkt.get("dst", "—"))
        self.kv_labels.get("proto", QLabel()).setText(pkt.get("protocol", "—"))
        self.kv_labels.get("port", QLabel()).setText(str(pkt.get("dst_port", "—")))

        # Build UDM JSON
        from app.core.secops_engine import normalize_to_udm
        process_data = {
            "pid": pkt.get("pid", 0),
            "ppid": pkt.get("ppid", 0),
            "name": pkt.get("process_name", ""),
            "cmdline": pkt.get("cmdline", ""),
            "username": pkt.get("username", ""),
            "exe_path": pkt.get("exe_path", ""),
            "sha256": pkt.get("exe_sha256", ""),
        }
        threat_intel = pkt.get("threat_data", {}) or {}
        self.current_udm = normalize_to_udm(pkt, process_data, threat_intel)
        self.udm_text.setPlainText(json.dumps(self.current_udm, indent=2))

        # Enable/disable IR buttons
        pid = pkt.get("pid")
        self.kill_btn.setEnabled(bool(pid and isinstance(pid, int) and pid > 1))
        self.block_btn.setEnabled(bool(pkt.get("dst")))
        self.quarantine_btn.setEnabled(bool(pkt.get("exe_path")))
        self.copy_udm_btn.setEnabled(True)

    def _on_kill(self):
        if self.current_pkt:
            pid = self.current_pkt.get("pid")
            if pid:
                self.kill_requested.emit(int(pid))

    def _on_block(self):
        if self.current_pkt:
            ip = self.current_pkt.get("dst", "")
            if ip:
                self.block_requested.emit(ip)

    def _on_quarantine(self):
        if self.current_pkt:
            path = self.current_pkt.get("exe_path", "")
            if path:
                self.quarantine_requested.emit(path)

    def _on_copy_udm(self):
        if self.current_udm:
            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(json.dumps(self.current_udm, indent=2))
            self.copy_udm_requested.emit()
