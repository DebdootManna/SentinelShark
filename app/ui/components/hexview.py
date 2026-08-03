from typing import Dict, Any, Optional
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel, QLineEdit
)


class HexView(QWidget):
    """
    Raw Hex & ASCII Inspector component.
    Presents offset line numbers, 16-byte hex representation, and ASCII characters.
    Also displays payload hashes (MD5 & SHA256).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Header
        top_bar = QHBoxLayout()
        title_lbl = QLabel("Raw Packet Bytes (Hex / ASCII)")
        title_lbl.setStyleSheet("font-weight: bold; color: #38bdf8; font-size: 13px;")
        top_bar.addWidget(title_lbl)
        top_bar.addStretch()
        layout.addLayout(top_bar)

        # Hex Text Editor
        self.hex_edit = QTextEdit()
        self.hex_edit.setReadOnly(True)
        self.hex_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.hex_edit)

        # Hash bar
        hash_bar = QHBoxLayout()
        hash_bar.addWidget(QLabel("Payload MD5:"))
        self.md5_val = QLineEdit()
        self.md5_val.setReadOnly(True)
        self.md5_val.setStyleSheet("font-family: monospace; font-size: 11px;")
        hash_bar.addWidget(self.md5_val)

        hash_bar.addWidget(QLabel("SHA256:"))
        self.sha256_val = QLineEdit()
        self.sha256_val.setReadOnly(True)
        self.sha256_val.setStyleSheet("font-family: monospace; font-size: 11px;")
        hash_bar.addWidget(self.sha256_val)

        layout.addLayout(hash_bar)

    def display_packet(self, pkt: Optional[Dict[str, Any]]):
        """Display hex dump and hashes for selected packet."""
        if not pkt:
            self.hex_edit.clear()
            self.md5_val.clear()
            self.sha256_val.clear()
            return

        hex_dump = pkt.get("hex_dump", "")
        self.hex_edit.setPlainText(hex_dump)
        self.md5_val.setText(pkt.get("payload_md5", ""))
        self.sha256_val.setText(pkt.get("payload_sha256", ""))
