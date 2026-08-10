from typing import Dict, Any, Optional
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel, QLineEdit
)


class HexView(QWidget):
    """
    Raw Hex & ASCII Inspector component.
    Presents offset line numbers, 16-byte hex representation, and ASCII characters.
    Also displays payload hashes (MD5 & SHA256) matching Redesigned UI.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Header bar
        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(8, 4, 8, 4)
        
        title_lbl = QLabel("Raw Packet Bytes")
        title_lbl.setStyleSheet("font-weight: 700; color: #22D3EE; font-size: 12px; font-family: 'JetBrains Mono', monospace;")
        
        sub_lbl = QLabel("Hex / ASCII")
        sub_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-family: 'JetBrains Mono', monospace;")

        self.size_lbl = QLabel("")
        self.size_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-family: 'JetBrains Mono', monospace;")

        top_bar.addWidget(title_lbl)
        top_bar.addWidget(sub_lbl)
        top_bar.addStretch()
        top_bar.addWidget(self.size_lbl)
        layout.addLayout(top_bar)

        # Hex Text Editor
        self.hex_edit = QTextEdit()
        self.hex_edit.setReadOnly(True)
        self.hex_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.hex_edit.setStyleSheet("""
            QTextEdit {
                background-color: #000810;
                color: #22D3EE;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                border: 1px solid #1E293B;
                padding: 8px;
            }
        """)
        layout.addWidget(self.hex_edit)

        # Hash Chips Bar
        hash_bar = QHBoxLayout()
        hash_bar.setContentsMargins(4, 2, 4, 4)
        hash_bar.setSpacing(8)

        lbl_md5 = QLabel("MD5:")
        lbl_md5.setStyleSheet("color: #22D3EE; font-weight: 600; font-family: monospace; font-size: 10px;")
        self.md5_val = QLineEdit()
        self.md5_val.setReadOnly(True)
        self.md5_val.setStyleSheet("""
            QLineEdit {
                background-color: #0A1520;
                color: #94A3B8;
                border: 1px solid #1A2535;
                border-radius: 4px;
                padding: 2px 6px;
                font-family: monospace;
                font-size: 10px;
            }
        """)

        lbl_sha256 = QLabel("SHA256:")
        lbl_sha256.setStyleSheet("color: #22D3EE; font-weight: 600; font-family: monospace; font-size: 10px;")
        self.sha256_val = QLineEdit()
        self.sha256_val.setReadOnly(True)
        self.sha256_val.setStyleSheet("""
            QLineEdit {
                background-color: #0A1520;
                color: #94A3B8;
                border: 1px solid #1A2535;
                border-radius: 4px;
                padding: 2px 6px;
                font-family: monospace;
                font-size: 10px;
            }
        """)

        hash_bar.addWidget(lbl_md5)
        hash_bar.addWidget(self.md5_val, stretch=1)
        hash_bar.addWidget(lbl_sha256)
        hash_bar.addWidget(self.sha256_val, stretch=2)

        layout.addLayout(hash_bar)

    def display_packet(self, pkt: Optional[Dict[str, Any]]):
        """Display hex dump and hashes for selected packet."""
        if not pkt:
            self.hex_edit.clear()
            self.md5_val.clear()
            self.sha256_val.clear()
            self.size_lbl.setText("")
            return

        length = pkt.get("length", 0)
        self.size_lbl.setText(f"{length} bytes")
        hex_dump = pkt.get("hex_dump", "")
        self.hex_edit.setPlainText(hex_dump)
        self.md5_val.setText(pkt.get("payload_md5", ""))
        self.sha256_val.setText(pkt.get("payload_sha256", ""))
