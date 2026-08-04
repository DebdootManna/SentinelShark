from typing import Dict, Any, Optional, List
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QBrush
from PyQt6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)

from app.config import config


class PacketTable(QTableWidget):
    """
    High-performance packet table component displaying real-time network traffic.
    Applies dynamic color-coding based on VirusTotal & AbuseIPDB Threat Intelligence scores.
    """

    packet_selected = pyqtSignal(dict)

    COLUMNS = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Threat Score"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.packets: List[Dict[str, Any]] = []
        self.ip_row_map: Dict[str, List[int]] = {}  # Maps IP -> list of row indices
        self.current_filter: str = ""
        self.init_ui()

    def init_ui(self):
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)

        # Table Behavior
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(False)  # Disabled during live capture for performance

        # Header sizing
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)  # No.
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)  # Time
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)  # Source
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)  # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)  # Length
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)      # Info
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Interactive)  # Threat Score

        self.setColumnWidth(0, 60)
        self.setColumnWidth(1, 100)
        self.setColumnWidth(2, 130)
        self.setColumnWidth(3, 130)
        self.setColumnWidth(4, 80)
        self.setColumnWidth(5, 70)
        self.setColumnWidth(7, 120)

        self.itemSelectionChanged.connect(self._on_selection_changed)

    def set_filter_query(self, query: str):
        """Filter visible packet rows in table based on query matching src, dst, protocol, or info."""
        self.current_filter = query.strip().lower()
        for row in range(self.rowCount()):
            self._update_row_visibility(row)

    def _matches_filter(self, pkt: Dict[str, Any]) -> bool:
        if not self.current_filter:
            return True
        q = self.current_filter
        tokens = q.split()
        
        search_target = f"{pkt.get('src', '')} {pkt.get('dst', '')} {pkt.get('protocol', '')} {pkt.get('info', '')} {pkt.get('src_port', '')} {pkt.get('dst_port', '')}".lower()
        
        # Support "ip src X" or "ip dst X"
        if "ip" in tokens and "src" in tokens:
            try:
                idx = tokens.index("src") + 1
                if idx < len(tokens):
                    return pkt.get("src", "").lower() == tokens[idx]
            except ValueError:
                pass
        if "ip" in tokens and "dst" in tokens:
            try:
                idx = tokens.index("dst") + 1
                if idx < len(tokens):
                    return pkt.get("dst", "").lower() == tokens[idx]
            except ValueError:
                pass
        if "port" in tokens:
            try:
                idx = tokens.index("port") + 1
                if idx < len(tokens):
                    pval = tokens[idx]
                    return str(pkt.get("src_port", "")) == pval or str(pkt.get("dst_port", "")) == pval
            except ValueError:
                pass

        # Substring/Token match
        return all(tok in search_target for tok in tokens)

    def _update_row_visibility(self, row: int):
        if row < len(self.packets):
            pkt = self.packets[row]
            visible = self._matches_filter(pkt)
            self.setRowHidden(row, not visible)

    def add_packet(self, pkt: Dict[str, Any]):
        """Append packet to table with styled items."""
        row = self.rowCount()
        self.insertRow(row)
        self.packets.append(pkt)

        src_ip = pkt.get("src", "")
        dst_ip = pkt.get("dst", "")

        # Track row indices for IP updates
        if src_ip:
            self.ip_row_map.setdefault(src_ip, []).append(row)
        if dst_ip:
            self.ip_row_map.setdefault(dst_ip, []).append(row)

        threat_str = "0% (Safe)"
        items = [
            QTableWidgetItem(str(pkt.get("no", row + 1))),
            QTableWidgetItem(str(pkt.get("time", ""))),
            QTableWidgetItem(str(src_ip)),
            QTableWidgetItem(str(dst_ip)),
            QTableWidgetItem(str(pkt.get("protocol", ""))),
            QTableWidgetItem(str(pkt.get("length", 0))),
            QTableWidgetItem(str(pkt.get("info", ""))),
            QTableWidgetItem(threat_str)
        ]

        # Right-align number & length
        items[0].setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        items[5].setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        items[7].setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        for col, item in enumerate(items):
            self.setItem(row, col, item)

        # Apply initial styling
        self._apply_row_style(row, pkt.get("threat_data"))

        # Apply current filter visibility
        self._update_row_visibility(row)

        # Auto-scroll if enabled and row is visible
        if config.auto_scroll and not self.isRowHidden(row):
            self.scrollToBottom()

    def update_threat_intel(self, ip: str, threat_data: Dict[str, Any]):
        """Dynamically update threat score and color-coding for all matching packet rows."""
        rows = self.ip_row_map.get(ip, [])
        for row in rows:
            if row < len(self.packets):
                # Calculate threat score
                abuse_score = threat_data.get("abuse_score", 0)
                vt_malicious = threat_data.get("vt_malicious", 0)

                # Store threat data in packet model
                self.packets[row]["threat_data"] = threat_data
                self.packets[row]["threat_score"] = max(abuse_score, vt_malicious * 20)

                # Update Threat Score text column
                if vt_malicious > 0:
                    score_text = f"CRITICAL ({vt_malicious} VT)"
                elif abuse_score > 30:
                    score_text = f"HIGH ({abuse_score}%)"
                elif abuse_score > 0:
                    score_text = f"MED ({abuse_score}%)"
                elif threat_data.get("is_public") is False:
                    score_text = "Internal IP"
                else:
                    score_text = "0% (Safe)"

                item = self.item(row, 7)
                if item:
                    item.setText(score_text)

                self._apply_row_style(row, threat_data)

    def _apply_row_style(self, row: int, threat_data: Optional[Dict[str, Any]]):
        """Apply dynamic color-coding based on threat classification."""
        if not threat_data:
            return

        abuse_score = threat_data.get("abuse_score", 0)
        vt_malicious = threat_data.get("vt_malicious", 0)

        bg_color = None
        text_color = None
        font_bold = False

        if vt_malicious > 0 or abuse_score > 30:
            # Critical Threat: Red / Dark Crimson
            bg_color = QColor(127, 29, 29, 200)   # #7f1d1d
            text_color = QColor(254, 202, 202)   # #fecaca
            font_bold = True
        elif abuse_score > 0 or threat_data.get("vt_suspicious", 0) > 0:
            # Low-Medium Risk: Amber / Orange
            bg_color = QColor(120, 53, 15, 180)   # #78350f
            text_color = QColor(254, 243, 199)   # #fef3c7
        elif threat_data.get("is_public") is True:
            # Safe Public IP: Dark Green
            bg_color = QColor(6, 78, 59, 160)     # #064e3b
            text_color = QColor(209, 250, 229)   # #d1fae5

        if bg_color:
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    item.setBackground(QBrush(bg_color))
                    if text_color:
                        item.setForeground(QBrush(text_color))
                    if font_bold:
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)

    def _on_selection_changed(self):
        """Emit selected packet data when row selection changes."""
        selected_rows = self.selectedIndexes()
        if selected_rows:
            row = selected_rows[0].row()
            if 0 <= row < len(self.packets):
                self.packet_selected.emit(self.packets[row])

    def clear_table(self):
        """Reset table and clear packets buffer."""
        self.setRowCount(0)
        self.packets.clear()
        self.ip_row_map.clear()
