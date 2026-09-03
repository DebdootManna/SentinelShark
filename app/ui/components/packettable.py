from typing import Dict, Any, Optional, List
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QBrush
from PyQt6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)

from app.config import config


# Figma EDR severity color map
SEVERITY_COLORS = {
    "critical": {"bg": QColor(61, 26, 26, 200), "fg": QColor(248, 81, 73)},
    "high":     {"bg": QColor(45, 31, 26, 180), "fg": QColor(255, 123, 114)},
    "medium":   {"bg": QColor(61, 46, 10, 160), "fg": QColor(210, 153, 34)},
    "safe":     {"bg": QColor(18, 42, 25, 180), "fg": QColor(46, 160, 67)},
}


class PacketTable(QTableWidget):
    """
    High-performance packet table component displaying real-time network traffic
    with EDR telemetry: PID, Process, MITRE ATT&CK tags, and Severity classification.
    """

    packet_selected = pyqtSignal(dict)

    COLUMNS = ["No.", "Time", "PID", "Process", "Source", "Destination", "Protocol", "Length", "MITRE", "Severity", "Info"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.packets: List[Dict[str, Any]] = []
        self.ip_row_map: Dict[str, List[int]] = {}
        self.current_filter: str = ""
        self.init_ui()

    def init_ui(self):
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(False)

        header = self.horizontalHeader()
        # No., Time, PID, Process, Source, Destination, Protocol, Length, MITRE, Severity, Info
        for i in range(len(self.COLUMNS)):
            if i == 10:  # Info
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)

        self.setColumnWidth(0, 50)    # No.
        self.setColumnWidth(1, 95)    # Time
        self.setColumnWidth(2, 55)    # PID
        self.setColumnWidth(3, 90)    # Process
        self.setColumnWidth(4, 120)   # Source
        self.setColumnWidth(5, 120)   # Destination
        self.setColumnWidth(6, 65)    # Protocol
        self.setColumnWidth(7, 55)    # Length
        self.setColumnWidth(8, 85)    # MITRE
        self.setColumnWidth(9, 75)    # Severity

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
        
        search_target = (
            f"{pkt.get('src', '')} {pkt.get('dst', '')} {pkt.get('protocol', '')} "
            f"{pkt.get('info', '')} {pkt.get('src_port', '')} {pkt.get('dst_port', '')} "
            f"{pkt.get('process_name', '')} {pkt.get('pid', '')} "
            f"{' '.join(pkt.get('mitre_tags', []))}"
        ).lower()
        
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

        return all(tok in search_target for tok in tokens)

    def _update_row_visibility(self, row: int):
        if row < len(self.packets):
            pkt = self.packets[row]
            visible = self._matches_filter(pkt)
            self.setRowHidden(row, not visible)

    def add_packets_batch(self, pkt_list: List[Dict[str, Any]]):
        """Append a list of packets in a single high-performance UI batch repaint cycle."""
        if not pkt_list:
            return

        self.setUpdatesEnabled(False)
        last_visible_row = -1

        try:
            for pkt in pkt_list:
                row = self.rowCount()
                self.insertRow(row)
                self.packets.append(pkt)

                src_ip = pkt.get("src", "")
                dst_ip = pkt.get("dst", "")

                if src_ip:
                    self.ip_row_map.setdefault(src_ip, []).append(row)
                if dst_ip:
                    self.ip_row_map.setdefault(dst_ip, []).append(row)

                # Extract EDR fields
                pid_val = pkt.get("pid", "")
                process_name = pkt.get("process_name", "")
                mitre_tags = pkt.get("mitre_tags", [])
                mitre_str = ", ".join(mitre_tags) if mitre_tags else "—"
                severity = pkt.get("severity", "safe")

                items = [
                    QTableWidgetItem(str(pkt.get("no", row + 1))),       # 0: No.
                    QTableWidgetItem(str(pkt.get("time", ""))),           # 1: Time
                    QTableWidgetItem(str(pid_val)),                       # 2: PID
                    QTableWidgetItem(str(process_name)),                  # 3: Process
                    QTableWidgetItem(str(src_ip)),                        # 4: Source
                    QTableWidgetItem(str(dst_ip)),                        # 5: Destination
                    QTableWidgetItem(str(pkt.get("protocol", ""))),       # 6: Protocol
                    QTableWidgetItem(str(pkt.get("length", 0))),          # 7: Length
                    QTableWidgetItem(mitre_str),                          # 8: MITRE
                    QTableWidgetItem(severity.upper()),                   # 9: Severity
                    QTableWidgetItem(str(pkt.get("info", ""))),           # 10: Info
                ]

                # Alignment
                items[0].setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                items[2].setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                items[7].setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                items[9].setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                # PID accent color
                if pid_val:
                    items[2].setForeground(QBrush(QColor(88, 166, 255)))  # accent

                # Protocol accent color
                items[6].setForeground(QBrush(QColor(88, 166, 255)))

                # MITRE tag styling (blue pill look via color)
                if mitre_tags:
                    items[8].setForeground(QBrush(QColor(88, 166, 255)))
                else:
                    items[8].setForeground(QBrush(QColor(72, 79, 88)))  # textDimmer

                # Severity coloring
                sev_colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["safe"])
                items[9].setForeground(QBrush(sev_colors["fg"]))
                sev_font = items[9].font()
                sev_font.setBold(True)
                items[9].setFont(sev_font)

                # Process styling - highlight LOLBins
                from app.core.secops_engine import LOLBIN_SET
                if process_name.lower() in LOLBIN_SET:
                    items[3].setForeground(QBrush(QColor(248, 81, 73)))  # danger
                    pf = items[3].font()
                    pf.setBold(True)
                    items[3].setFont(pf)

                for col, item in enumerate(items):
                    self.setItem(row, col, item)

                self._apply_row_style(row, pkt)
                self._update_row_visibility(row)

                if not self.isRowHidden(row):
                    last_visible_row = row
        finally:
            self.setUpdatesEnabled(True)

        if config.auto_scroll and last_visible_row >= 0:
            self.scrollToBottom()

    def add_packet(self, pkt: Dict[str, Any]):
        """Append packet to table with styled items."""
        self.add_packets_batch([pkt])

    def update_threat_intel(self, ip: str, threat_data: Dict[str, Any]):
        """Dynamically update severity and color-coding for all matching packet rows."""
        rows = self.ip_row_map.get(ip, [])
        for row in rows:
            if row < len(self.packets):
                self.packets[row]["threat_data"] = threat_data

                # Recompute severity with threat data
                from app.core.secops_engine import compute_severity
                process_data = {
                    "name": self.packets[row].get("process_name", ""),
                    "pid": self.packets[row].get("pid", 0),
                }
                mitre_tags = self.packets[row].get("mitre_tags", [])
                new_severity = compute_severity(threat_data, mitre_tags, process_data)
                self.packets[row]["severity"] = new_severity

                # Update severity column text
                sev_item = self.item(row, 9)
                if sev_item:
                    sev_item.setText(new_severity.upper())
                    sev_colors = SEVERITY_COLORS.get(new_severity, SEVERITY_COLORS["safe"])
                    sev_item.setForeground(QBrush(sev_colors["fg"]))

                self._apply_row_style(row, self.packets[row])

    def _apply_row_style(self, row: int, pkt: Dict[str, Any]):
        """Apply dynamic row background color based on severity classification."""
        severity = pkt.get("severity", "safe")
        sev_colors = SEVERITY_COLORS.get(severity)

        if not sev_colors:
            return

        # Only color rows with non-safe severity or confirmed public IPs
        if severity == "safe":
            threat_data = pkt.get("threat_data")
            if threat_data and threat_data.get("is_public") is True:
                bg_color = sev_colors["bg"]
            else:
                return  # Don't color unanalyzed safe rows
        else:
            bg_color = sev_colors["bg"]

        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                item.setBackground(QBrush(bg_color))
                if severity in ("critical", "high"):
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
