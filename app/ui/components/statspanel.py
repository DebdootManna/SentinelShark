from typing import Dict, Any
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QGroupBox, QProgressBar
)


class StatCard(QGroupBox):
    """Sleek metric card displaying counter values and visual indicators."""

    def __init__(self, title: str, initial_value: str = "0", accent_color: str = "#38bdf8", parent=None):
        super().__init__(title, parent)
        self.accent_color = accent_color
        self.init_ui(initial_value)

    def init_ui(self, initial_value: str):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        
        self.value_lbl = QLabel(initial_value)
        self.value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_lbl.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {self.accent_color};")
        layout.addWidget(self.value_lbl)

    def set_value(self, val: str):
        self.value_lbl.setText(val)


class StatsPanel(QWidget):
    """
    Live NIDS Statistics Panel.
    Tracks packet counts, bandwidth, protocol distribution, and threat distribution.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.total_packets = 0
        self.total_bytes = 0
        self.safe_count = 0
        self.suspicious_count = 0
        self.critical_count = 0
        self.protocols: Dict[str, int] = {}
        
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        # Metric Cards Grid
        grid = QGridLayout()
        grid.setSpacing(6)

        self.card_packets = StatCard("TOTAL PACKETS", "0", "#38bdf8")
        self.card_bytes = StatCard("DATA TRAFFIC", "0 KB", "#818cf8")
        self.card_safe = StatCard("SAFE PACKETS", "0", "#34d399")
        self.card_critical = StatCard("THREATS DETECTED", "0", "#f87171")

        grid.addWidget(self.card_packets, 0, 0)
        grid.addWidget(self.card_bytes, 0, 1)
        grid.addWidget(self.card_safe, 1, 0)
        grid.addWidget(self.card_critical, 1, 1)

        layout.addLayout(grid)

        # Protocol Breakdown Group
        proto_group = QGroupBox("Protocol Breakdown")
        proto_layout = QVBoxLayout(proto_group)
        self.proto_lbl = QLabel("TCP: 0  |  UDP: 0  |  HTTP: 0  |  DNS: 0  |  Other: 0")
        self.proto_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        proto_layout.addWidget(self.proto_lbl)
        layout.addWidget(proto_group)

        # Threat Queue Indicator
        queue_group = QGroupBox("Threat Intel API Queue")
        queue_layout = QVBoxLayout(queue_group)
        self.queue_bar = QProgressBar()
        self.queue_bar.setRange(0, 100)
        self.queue_bar.setValue(0)
        self.queue_lbl = QLabel("Queue Idle (0 pending)")
        self.queue_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        queue_layout.addWidget(self.queue_lbl)
        queue_layout.addWidget(self.queue_bar)
        layout.addWidget(queue_group)

        layout.addStretch()

    def update_packet_stats(self, pkt: Dict[str, Any]):
        """Record new packet statistics."""
        self.total_packets += 1
        pkt_bytes = pkt.get("length", 0)
        self.total_bytes += pkt_bytes

        # Protocol counts
        proto = pkt.get("protocol", "OTHER").upper()
        self.protocols[proto] = self.protocols.get(proto, 0) + 1

        # Update cards
        self.card_packets.set_value(f"{self.total_packets:,}")
        
        # Bytes formatting
        if self.total_bytes > 1024 * 1024:
            bytes_str = f"{self.total_bytes / (1024 * 1024):.2f} MB"
        else:
            bytes_str = f"{self.total_bytes / 1024:.1f} KB"
        self.card_bytes.set_value(bytes_str)

        # Protocol summary string
        tcp = self.protocols.get("TCP", 0)
        udp = self.protocols.get("UDP", 0)
        http = self.protocols.get("HTTP", 0)
        dns = self.protocols.get("DNS", 0)
        other = self.total_packets - (tcp + udp + http + dns)
        self.proto_lbl.setText(f"TCP: {tcp} | UDP: {udp} | HTTP: {http} | DNS: {dns} | Other: {other}")

    def update_threat_stats(self, threat_data: Dict[str, Any]):
        """Record threat intelligence classification stats."""
        abuse = threat_data.get("abuse_score", 0)
        vt_mal = threat_data.get("vt_malicious", 0)

        if vt_mal > 0 or abuse > 30:
            self.critical_count += 1
        elif abuse > 0:
            self.suspicious_count += 1
        else:
            self.safe_count += 1

        self.card_safe.set_value(f"{self.safe_count:,}")
        self.card_critical.set_value(f"{self.critical_count:,}")

    def update_queue_status(self, pending: int, in_progress: int):
        """Update threat intel queue progress bar."""
        total = pending + in_progress
        if total == 0:
            self.queue_bar.setValue(0)
            self.queue_lbl.setText("Queue Idle (0 pending)")
        else:
            self.queue_bar.setValue(min(total * 10, 100))
            self.queue_lbl.setText(f"API Lookups: {pending} pending, {in_progress} active")

    def reset_stats(self):
        """Clear all counter metrics."""
        self.total_packets = 0
        self.total_bytes = 0
        self.safe_count = 0
        self.suspicious_count = 0
        self.critical_count = 0
        self.protocols.clear()

        self.card_packets.set_value("0")
        self.card_bytes.set_value("0 KB")
        self.card_safe.set_value("0")
        self.card_critical.set_value("0")
        self.proto_lbl.setText("TCP: 0  |  UDP: 0  |  HTTP: 0  |  DNS: 0  |  Other: 0")
        self.update_queue_status(0, 0)
