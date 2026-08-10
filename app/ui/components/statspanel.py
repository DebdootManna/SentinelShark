from typing import Dict, Any, Optional
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QGroupBox, QProgressBar, QFrame
)
from app.config import config


PROTO_COLORS = {
    "DNS": "#60A5FA",
    "TLS": "#34D399",
    "HTTPS": "#34D399",
    "HTTP": "#FBBF24",
    "TCP": "#94A3B8",
    "UDP": "#A78BFA",
    "ICMP": "#38BDF8",
    "ICMPV6": "#38BDF8",
    "ARP": "#818CF8",
    "QUIC": "#2DD4BF",
    "SSH": "#F87171",
    "OTHER": "#94A3B8"
}

TRACKED_PROTOCOLS = ["TCP", "HTTPS", "HTTP", "DNS", "TLS", "UDP", "ICMP", "ICMPV6", "ARP", "QUIC", "SSH", "OTHER"]


class StatCard(QFrame):
    """Sleek metric card displaying counter values matching Redesigned UI."""

    def __init__(self, title: str, initial_value: str = "0", accent_color: str = "#22D3EE", parent=None):
        super().__init__(parent)
        self.accent_color = accent_color
        self.setStyleSheet("""
            QFrame {
                background-color: #131C2B;
                border: 1px solid #1E293B;
                border-radius: 10px;
            }
        """)
        self.init_ui(title, initial_value)

    def init_ui(self, title: str, initial_value: str):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("""
            font-size: 10px;
            color: #94A3B8;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            border: none;
            background: transparent;
        """)
        layout.addWidget(self.title_lbl)

        self.value_lbl = QLabel(initial_value)
        self.value_lbl.setStyleSheet(f"""
            font-size: 16px;
            font-weight: bold;
            color: {self.accent_color};
            font-family: 'JetBrains Mono', monospace;
            border: none;
            background: transparent;
        """)
        layout.addWidget(self.value_lbl)

    def set_value(self, val: str):
        self.value_lbl.setText(val)


class StatsPanel(QWidget):
    """
    Live NIDS Statistics Panel matching Redesigned UI.
    Tracks packet counts, bandwidth, protocol distribution, threat distribution,
    and 4-API Threat Intel Queue status (VirusTotal, AbuseIPDB, Shodan, IPinfo).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.total_packets = 0
        self.total_bytes = 0
        self.safe_count = 0
        self.suspicious_count = 0
        self.critical_count = 0
        self.protocols: Dict[str, int] = {}
        self.selected_pkt: Optional[Dict[str, Any]] = None
        self.proto_row_widgets: Dict[str, dict] = {}

        self.setMinimumWidth(300)
        self.setMinimumHeight(520)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        # 1. Metric Cards 2x2 Grid
        grid = QGridLayout()
        grid.setSpacing(8)

        self.card_packets = StatCard("TOTAL PACKETS", "0", "#22D3EE")
        self.card_bytes = StatCard("DATA TRAFFIC", "0.0 KB", "#2DD4BF")
        self.card_safe = StatCard("SAFE PACKETS", "0", "#4ADE80")
        self.card_threats = StatCard("THREATS DETECTED", "0", "#EF4444")

        grid.addWidget(self.card_packets, 0, 0)
        grid.addWidget(self.card_bytes, 0, 1)
        grid.addWidget(self.card_safe, 1, 0)
        grid.addWidget(self.card_threats, 1, 1)

        layout.addLayout(grid)

        # 2. Protocol Breakdown Panel
        proto_box = QGroupBox("PROTOCOL BREAKDOWN")
        proto_box.setStyleSheet("""
            QGroupBox {
                background-color: #131C2B;
                border: 1px solid #1E293B;
                border-radius: 10px;
                margin-top: 6px;
                padding-top: 18px;
            }
            QGroupBox::title {
                color: #22D3EE;
                font-weight: 700;
                font-size: 11px;
                font-family: 'JetBrains Mono', monospace;
                subcontrol-origin: margin;
                left: 12px;
                top: 2px;
            }
        """)
        self.proto_layout = QVBoxLayout(proto_box)
        self.proto_layout.setContentsMargins(12, 10, 12, 12)
        self.proto_layout.setSpacing(6)

        self.proto_empty_lbl = QLabel("No protocol data recorded")
        self.proto_empty_lbl.setStyleSheet("color: #94A3B8; font-family: monospace; font-size: 11px;")
        self.proto_layout.addWidget(self.proto_empty_lbl)

        # Build reusable protocol row widgets ahead of time to avoid layout stacking/leaks
        for proto in TRACKED_PROTOCOLS:
            row_container = QWidget()
            row_layout = QHBoxLayout(row_container)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(8)

            lbl_proto = QLabel(proto)
            lbl_proto.setFixedWidth(52)
            lbl_proto.setStyleSheet("color: #94A3B8; font-family: 'JetBrains Mono', monospace; font-size: 11px;")

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setTextVisible(False)
            bar.setFixedHeight(4)
            color = PROTO_COLORS.get(proto, "#94A3B8")
            bar.setStyleSheet(f"""
                QProgressBar {{
                    background-color: #1E293B;
                    border: none;
                    border-radius: 2px;
                }}
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 2px;
                }}
            """)

            lbl_count = QLabel("0")
            lbl_count.setFixedWidth(32)
            lbl_count.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_count.setStyleSheet("color: #E2E8F0; font-family: 'JetBrains Mono', monospace; font-size: 11px;")

            row_layout.addWidget(lbl_proto)
            row_layout.addWidget(bar)
            row_layout.addWidget(lbl_count)

            row_container.setVisible(False)
            self.proto_layout.addWidget(row_container)
            self.proto_row_widgets[proto] = {
                "container": row_container,
                "bar": bar,
                "count": lbl_count
            }

        layout.addWidget(proto_box)

        # 3. Threat Intel API Queue Panel (VirusTotal, AbuseIPDB, Shodan, IPinfo)
        queue_box = QGroupBox("THREAT INTEL API QUEUE")
        queue_box.setStyleSheet("""
            QGroupBox {
                background-color: #131C2B;
                border: 1px solid #1E293B;
                border-radius: 10px;
                margin-top: 6px;
                padding-top: 18px;
            }
            QGroupBox::title {
                color: #22D3EE;
                font-weight: 700;
                font-size: 11px;
                font-family: 'JetBrains Mono', monospace;
                subcontrol-origin: margin;
                left: 12px;
                top: 2px;
            }
        """)
        queue_layout = QVBoxLayout(queue_box)
        queue_layout.setContentsMargins(12, 10, 12, 12)
        queue_layout.setSpacing(6)

        # API Items
        self.vt_status = self._create_api_status_row("VirusTotal", config.virustotal_api_key)
        self.abuse_status = self._create_api_status_row("AbuseIPDB", config.abuseipdb_api_key)
        self.shodan_status = self._create_api_status_row("Shodan", config.shodan_api_key)
        self.ipinfo_status = self._create_api_status_row("IPinfo", config.ipinfo_api_key)

        queue_layout.addLayout(self.vt_status['layout'])
        queue_layout.addLayout(self.abuse_status['layout'])
        queue_layout.addLayout(self.shodan_status['layout'])
        queue_layout.addLayout(self.ipinfo_status['layout'])

        # Queue Progress
        q_header = QHBoxLayout()
        q_label = QLabel("Queue Processing")
        q_label.setStyleSheet("color: #94A3B8; font-size: 11px;")
        self.queue_counter_lbl = QLabel("0 / 0")
        self.queue_counter_lbl.setStyleSheet("color: #E2E8F0; font-family: monospace; font-size: 11px;")
        q_header.addWidget(q_label)
        q_header.addStretch()
        q_header.addWidget(self.queue_counter_lbl)
        queue_layout.addLayout(q_header)

        self.queue_bar = QProgressBar()
        self.queue_bar.setRange(0, 100)
        self.queue_bar.setValue(0)
        self.queue_bar.setTextVisible(False)
        self.queue_bar.setFixedHeight(4)
        queue_layout.addWidget(self.queue_bar)

        layout.addWidget(queue_box)

        # 4. Selected Packet Summary Card
        self.pkt_box = QGroupBox("SELECTED PACKET")
        self.pkt_box.setStyleSheet("""
            QGroupBox {
                background-color: #131C2B;
                border: 1px solid #1E293B;
                border-radius: 10px;
                margin-top: 6px;
                padding-top: 18px;
            }
            QGroupBox::title {
                color: #22D3EE;
                font-weight: 700;
                font-size: 11px;
                font-family: 'JetBrains Mono', monospace;
                subcontrol-origin: margin;
                left: 12px;
                top: 2px;
            }
        """)
        self.pkt_layout = QVBoxLayout(self.pkt_box)
        self.pkt_layout.setContentsMargins(12, 10, 12, 12)
        self.pkt_layout.setSpacing(4)

        self.pkt_empty_lbl = QLabel("No packet selected")
        self.pkt_empty_lbl.setStyleSheet("color: #94A3B8; font-family: monospace; font-size: 11px;")
        self.pkt_layout.addWidget(self.pkt_empty_lbl)

        # Pre-create key-value rows for Protocol, Source, Dest, Size
        self.pkt_detail_widgets = {}
        for key_label, dict_key in [("Protocol", "proto"), ("Source", "src"), ("Dest", "dst"), ("Size", "size")]:
            container = QWidget()
            row = QHBoxLayout(container)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(8)

            lbl_k = QLabel(key_label)
            lbl_k.setStyleSheet("color: #94A3B8; font-size: 11px;")

            lbl_v = QLabel("")
            lbl_v.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_v.setStyleSheet("color: #E2E8F0; font-family: 'JetBrains Mono', monospace; font-size: 11px;")

            row.addWidget(lbl_k)
            row.addStretch()
            row.addWidget(lbl_v)

            container.setVisible(False)
            self.pkt_layout.addWidget(container)

            self.pkt_detail_widgets[dict_key] = {
                "container": container,
                "val": lbl_v
            }

        layout.addWidget(self.pkt_box)
        layout.addStretch()

    def _create_api_status_row(self, name: str, key_val: str) -> dict:
        layout = QHBoxLayout()
        lbl_name = QLabel(name)
        lbl_name.setStyleSheet("color: #94A3B8; font-size: 12px;")

        lbl_state = QLabel()
        lbl_state.setStyleSheet("font-family: monospace; font-size: 11px;")
        
        if key_val:
            lbl_state.setText("Connected")
            lbl_state.setStyleSheet("color: #22C55E; font-family: monospace; font-size: 11px;")
        else:
            lbl_state.setText("Not Configured")
            lbl_state.setStyleSheet("color: #64748B; font-family: monospace; font-size: 11px;")

        layout.addWidget(lbl_name)
        layout.addStretch()
        layout.addWidget(lbl_state)
        return {"layout": layout, "state": lbl_state}

    def update_packet_stats(self, pkt: Dict[str, Any]):
        """Record new packet statistics."""
        self.total_packets += 1
        pkt_bytes = pkt.get("length", 0)
        self.total_bytes += pkt_bytes

        # Protocol counts
        raw_proto = pkt.get("protocol", "OTHER").upper()
        proto = raw_proto if raw_proto in TRACKED_PROTOCOLS else "OTHER"
        self.protocols[proto] = self.protocols.get(proto, 0) + 1

        # Update metric cards
        self.card_packets.set_value(f"{self.total_packets:,}")
        
        if self.total_bytes > 1024 * 1024:
            bytes_str = f"{self.total_bytes / (1024 * 1024):.1f} MB"
        else:
            bytes_str = f"{self.total_bytes / 1024:.1f} KB"
        self.card_bytes.set_value(bytes_str)

        self._refresh_protocol_bars()

    def _refresh_protocol_bars(self):
        """Render top protocol distribution bars matching Redesigned UI smoothly without layout recreation."""
        top_protos = sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)[:5]
        
        if not top_protos:
            self.proto_empty_lbl.setVisible(True)
            for w in self.proto_row_widgets.values():
                w["container"].setVisible(False)
            return

        self.proto_empty_lbl.setVisible(False)
        active_protos = set()

        for proto, count in top_protos:
            active_protos.add(proto)
            w = self.proto_row_widgets.get(proto) or self.proto_row_widgets["OTHER"]
            w["bar"].setRange(0, max(self.total_packets, 1))
            w["bar"].setValue(count)
            w["count"].setText(str(count))
            w["container"].setVisible(True)

        for proto, w in self.proto_row_widgets.items():
            if proto not in active_protos:
                w["container"].setVisible(False)

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
        self.card_threats.set_value(f"{self.critical_count:,}")

    def update_queue_status(self, pending: int, in_progress: int):
        """Update threat intel queue progress bar and status tags."""
        total = pending + in_progress
        self.queue_counter_lbl.setText(f"{in_progress} / {total}")
        if total == 0:
            self.queue_bar.setValue(0)
        else:
            pct = int((in_progress / total) * 100) if total > 0 else 0
            self.queue_bar.setValue(min(pct, 100))

        # Refresh API Key status text dynamically
        for key_name, widget_dict in [
            ("virustotal", self.vt_status),
            ("abuseipdb", self.abuse_status),
            ("shodan", self.shodan_status),
            ("ipinfo", self.ipinfo_status)
        ]:
            key_val = getattr(config, f"{key_name}_api_key", "")
            lbl = widget_dict["state"]
            if key_name == "shodan":
                if key_val:
                    lbl.setText("Connected (Host API)")
                else:
                    lbl.setText("Connected (InternetDB)")
                lbl.setStyleSheet("color: #22C55E; font-family: monospace; font-size: 11px;")
            elif key_val:
                lbl.setText("Connected")
                lbl.setStyleSheet("color: #22C55E; font-family: monospace; font-size: 11px;")
            else:
                lbl.setText("Not Configured")
                lbl.setStyleSheet("color: #64748B; font-family: monospace; font-size: 11px;")

    def set_selected_packet(self, pkt: Optional[Dict[str, Any]]):
        """Display summary card details for selected packet matching Redesigned UI."""
        self.selected_pkt = pkt
        if not pkt:
            self.pkt_box.setTitle("SELECTED PACKET")
            self.pkt_empty_lbl.setVisible(True)
            for w in self.pkt_detail_widgets.values():
                w["container"].setVisible(False)
            return

        no = pkt.get("no", "")
        self.pkt_box.setTitle(f"SELECTED: PACKET #{no}")
        self.pkt_empty_lbl.setVisible(False)

        self.pkt_detail_widgets["proto"]["val"].setText(str(pkt.get("protocol", "N/A")))
        self.pkt_detail_widgets["src"]["val"].setText(str(pkt.get("src", "N/A")))
        self.pkt_detail_widgets["dst"]["val"].setText(str(pkt.get("dst", "N/A")))
        self.pkt_detail_widgets["size"]["val"].setText(f"{pkt.get('length', 0)} bytes")

        for w in self.pkt_detail_widgets.values():
            w["container"].setVisible(True)

    def reset_stats(self):
        """Clear all counter metrics."""
        self.total_packets = 0
        self.total_bytes = 0
        self.safe_count = 0
        self.suspicious_count = 0
        self.critical_count = 0
        self.protocols.clear()

        self.card_packets.set_value("0")
        self.card_bytes.set_value("0.0 KB")
        self.card_safe.set_value("0")
        self.card_threats.set_value("0")
        self._refresh_protocol_bars()
        self.update_queue_status(0, 0)
        self.set_selected_packet(None)
