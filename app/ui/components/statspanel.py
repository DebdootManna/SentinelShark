from collections import Counter
from typing import Dict, Any, Optional
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QGroupBox, QProgressBar, QFrame, QPushButton, QSizePolicy, QLayout
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
        self.setMinimumSize(130, 58)
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


class CollapsibleCard(QFrame):
    """
    A sleek, modern Figma-inspired card container with a header bar,
    title label, collapse/expand toggle button, and inner content layout.
    """

    def __init__(self, title: str, expanded_min_height: int = 140, parent=None):
        super().__init__(parent)
        self.is_collapsed = False
        self.expanded_min_height = expanded_min_height
        self.setObjectName("CollapsibleCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.setMinimumHeight(self.expanded_min_height)
        self.setStyleSheet("""
            QFrame#CollapsibleCard {
                background-color: #131C2B;
                border: 1px solid #1E293B;
                border-radius: 12px;
            }
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 12, 14, 12)
        main_layout.setSpacing(8)

        # Header bar
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)

        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("""
            color: #22D3EE;
            font-weight: 700;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: transparent;
            border: none;
        """)

        self.toggle_btn = QPushButton("−")
        self.toggle_btn.setFixedSize(22, 22)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.setToolTip("Collapse / Expand Section")
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(30, 41, 59, 0.6);
                border: 1px solid #1E293B;
                color: #94A3B8;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
                padding: 0px;
            }
            QPushButton:hover {
                background-color: #1E293B;
                color: #22D3EE;
                border-color: #38BDF8;
            }
        """)
        self.toggle_btn.clicked.connect(self.toggle_collapse)

        header_layout.addWidget(self.title_lbl)
        header_layout.addStretch()
        header_layout.addWidget(self.toggle_btn)
        main_layout.addLayout(header_layout)

        # Content container
        self.content_widget = QWidget()
        self.content_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 4, 0, 0)
        self.content_layout.setSpacing(8)

        main_layout.addWidget(self.content_widget)

    def toggle_collapse(self):
        self.is_collapsed = not self.is_collapsed
        self.content_widget.setVisible(not self.is_collapsed)
        self.toggle_btn.setText("+" if self.is_collapsed else "−")
        if self.is_collapsed:
            self.setFixedHeight(44)
        else:
            self.setMinimumHeight(self.expanded_min_height)
            self.setMaximumHeight(16777215)

    def set_title(self, new_title: str):
        self.title_lbl.setText(new_title)


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
        self.processes = Counter()
        self.mitre_techniques = Counter()
        self.selected_pkt: Optional[Dict[str, Any]] = None
        self.proto_row_widgets: Dict[str, dict] = {}
        self.proc_row_widgets: list[dict] = []
        self.mitre_row_widgets: list[dict] = []

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.init_ui()
        self.setMinimumSize(300, 650)

    def minimumSizeHint(self) -> QSize:
        return QSize(300, 650)

    def sizeHint(self) -> QSize:
        return QSize(320, 680)

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(14)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)

        # 1. Metric Cards 2x2 Grid
        grid = QGridLayout()
        grid.setSpacing(10)

        self.card_packets = StatCard("TOTAL EVENTS", "0", "#58A6FF")
        self.card_bytes = StatCard("DATA TRAFFIC", "0.0 KB", "#3FB950")
        self.card_safe = StatCard("SAFE EVENTS", "0", "#2EA043")
        self.card_threats = StatCard("THREATS DETECTED", "0", "#F85149")

        grid.addWidget(self.card_packets, 0, 0)
        grid.addWidget(self.card_bytes, 0, 1)
        grid.addWidget(self.card_safe, 1, 0)
        grid.addWidget(self.card_threats, 1, 1)

        layout.addLayout(grid)

        # 2. MITRE ATT&CK Coverage Panel
        self.mitre_card = CollapsibleCard("MITRE ATT&CK COVERAGE", expanded_min_height=140)
        self.mitre_layout = self.mitre_card.content_layout
        self.mitre_layout.setSpacing(5)
        self.mitre_empty_lbl = QLabel("No techniques tagged yet")
        self.mitre_empty_lbl.setStyleSheet("color: #8B949E; font-family: monospace; font-size: 11px;")
        self.mitre_layout.addWidget(self.mitre_empty_lbl)

        for _ in range(5):
            row_container = QWidget()
            row_layout = QHBoxLayout(row_container)
            row_layout.setContentsMargins(0, 2, 0, 2)
            row_layout.setSpacing(6)

            lbl_tag = QLabel()
            lbl_tag.setFixedWidth(68)
            lbl_tag.setStyleSheet("""
                color: #58A6FF; font-family: 'JetBrains Mono', monospace;
                font-size: 9px; font-weight: 700; background-color: #1F3A5F;
                border: 1px solid #2A4A7A; border-radius: 3px; padding: 1px 3px;
            """)

            lbl_name = QLabel()
            lbl_name.setFixedWidth(85)
            lbl_name.setStyleSheet("color: #8B949E; font-size: 10px;")

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setTextVisible(False)
            bar.setFixedHeight(5)
            bar.setStyleSheet("""
                QProgressBar { background-color: #21262D; border: none; border-radius: 2px; }
                QProgressBar::chunk { background-color: #D29922; border-radius: 2px; }
            """)

            lbl_count = QLabel("0")
            lbl_count.setFixedWidth(34)
            lbl_count.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_count.setStyleSheet("color: #E6EDF3; font-family: 'JetBrains Mono', monospace; font-size: 10px;")

            row_layout.addWidget(lbl_tag)
            row_layout.addWidget(lbl_name)
            row_layout.addWidget(bar)
            row_layout.addWidget(lbl_count)

            row_container.setVisible(False)
            self.mitre_layout.addWidget(row_container)
            self.mitre_row_widgets.append({
                "container": row_container,
                "tag": lbl_tag,
                "name": lbl_name,
                "bar": bar,
                "count": lbl_count
            })

        layout.addWidget(self.mitre_card)

        # 3. Top Processes Panel
        self.proc_card = CollapsibleCard("TOP PROCESSES", expanded_min_height=140)
        self.proc_layout = self.proc_card.content_layout
        self.proc_layout.setSpacing(5)
        self.proc_empty_lbl = QLabel("No process telemetry recorded")
        self.proc_empty_lbl.setStyleSheet("color: #8B949E; font-family: monospace; font-size: 11px;")
        self.proc_layout.addWidget(self.proc_empty_lbl)

        for i in range(5):
            row_container = QWidget()
            row_layout = QHBoxLayout(row_container)
            row_layout.setContentsMargins(0, 2, 0, 2)
            row_layout.setSpacing(6)

            lbl_rank = QLabel(f"{i+1}.")
            lbl_rank.setFixedWidth(14)
            lbl_rank.setStyleSheet("color: #484F58; font-family: 'JetBrains Mono', monospace; font-size: 10px;")

            lbl_name = QLabel()
            lbl_name.setFixedWidth(80)
            lbl_name.setStyleSheet("color: #E6EDF3; font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 600;")

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setTextVisible(False)
            bar.setFixedHeight(5)
            bar.setStyleSheet("""
                QProgressBar { background-color: #21262D; border: none; border-radius: 2px; }
                QProgressBar::chunk { background-color: #58A6FF; border-radius: 2px; }
            """)

            lbl_count = QLabel("0")
            lbl_count.setFixedWidth(36)
            lbl_count.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_count.setStyleSheet("color: #8B949E; font-family: 'JetBrains Mono', monospace; font-size: 10px;")

            row_layout.addWidget(lbl_rank)
            row_layout.addWidget(lbl_name)
            row_layout.addWidget(bar)
            row_layout.addWidget(lbl_count)

            row_container.setVisible(False)
            self.proc_layout.addWidget(row_container)
            self.proc_row_widgets.append({
                "container": row_container,
                "name": lbl_name,
                "bar": bar,
                "count": lbl_count
            })

        layout.addWidget(self.proc_card)

        # 4. Protocol Breakdown Panel
        self.proto_card = CollapsibleCard("PROTOCOL BREAKDOWN", expanded_min_height=170)
        self.proto_layout = self.proto_card.content_layout
        self.proto_layout.setSpacing(8)

        self.proto_empty_lbl = QLabel("No protocol data recorded")
        self.proto_empty_lbl.setStyleSheet("color: #94A3B8; font-family: monospace; font-size: 11px;")
        self.proto_layout.addWidget(self.proto_empty_lbl)

        # Build reusable protocol row widgets ahead of time to avoid layout stacking/leaks
        for proto in TRACKED_PROTOCOLS:
            row_container = QWidget()
            row_layout = QHBoxLayout(row_container)
            row_layout.setContentsMargins(0, 2, 0, 2)
            row_layout.setSpacing(8)

            lbl_proto = QLabel(proto)
            lbl_proto.setFixedWidth(52)
            lbl_proto.setStyleSheet("color: #94A3B8; font-family: 'JetBrains Mono', monospace; font-size: 11px;")

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setTextVisible(False)
            bar.setFixedHeight(6)
            color = PROTO_COLORS.get(proto, "#94A3B8")
            bar.setStyleSheet(f"""
                QProgressBar {{
                    background-color: #1E293B;
                    border: none;
                    border-radius: 3px;
                }}
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 3px;
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

        layout.addWidget(self.proto_card)

        # 3. Threat Intel API Queue Panel (VirusTotal, AbuseIPDB, Shodan, IPinfo)
        self.queue_card = CollapsibleCard("THREAT INTEL API QUEUE", expanded_min_height=190)
        queue_layout = self.queue_card.content_layout
        queue_layout.setSpacing(8)

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
        q_header.setContentsMargins(0, 4, 0, 0)
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
        self.queue_bar.setFixedHeight(5)
        queue_layout.addWidget(self.queue_bar)

        layout.addWidget(self.queue_card)

        # 4. Selected Packet Summary Card
        self.pkt_card = CollapsibleCard("SELECTED PACKET", expanded_min_height=140)
        self.pkt_layout = self.pkt_card.content_layout
        self.pkt_layout.setSpacing(6)

        self.pkt_empty_lbl = QLabel("No packet selected")
        self.pkt_empty_lbl.setStyleSheet("color: #94A3B8; font-family: monospace; font-size: 11px;")
        self.pkt_layout.addWidget(self.pkt_empty_lbl)

        # Pre-create key-value rows for Protocol, Source, Dest, Size
        self.pkt_detail_widgets = {}
        for key_label, dict_key in [("Protocol", "proto"), ("Source", "src"), ("Dest", "dst"), ("Size", "size")]:
            container = QWidget()
            row = QHBoxLayout(container)
            row.setContentsMargins(0, 2, 0, 2)
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

        layout.addWidget(self.pkt_card)
        layout.addStretch()

    def _create_api_status_row(self, name: str, key_val: str) -> dict:
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 2, 0, 2)
        lbl_name = QLabel(name)
        lbl_name.setStyleSheet("color: #94A3B8; font-size: 11px;")

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

    def update_packets_batch(self, pkt_list: list):
        """Batch update statistics for a list of packets efficiently."""
        if not pkt_list:
            return

        for pkt in pkt_list:
            self.total_packets += 1
            if isinstance(pkt, tuple):
                # (no, time, pid, process, src, dst, proto, length, mitre, sev, info)
                pkt_bytes = int(pkt[7]) if str(pkt[7]).isdigit() else 0
                raw_proto = str(pkt[6] or "OTHER").upper()
                pname = str(pkt[3]) or "System / External"
                mitre_str = str(pkt[8])
                mitre_tags = [t.strip() for t in mitre_str.split(",") if t.strip() and t.strip() != "—"]
                sev = str(pkt[9]).lower()
            else:
                pkt_bytes = pkt.get("length", 0) or 0
                raw_proto = (pkt.get("protocol") or "OTHER").upper()
                pname = pkt.get("process_name") or "System / External"
                mitre_tags = pkt.get("mitre_tags", [])
                sev = str(pkt.get("severity", "safe")).lower()

            self.total_bytes += pkt_bytes

            # Protocol counts
            proto = raw_proto if raw_proto in TRACKED_PROTOCOLS else "OTHER"
            self.protocols[proto] = self.protocols.get(proto, 0) + 1

            # Process telemetry counts
            self.processes[pname] += 1

            # MITRE ATT&CK technique counts
            for tag in mitre_tags:
                if tag:
                    self.mitre_techniques[tag] += 1

            # Severity counts
            if sev in ("critical", "high"):
                self.critical_count += 1
            else:
                self.safe_count += 1

        # Update metric cards
        self.card_packets.set_value(f"{self.total_packets:,}")
        if self.total_bytes > 1024 * 1024:
            bytes_str = f"{self.total_bytes / (1024 * 1024):.1f} MB"
        else:
            bytes_str = f"{self.total_bytes / 1024:.1f} KB"
        self.card_bytes.set_value(bytes_str)
        self.card_safe.set_value(f"{self.safe_count:,}")
        self.card_threats.set_value(f"{self.critical_count:,}")

        self._refresh_protocol_bars()
        self._refresh_edr_sections()

    def update_packet_stats(self, pkt: Dict[str, Any]):
        """Record single packet statistics."""
        self.update_packets_batch([pkt])

    def _refresh_edr_sections(self):
        """Update MITRE and Process cards dynamically with progress bars and badges."""
        from app.core.secops_engine import TECHNIQUE_NAMES, LOLBIN_SET

        # 1. Top Processes
        top_procs = self.processes.most_common(5)
        if not top_procs:
            self.proc_empty_lbl.setVisible(True)
            for w in self.proc_row_widgets:
                w["container"].setVisible(False)
        else:
            self.proc_empty_lbl.setVisible(False)
            max_proc_cnt = top_procs[0][1] if top_procs else 1
            for i, w in enumerate(self.proc_row_widgets):
                if i < len(top_procs):
                    pname, cnt = top_procs[i]
                    disp_name = pname[:12] + "…" if len(pname) > 13 else pname
                    w["name"].setText(disp_name)
                    pct = int((cnt / max_proc_cnt) * 100) if max_proc_cnt > 0 else 0
                    w["bar"].setValue(pct)
                    w["count"].setText(str(cnt))

                    # Highlight LOLBins in danger red
                    if any(lol in pname.lower() for lol in LOLBIN_SET):
                        w["name"].setStyleSheet("color: #F85149; font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700;")
                        w["bar"].setStyleSheet("""
                            QProgressBar { background-color: #21262D; border: none; border-radius: 2px; }
                            QProgressBar::chunk { background-color: #F85149; border-radius: 2px; }
                        """)
                    else:
                        w["name"].setStyleSheet("color: #E6EDF3; font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 600;")
                        w["bar"].setStyleSheet("""
                            QProgressBar { background-color: #21262D; border: none; border-radius: 2px; }
                            QProgressBar::chunk { background-color: #58A6FF; border-radius: 2px; }
                        """)
                    w["container"].setVisible(True)
                else:
                    w["container"].setVisible(False)

        # 2. MITRE ATT&CK Coverage
        top_mitre = self.mitre_techniques.most_common(5)
        if not top_mitre:
            self.mitre_empty_lbl.setVisible(True)
            for w in self.mitre_row_widgets:
                w["container"].setVisible(False)
        else:
            self.mitre_empty_lbl.setVisible(False)
            max_mitre_cnt = top_mitre[0][1] if top_mitre else 1
            for i, w in enumerate(self.mitre_row_widgets):
                if i < len(top_mitre):
                    tag, cnt = top_mitre[i]
                    tech_desc = TECHNIQUE_NAMES.get(tag, "Technique")
                    w["tag"].setText(tag)
                    w["name"].setText(tech_desc[:14])
                    pct = int((cnt / max_mitre_cnt) * 100) if max_mitre_cnt > 0 else 0
                    w["bar"].setValue(pct)
                    w["count"].setText(f"({cnt})")
                    w["container"].setVisible(True)
                else:
                    w["container"].setVisible(False)

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
            self.pkt_card.set_title("SELECTED PACKET")
            self.pkt_empty_lbl.setVisible(True)
            for w in self.pkt_detail_widgets.values():
                w["container"].setVisible(False)
            return

        no = pkt.get("no", "")
        self.pkt_card.set_title(f"SELECTED: PACKET #{no}")
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
        self.processes.clear()
        self.mitre_techniques.clear()

        self.card_packets.set_value("0")
        self.card_bytes.set_value("0.0 KB")
        self.card_safe.set_value("0")
        self.card_threats.set_value("0")
        self.mitre_empty_lbl.setText("No techniques tagged yet")
        self.mitre_empty_lbl.setStyleSheet("color: #8B949E; font-family: monospace; font-size: 11px;")
        self.proc_empty_lbl.setText("No process telemetry recorded")
        self.proc_empty_lbl.setStyleSheet("color: #8B949E; font-family: monospace; font-size: 11px;")
        self._refresh_protocol_bars()
        self._refresh_edr_sections()
        self.update_queue_status(0, 0)
        self.set_selected_packet(None)
