from typing import Dict, Any, Optional
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush, QFont
from PyQt6.QtWidgets import (
    QTreeWidget, QTreeWidgetItem, QHeaderView, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFrame, QApplication
)

from app.config import config

# Figma design color tokens
C = {
    "bg": "#0D1117", "surface": "#161B22", "border": "#30363D",
    "borderSubtle": "#21262D", "accent": "#58A6FF", "accentDim": "#1F3A5F",
    "danger": "#F85149", "dangerDim": "#3D1A1A", "dangerBorder": "#5A1E1E",
    "warning": "#D29922", "warningDim": "#3D2E0A",
    "safe": "#2EA043", "safeDim": "#122A19",
    "text": "#E6EDF3", "textMuted": "#8B949E", "textDimmer": "#484F58",
}

SEVERITY_FG = {
    "critical": QColor(248, 81, 73),
    "high": QColor(255, 123, 114),
    "medium": QColor(210, 153, 34),
    "safe": QColor(46, 160, 67),
}


class PacketDetailView(QWidget):
    """
    Packet Inspection panel with collapsible sections:
    1. Threat Intel Summary
    2. Host & Process Forensics (NEW for EDR)
    3. Layer Dissection
    Matches the Figma EDR design layout.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
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
            }}
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 8, 14, 8)
        header_lbl = QLabel("🔍  PACKET INSPECTION")
        header_lbl.setStyleSheet(f"""
            font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
            text-transform: uppercase; color: {C['textMuted']};
            background: transparent; border: none;
        """)

        self.expand_btn = QPushButton("Expand All")
        self.expand_btn.setFixedSize(85, 24)
        self.expand_btn.setStyleSheet("font-size: 11px; padding: 2px 6px;")

        self.collapse_btn = QPushButton("Collapse All")
        self.collapse_btn.setFixedSize(85, 24)
        self.collapse_btn.setStyleSheet("font-size: 11px; padding: 2px 6px;")

        header_layout.addWidget(header_lbl)
        header_layout.addStretch()
        header_layout.addWidget(self.expand_btn)
        header_layout.addWidget(self.collapse_btn)
        layout.addWidget(header)

        # QTreeWidget
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setAnimated(True)
        self.tree.setIndentation(16)

        self.expand_btn.clicked.connect(lambda: self.tree.expandAll())
        self.collapse_btn.clicked.connect(lambda: self.tree.collapseAll())

        layout.addWidget(self.tree)

    def display_packet(self, pkt: Optional[Dict[str, Any]]):
        """Populate tree view with threat intel, process forensics, and layer fields."""
        self.tree.clear()
        if not pkt:
            return

        # 1. Threat Intelligence Summary Node
        threat_data = pkt.get("threat_data")
        if threat_data:
            self._add_threat_node(threat_data, pkt)

        # 2. Host & Process Forensics Node (EDR)
        self._add_process_forensics_node(pkt)

        # 3. Layer Dissection Nodes
        layers_tree = pkt.get("layers_tree", [])
        for layer in layers_tree:
            layer_name = layer.get("name", "Layer")
            root_item = QTreeWidgetItem(self.tree, [layer_name])
            font = root_item.font(0)
            font.setBold(True)
            root_item.setFont(0, font)
            for child in layer.get("children", []):
                QTreeWidgetItem(root_item, [str(child)])

        self.tree.expandAll()

    def _add_process_forensics_node(self, pkt: Dict[str, Any]):
        """Add Host & Process Forensics collapsible section matching Figma design."""
        pid = pkt.get("pid", "")
        process_name = pkt.get("process_name", "")
        if not pid and not process_name:
            return

        severity = pkt.get("severity", "safe")
        sev_color = SEVERITY_FG.get(severity, SEVERITY_FG["safe"])

        node_title = f"Host & Process Forensics [PID: {pid} — {process_name}]"
        root = QTreeWidgetItem(self.tree, [node_title])
        font = root.font(0)
        font.setBold(True)
        root.setFont(0, font)
        root.setForeground(0, QBrush(QColor(88, 166, 255)))  # accent

        # Command Line
        cmdline = pkt.get("cmdline", "")
        if cmdline:
            cmd_item = QTreeWidgetItem(root, [f"Command Line: {cmdline}"])
            cmd_item.setForeground(0, QBrush(sev_color))

        # Executable Path
        exe_path = pkt.get("exe_path", "")
        if exe_path:
            QTreeWidgetItem(root, [f"Executable Path: {exe_path}"])

        # SHA-256 Hash
        sha256 = pkt.get("exe_sha256", "")
        if sha256:
            hash_item = QTreeWidgetItem(root, [f"File SHA-256: {sha256}"])
            hash_item.setForeground(0, QBrush(QColor(139, 148, 158)))  # textMuted

        # Process Lineage
        ppid = pkt.get("ppid", "")
        if ppid:
            lineage = f"Process Lineage: init/systemd (PID 1) → PID {ppid} → {process_name} (PID {pid})"
            QTreeWidgetItem(root, [lineage])

        # User Context
        username = pkt.get("username", "")
        if username:
            user_item = QTreeWidgetItem(root, [f"User: {username}"])
            if username in ("root", "SYSTEM", "Administrator"):
                user_item.setForeground(0, QBrush(QColor(248, 81, 73)))  # danger

        # PID + PPID
        QTreeWidgetItem(root, [f"Process ID: {pid}"])
        if ppid:
            QTreeWidgetItem(root, [f"Parent Process ID: {ppid}"])

    def _add_threat_node(self, threat: Dict[str, Any], pkt: Dict[str, Any] = None):
        """Add highlighted Threat Intelligence layer node."""
        ip = threat.get("ip", "")
        abuse = threat.get("abuse_score", 0)
        vt_mal = threat.get("vt_malicious", 0)
        vt_susp = threat.get("vt_suspicious", 0)
        country = threat.get("country", "N/A")
        reports = threat.get("reports_count", 0)
        domain = threat.get("domain", "N/A")

        severity = (pkt or {}).get("severity", "safe")
        node_title = f"Threat Intelligence Summary [IP: {ip}] — Abuse: {abuse}%, VT Malicious: {vt_mal}"
        root_item = QTreeWidgetItem(self.tree, [node_title])

        font = root_item.font(0)
        font.setBold(True)
        root_item.setFont(0, font)

        if vt_mal > 0 or abuse > 30:
            root_item.setForeground(0, QBrush(QColor(248, 81, 73)))   # danger
        else:
            root_item.setForeground(0, QBrush(QColor(46, 160, 67)))    # safe

        children = [
            f"AbuseIPDB Score: {abuse}% ({reports} total reports)",
            f"VirusTotal Detections: {vt_mal} Malicious, {vt_susp} Suspicious",
            f"Geographic Country Code: {country}",
            f"Associated Domain: {domain}",
            f"Cache Status: {'In-Memory Cache' if threat.get('cached') else 'Live API Lookup'}"
        ]

        for child in children:
            QTreeWidgetItem(root_item, [child])

        # IPinfo Details
        ipinfo_details = threat.get("ipinfo_details")
        if ipinfo_details and isinstance(ipinfo_details, dict) and len(ipinfo_details) > 0:
            ipinfo_node = QTreeWidgetItem(root_item, ["IPinfo Details & Geolocation"])
            font_ipinfo = ipinfo_node.font(0)
            font_ipinfo.setBold(True)
            ipinfo_node.setFont(0, font_ipinfo)
            ipinfo_node.setForeground(0, QBrush(QColor(88, 166, 255)))

            def format_dict_to_tree(parent_node: QTreeWidgetItem, d: dict):
                for k, v in d.items():
                    if isinstance(v, dict):
                        sub_node = QTreeWidgetItem(parent_node, [f"{k}:"])
                        format_dict_to_tree(sub_node, v)
                    elif isinstance(v, list):
                        sub_node = QTreeWidgetItem(parent_node, [f"{k}:"])
                        for item in v:
                            if isinstance(item, dict):
                                item_node = QTreeWidgetItem(sub_node, ["item:"])
                                format_dict_to_tree(item_node, item)
                            else:
                                QTreeWidgetItem(sub_node, [str(item)])
                    else:
                        QTreeWidgetItem(parent_node, [f"{k}: {v}"])

            format_dict_to_tree(ipinfo_node, ipinfo_details)
        elif any(bool(threat.get(k)) for k in ("ipinfo_org", "ipinfo_city", "ipinfo_hostname", "ipinfo_loc", "ipinfo_country", "ipinfo_region", "ipinfo_timezone")):
            ipinfo_node = QTreeWidgetItem(root_item, ["IPinfo Details & Geolocation"])
            font_ipinfo = ipinfo_node.font(0)
            font_ipinfo.setBold(True)
            ipinfo_node.setFont(0, font_ipinfo)
            ipinfo_node.setForeground(0, QBrush(QColor(88, 166, 255)))

            if threat.get("ipinfo_org"):
                QTreeWidgetItem(ipinfo_node, [f"org: {threat.get('ipinfo_org')}"])
            if threat.get("ipinfo_hostname"):
                QTreeWidgetItem(ipinfo_node, [f"hostname: {threat.get('ipinfo_hostname')}"])
            if threat.get("ipinfo_city"):
                QTreeWidgetItem(ipinfo_node, [f"city: {threat.get('ipinfo_city')}"])
            if threat.get("ipinfo_region"):
                QTreeWidgetItem(ipinfo_node, [f"region: {threat.get('ipinfo_region')}"])
            if threat.get("ipinfo_country"):
                QTreeWidgetItem(ipinfo_node, [f"country: {threat.get('ipinfo_country')}"])
            if threat.get("ipinfo_loc"):
                QTreeWidgetItem(ipinfo_node, [f"loc: {threat.get('ipinfo_loc')}"])
            if threat.get("ipinfo_timezone"):
                QTreeWidgetItem(ipinfo_node, [f"timezone: {threat.get('ipinfo_timezone')}"])
            if threat.get("ipinfo_postal"):
                QTreeWidgetItem(ipinfo_node, [f"postal: {threat.get('ipinfo_postal')}"])
            if threat.get("ipinfo_anycast"):
                QTreeWidgetItem(ipinfo_node, [f"anycast: {threat.get('ipinfo_anycast')}"])
        else:
            status_text = "No API Key Configured" if not config.ipinfo_api_key else "No Data / Pending Lookup"
            ipinfo_node = QTreeWidgetItem(root_item, [f"IPinfo Details: ({status_text})"])
            ipinfo_node.setForeground(0, QBrush(QColor(139, 148, 158)))

        # Shodan Details
        shodan_details = threat.get("shodan_details")
        shodan_ports = threat.get("shodan_ports", [])
        shodan_vulns = threat.get("shodan_vulns", [])
        shodan_cpes = threat.get("shodan_cpes", [])
        shodan_status = threat.get("shodan_status")
        shodan_tier = threat.get("shodan_tier", "")

        has_shodan_data = (shodan_details and isinstance(shodan_details, dict) and len(shodan_details) > 0) or shodan_ports or shodan_vulns

        if has_shodan_data:
            node_title = f"Shodan Host Intelligence ({shodan_status})" if shodan_status else "Shodan Host Intelligence"
            shodan_node = QTreeWidgetItem(root_item, [node_title])
            font_shodan = shodan_node.font(0)
            font_shodan.setBold(True)
            shodan_node.setFont(0, font_shodan)
            shodan_node.setForeground(0, QBrush(QColor(59, 185, 80)))  # safe green

            if threat.get("shodan_org"):
                QTreeWidgetItem(shodan_node, [f"Organization: {threat.get('shodan_org')}"])
            if threat.get("shodan_os"):
                QTreeWidgetItem(shodan_node, [f"Operating System: {threat.get('shodan_os')}"])
            if shodan_ports:
                QTreeWidgetItem(shodan_node, [f"Open Ports: {', '.join(map(str, shodan_ports))}"])
            if shodan_vulns:
                vuln_item = QTreeWidgetItem(shodan_node, [f"Vulnerabilities / CVEs ({len(shodan_vulns)}):"])
                vuln_item.setForeground(0, QBrush(QColor(248, 81, 73)))
                for v in shodan_vulns[:10]:
                    QTreeWidgetItem(vuln_item, [str(v)])
            if shodan_cpes:
                QTreeWidgetItem(shodan_node, [f"CPE Identifiers: {', '.join(shodan_cpes[:5])}"])
            if threat.get("shodan_tags"):
                QTreeWidgetItem(shodan_node, [f"Tags: {', '.join(threat.get('shodan_tags'))}"])
            if threat.get("shodan_hostnames"):
                QTreeWidgetItem(shodan_node, [f"Hostnames: {', '.join(threat.get('shodan_hostnames'))}"])
        else:
            if shodan_status:
                status_text = shodan_status
            elif not config.shodan_api_key:
                status_text = "InternetDB Mode (No Key)"
            else:
                status_text = "Lookup In Progress / Pending"
            shodan_node = QTreeWidgetItem(root_item, [f"Shodan Details: ({status_text})"])
            shodan_node.setForeground(0, QBrush(QColor(139, 148, 158)))
