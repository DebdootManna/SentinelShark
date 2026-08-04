from typing import Dict, Any, Optional
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush, QFont
from PyQt6.QtWidgets import (
    QTreeWidget, QTreeWidgetItem, QHeaderView, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel
)


class PacketDetailView(QWidget):
    """
    Interactive QTreeWidget breaking down packet dissect layers:
    Frame -> Ethernet -> IP -> TCP/UDP -> DNS/HTTP/TLS -> Threat Intel Summary.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Header controls
        top_bar = QHBoxLayout()
        self.title_lbl = QLabel("Packet Details (Dissection)")
        self.title_lbl.setStyleSheet("font-weight: bold; color: #38bdf8; font-size: 13px;")

        self.expand_btn = QPushButton("Expand All")
        self.expand_btn.setFixedSize(85, 24)
        self.expand_btn.setStyleSheet("font-size: 11px; padding: 2px 6px;")
        self.expand_btn.clicked.connect(lambda: self.tree.expandAll())

        self.collapse_btn = QPushButton("Collapse All")
        self.collapse_btn.setFixedSize(85, 24)
        self.collapse_btn.setStyleSheet("font-size: 11px; padding: 2px 6px;")
        self.collapse_btn.clicked.connect(lambda: self.tree.collapseAll())

        top_bar.addWidget(self.title_lbl)
        top_bar.addStretch()
        top_bar.addWidget(self.expand_btn)
        top_bar.addWidget(self.collapse_btn)
        layout.addLayout(top_bar)

        # QTreeWidget
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setAnimated(True)
        self.tree.setIndentation(16)
        layout.addWidget(self.tree)

    def display_packet(self, pkt: Optional[Dict[str, Any]]):
        """Populate tree view with dissected layer fields."""
        self.tree.clear()
        if not pkt:
            return

        # 1. Threat Intelligence Summary Node (if present)
        threat_data = pkt.get("threat_data")
        if threat_data:
            self._add_threat_node(threat_data)

        # 2. Layer Dissection Nodes
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

    def _add_threat_node(self, threat: Dict[str, Any]):
        """Add highlighted Threat Intelligence layer node."""
        ip = threat.get("ip", "")
        abuse = threat.get("abuse_score", 0)
        vt_mal = threat.get("vt_malicious", 0)
        vt_susp = threat.get("vt_suspicious", 0)
        country = threat.get("country", "N/A")
        reports = threat.get("reports_count", 0)
        domain = threat.get("domain", "N/A")

        node_title = f"Threat Intelligence Summary [IP: {ip}] - Abuse: {abuse}%, VT Malicious: {vt_mal}"
        root_item = QTreeWidgetItem(self.tree, [node_title])
        
        font = root_item.font(0)
        font.setBold(True)
        root_item.setFont(0, font)

        if vt_mal > 0 or abuse > 30:
            root_item.setForeground(0, QBrush(QColor(248, 113, 113)))  # Red
        else:
            root_item.setForeground(0, QBrush(QColor(52, 211, 153)))   # Green

        children = [
            f"AbuseIPDB Score: {abuse}% ({reports} total reports)",
            f"VirusTotal Detections: {vt_mal} Malicious, {vt_susp} Suspicious",
            f"Geographic Country Code: {country}",
            f"Associated Domain: {domain}",
            f"Cache Status: {'Cached (SQLite)' if threat.get('cached') else 'Live API Lookup'}"
        ]

        for child in children:
            QTreeWidgetItem(root_item, [child])

        # IPinfo Detailed Integration Node
        ipinfo_details = threat.get("ipinfo_details")
        if ipinfo_details and isinstance(ipinfo_details, dict) and len(ipinfo_details) > 0:
            ipinfo_node = QTreeWidgetItem(root_item, ["IPinfo Details & Geolocation"])
            font_ipinfo = ipinfo_node.font(0)
            font_ipinfo.setBold(True)
            ipinfo_node.setFont(0, font_ipinfo)
            ipinfo_node.setForeground(0, QBrush(QColor(56, 189, 248)))  # Sky blue

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
            ipinfo_node.setForeground(0, QBrush(QColor(56, 189, 248)))

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
            ipinfo_node.setForeground(0, QBrush(QColor(148, 163, 184)))
