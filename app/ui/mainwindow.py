import os
import time
from typing import Optional
import psutil
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QIcon, QFont, QAction, QColor
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QToolBar,
    QComboBox, QLineEdit, QPushButton, QLabel, QFileDialog, QMessageBox,
    QDialog, QFormLayout, QDialogButtonBox, QStatusBar, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)

from app.config import config, CONFIG_PATH
from app.core.capture import LiveCaptureThread, get_available_interfaces
from app.services.queuemanager import queue_manager
from app.core.cache import cache
from app.ui.styles import DARK_THEME_QSS
from app.ui.components.packettable import PacketTable
from app.ui.components.packetdetail import PacketDetailView
from app.ui.components.hexview import HexView
from app.ui.components.statspanel import StatsPanel
from app.ui.components.sparkline import SparklineWidget
from app.core.interfacemapper import interface_mapper


class InterfaceSelectionDialog(QDialog):
    """
    Wireshark-style modal dialog displaying real-time packet activity sparklines
    for all host network interfaces.
    """

    def __init__(self, interfaces: list, current_iface: str = "en0", parent=None):
        super().__init__(parent)
        self.setWindowTitle("SentinelShark - Select Network Interface")
        self.setMinimumSize(680, 460)
        self.selected_interface = current_iface
        self.interfaces = interfaces
        self.last_counters = {}
        self.last_time = time.time()
        self.sparklines = {}
        self.rate_labels = {}

        # Refresh OS interface mappings
        interface_mapper.refresh()

        self.init_ui(interfaces, current_iface)

        # 300ms Timer for real-time traffic sampling
        self.sample_timer = QTimer(self)
        self.sample_timer.timeout.connect(self.sample_traffic)
        self.sample_timer.start(300)

    def init_ui(self, interfaces: list, current_iface: str):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title_lbl = QLabel("<b>Select Network Interface for Packet Capture</b>")
        title_lbl.setStyleSheet("font-size: 15px; color: #38bdf8;")
        layout.addWidget(title_lbl)

        desc_lbl = QLabel(
            "Live traffic activity curves below show real-time packet transmission across your network devices (Wireshark-style preview):"
        )
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("color: #94a3b8; font-size: 12px;")
        layout.addWidget(desc_lbl)

        # Table Widget
        self.table = QTableWidget(len(interfaces), 4)
        self.table.setHorizontalHeaderLabels(["Interface", "IP Address", "Live Traffic Sparkline", "Rate"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(0, 240)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(3, 100)

        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.itemDoubleClicked.connect(self.on_row_double_clicked)

        norm_current = current_iface.strip("\\").lower()

        selected_row = 0
        for row, iface in enumerate(interfaces):
            # 1. Interface Name
            friendly_name = interface_mapper.get_friendly_label(iface)
            item_name = QTableWidgetItem(friendly_name)
            item_name.setToolTip(f"Full Identifier: {iface}")
            item_name.setData(Qt.ItemDataRole.UserRole, iface)

            # Highlight default selected interface
            norm_iface = iface.strip("\\").lower()
            if norm_iface == norm_current or iface == current_iface:
                selected_row = row

            self.table.setItem(row, 0, item_name)

            # 2. IP Address
            ip_str = interface_mapper.get_ip_address(iface)
            item_ip = QTableWidgetItem(ip_str)
            item_ip.setForeground(QColor("#94a3b8"))
            self.table.setItem(row, 1, item_ip)

            # 3. Live Sparkline Widget
            sparkline = SparklineWidget()
            self.sparklines[iface] = sparkline
            self.table.setCellWidget(row, 2, sparkline)

            # 4. Rate Label
            lbl_rate = QLabel("0.0 KB/s")
            lbl_rate.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_rate.setStyleSheet("color: #64748b; font-family: monospace; font-size: 11px;")
            self.rate_labels[iface] = lbl_rate
            self.table.setCellWidget(row, 3, lbl_rate)

            self.table.setRowHeight(row, 38)

        self.table.selectRow(selected_row)
        layout.addWidget(self.table)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Start Capture on Interface")
        buttons.accepted.connect(self.save_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def sample_traffic(self):
        """Periodic timer task sampling network throughput per interface."""
        now = time.time()
        dt = max(now - self.last_time, 0.1)
        self.last_time = now

        try:
            counters = psutil.net_io_counters(pernic=True)
        except Exception:
            return

        for iface in self.interfaces:
            psutil_name = interface_mapper.get_psutil_name(iface)
            cur = counters.get(psutil_name) or counters.get(iface)
            prev = self.last_counters.get(iface)

            rate_kb = 0.0
            if cur and prev:
                delta_bytes = (cur.bytes_sent + cur.bytes_recv) - (prev.bytes_sent + prev.bytes_recv)
                rate_kb = max(0.0, (delta_bytes / dt) / 1024.0)

            if cur:
                self.last_counters[iface] = cur

            # Update sparkline waveform
            if iface in self.sparklines:
                self.sparklines[iface].add_value(rate_kb)

            # Update text label
            if iface in self.rate_labels:
                if rate_kb > 1024:
                    rate_str = f"{rate_kb / 1024.0:.1f} MB/s"
                elif rate_kb > 0.05:
                    rate_str = f"{rate_kb:.1f} KB/s"
                else:
                    rate_str = "0.0 KB/s"

                lbl = self.rate_labels[iface]
                lbl.setText(rate_str)
                if rate_kb > 0.05:
                    lbl.setStyleSheet("color: #34d399; font-weight: bold; font-family: monospace; font-size: 11px;")
                else:
                    lbl.setStyleSheet("color: #64748b; font-family: monospace; font-size: 11px;")

    def on_row_double_clicked(self, item: QTableWidgetItem):
        self.save_and_accept()

    def save_and_accept(self):
        row = self.table.currentRow()
        if row >= 0:
            item = self.table.item(row, 0)
            if item:
                iface = item.data(Qt.ItemDataRole.UserRole)
                if iface:
                    self.selected_interface = iface
        self.sample_timer.stop()
        self.accept()

    def reject(self):
        self.sample_timer.stop()
        super().reject()


class APISettingsDialog(QDialog):
    """Configuration modal for entering AbuseIPDB, VirusTotal & IPinfo API keys."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SentinelShark - API & Threat Intel Settings")
        self.setMinimumWidth(480)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        form = QFormLayout()
        
        self.abuse_edit = QLineEdit(config.abuseipdb_api_key)
        self.abuse_edit.setPlaceholderText("Enter AbuseIPDB API v2 Key")
        self.abuse_edit.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        form.addRow("AbuseIPDB API Key:", self.abuse_edit)

        self.vt_edit = QLineEdit(config.virustotal_api_key)
        self.vt_edit.setPlaceholderText("Enter VirusTotal v3 API Key")
        self.vt_edit.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        form.addRow("VirusTotal API Key:", self.vt_edit)

        self.ipinfo_edit = QLineEdit(config.ipinfo_api_key)
        self.ipinfo_edit.setPlaceholderText("Enter IPinfo API Key / Access Token")
        self.ipinfo_edit.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        form.addRow("IPinfo API Key:", self.ipinfo_edit)

        self.ttl_spin = QLineEdit(str(config.cache_ttl_hours))
        form.addRow("Cache TTL (Hours):", self.ttl_spin)

        self.rate_spin = QLineEdit(str(config.max_requests_per_minute))
        form.addRow("Max Requests / Min:", self.rate_spin)

        self.mock_chk = QCheckBox("Enable Mock Traffic Mode (No TShark required)")
        self.mock_chk.setChecked(config.mock_mode)
        form.addRow("", self.mock_chk)

        layout.addLayout(form)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.save_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def save_and_accept(self):
        config.abuseipdb_api_key = self.abuse_edit.text().strip()
        config.virustotal_api_key = self.vt_edit.text().strip()
        config.ipinfo_api_key = self.ipinfo_edit.text().strip()
        try:
            config.cache_ttl_hours = int(self.ttl_spin.text().strip())
            config.max_requests_per_minute = int(self.rate_spin.text().strip())
        except ValueError:
            pass
        config.mock_mode = self.mock_chk.isChecked()
        config.save()
        self.accept()


class MainWindow(QMainWindow):
    """Main Application Window for SentinelShark NIDS."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SentinelShark - Network Intrusion Detection & Analysis System")
        self.resize(1400, 900)
        self.setStyleSheet(DARK_THEME_QSS)

        self.capture_thread: Optional[LiveCaptureThread] = None

        self.init_ui()
        self.wire_signals()
        QTimer.singleShot(200, self.prompt_interface_selection)

    def init_ui(self):
        # 1. Menu Bar
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("File")
        open_pcap_act = QAction("Open PCAP File...", self)
        open_pcap_act.triggered.connect(self.open_pcap_dialog)
        file_menu.addAction(open_pcap_act)
        file_menu.addSeparator()
        exit_act = QAction("Exit", self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        settings_menu = menubar.addMenu("Settings")
        api_act = QAction("API Credentials...", self)
        api_act.triggered.connect(self.open_api_settings)
        settings_menu.addAction(api_act)

        help_menu = menubar.addMenu("Help")
        about_act = QAction("About SentinelShark", self)
        about_act.triggered.connect(self.show_about)
        help_menu.addAction(about_act)

        # 2. Toolbar Controls
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        toolbar.addWidget(QLabel("Interface: "))
        self.iface_combo = QComboBox()
        interfaces = get_available_interfaces()
        self.iface_combo.addItems(interfaces)
        self.iface_combo.setMinimumWidth(120)
        toolbar.addWidget(self.iface_combo)

        toolbar.addSeparator()

        toolbar.addWidget(QLabel("BPF Filter: "))
        self.bpf_edit = QLineEdit()
        self.bpf_edit.setPlaceholderText("e.g. tcp port 80 or ip src 192.168.1.1")
        self.bpf_edit.setMinimumWidth(220)
        toolbar.addWidget(self.bpf_edit)

        toolbar.addSeparator()

        self.start_btn = QPushButton("Start Capture")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self.start_capture)
        toolbar.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_capture)
        toolbar.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_all)
        toolbar.addWidget(self.clear_btn)

        toolbar.addSeparator()

        self.mock_btn = QPushButton("Mock Mode (ON)" if config.mock_mode else "Mock Mode")
        self.mock_btn.setObjectName("mockBtn")
        self.mock_btn.setCheckable(True)
        self.mock_btn.setChecked(config.mock_mode)
        self.mock_btn.toggled.connect(self.toggle_mock_mode)
        toolbar.addWidget(self.mock_btn)

        toolbar.addSeparator()

        self.api_btn = QPushButton("API Keys")
        self.api_btn.clicked.connect(self.open_api_settings)
        toolbar.addWidget(self.api_btn)

        # 3. Main Central Layout with Splitters
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(6, 6, 6, 6)

        # Vertical Splitter (Top: Table + Stats, Bottom: Inspector + Hex)
        self.v_splitter = QSplitter(Qt.Orientation.Vertical)

        # Top Horizontal Splitter (Packet Table + Stats Panel)
        self.top_h_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.packet_table = PacketTable()
        self.stats_panel = StatsPanel()
        
        self.top_h_splitter.addWidget(self.packet_table)
        self.top_h_splitter.addWidget(self.stats_panel)
        self.top_h_splitter.setStretchFactor(0, 4)
        self.top_h_splitter.setStretchFactor(1, 1)

        # Bottom Horizontal Splitter (Detail Tree + Hex View)
        self.bot_h_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.packet_detail = PacketDetailView()
        self.hex_view = HexView()

        self.bot_h_splitter.addWidget(self.packet_detail)
        self.bot_h_splitter.addWidget(self.hex_view)
        self.bot_h_splitter.setStretchFactor(0, 1)
        self.bot_h_splitter.setStretchFactor(1, 1)

        self.v_splitter.addWidget(self.top_h_splitter)
        self.v_splitter.addWidget(self.bot_h_splitter)
        self.v_splitter.setStretchFactor(0, 3)
        self.v_splitter.setStretchFactor(1, 2)

        main_layout.addWidget(self.v_splitter)

        # 4. Status Bar
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)

        # TShark Indicator
        tshark_path = config.find_tshark()
        if tshark_path:
            self.tshark_lbl = QLabel(f"  TShark: Available ({tshark_path})  ")
            self.tshark_lbl.setStyleSheet("color: #34d399; font-weight: bold;")
        else:
            self.tshark_lbl = QLabel("  TShark: Not Installed (Mock Mode Active)  ")
            self.tshark_lbl.setStyleSheet("color: #fbbf24; font-weight: bold;")
        
        self.capture_lbl = QLabel("  Capture Status: Idle  ")
        self.capture_lbl.setStyleSheet("color: #94a3b8;")

        self.statusbar.addPermanentWidget(self.tshark_lbl)
        self.statusbar.addWidget(self.capture_lbl)

    def wire_signals(self):
        """Connect UI signals to event handlers."""
        self.packet_table.packet_selected.connect(self.on_packet_selected)
        queue_manager.signals.threat_resolved.connect(self.on_threat_resolved)
        queue_manager.signals.queue_status.connect(self.stats_panel.update_queue_status)

    @pyqtSlot(dict)
    def on_packet_captured(self, pkt: dict):
        """Handle newly captured packet emitted by worker thread."""
        self.packet_table.add_packet(pkt)
        self.stats_panel.update_packet_stats(pkt)

        # Extract Destination IP for threat intel checking
        dst_ip = pkt.get("dst", "")
        if dst_ip:
            queue_manager.enqueue_ip(dst_ip)
        
        # Also check Source IP if public
        src_ip = pkt.get("src", "")
        if src_ip:
            queue_manager.enqueue_ip(src_ip)

    @pyqtSlot(dict)
    def on_packet_selected(self, pkt: dict):
        """Update detail tree and hex dump view when a packet row is clicked."""
        self.packet_detail.display_packet(pkt)
        self.hex_view.display_packet(pkt)

    @pyqtSlot(str, dict)
    def on_threat_resolved(self, ip: str, threat_data: dict):
        """Update threat color coding and stats when Threat Intel queue resolves an IP."""
        self.packet_table.update_threat_intel(ip, threat_data)
        self.stats_panel.update_threat_stats(threat_data)

    def start_capture(self, pcap_file: str = ""):
        """Start live packet capture or PCAP file reading thread."""
        if self.capture_thread and self.capture_thread.isRunning():
            return

        iface = self.iface_combo.currentText()
        bpf = self.bpf_edit.text()

        self.capture_thread = LiveCaptureThread(
            interface=iface,
            bpf_filter=bpf,
            pcap_file=pcap_file
        )

        self.capture_thread.packet_received.connect(self.on_packet_captured)
        self.capture_thread.status_changed.connect(self.update_capture_status)
        self.capture_thread.error_occurred.connect(self.show_capture_error)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.bpf_edit.setEnabled(False)

        self.capture_thread.start()

    def stop_capture(self):
        """Stop running capture thread."""
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.bpf_edit.setEnabled(True)

        self.update_capture_status("Capture stopped.")

    def clear_all(self):
        """Reset table, stats, inspector, hex dump, and queue status."""
        self.packet_table.clear_table()
        self.stats_panel.reset_stats()
        self.packet_detail.display_packet(None)
        self.hex_view.display_packet(None)
        queue_manager.clear()

    def toggle_mock_mode(self, enabled: bool):
        config.mock_mode = enabled
        config.save()
        self.mock_btn.setText("Mock Mode (ON)" if enabled else "Mock Mode")
        mode_str = "Mock Mode Active" if enabled else "Live Mode Active"
        self.statusbar.showMessage(f"Switched to {mode_str}", 4000)

    def open_pcap_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP File", "", "Packet Capture Files (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        if file_path:
            self.clear_all()
            self.start_capture(pcap_file=file_path)

    def open_api_settings(self):
        dlg = APISettingsDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            cache.clear_memory()
            queue_manager.clear()
            self.mock_btn.setChecked(config.mock_mode)
            self.mock_btn.setText("Mock Mode (ON)" if config.mock_mode else "Mock Mode")
            self.statusbar.showMessage("Configuration saved successfully. Cache flushed for new API keys.", 4000)

    def update_capture_status(self, status_msg: str):
        self.capture_lbl.setText(f"  Capture Status: {status_msg}  ")

    def show_capture_error(self, err_msg: str):
        self.statusbar.showMessage(err_msg, 5000)

    def prompt_interface_selection(self):
        """Display popup dialog on application startup for network interface selection."""
        interfaces = get_available_interfaces()
        current_iface = self.iface_combo.currentText() or config.default_interface or "en0"
        dlg = InterfaceSelectionDialog(interfaces, current_iface, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            selected = dlg.selected_interface
            idx = self.iface_combo.findText(selected)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
            config.default_interface = selected
            config.save()
            self.statusbar.showMessage(f"Selected network interface: {selected}", 4000)

    def show_about(self):
        QMessageBox.about(
            self,
            "About SentinelShark",
            "<h3>SentinelShark NIDS v1.0</h3>"
            "<p>A modern desktop Network Intrusion Detection & Analysis System (NIDS) "
            "written in Python with PyQt6, PyShark, and httpx.</p>"
            "<p>Enriches live network traffic with real-time threat intelligence and geolocation data "
            "from <b>VirusTotal</b>, <b>AbuseIPDB</b>, and <b>IPinfo</b>.</p>"
        )

    def closeEvent(self, event):
        self.stop_capture()
        super().closeEvent(event)
