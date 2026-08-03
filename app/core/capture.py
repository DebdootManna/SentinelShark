import random
import time
from typing import List, Optional
from PyQt6.QtCore import QThread, pyqtSignal

from app.config import config
from app.core.parser import PacketDissector, format_hex_dump, calculate_payload_hash


def get_available_interfaces() -> List[str]:
    """Dynamically discover available network interfaces on host."""
    interfaces = []
    
    # Try PyShark tshark interface discovery first
    if config.is_tshark_available:
        try:
            import pyshark.tshark.tshark as tshark_mod
            if hasattr(tshark_mod, "get_tshark_interfaces"):
                interfaces = tshark_mod.get_tshark_interfaces(tshark_path=config.find_tshark())
        except Exception as e:
            print(f"[Capture] Error getting tshark interfaces: {e}")

    if not interfaces:
        # Standard macOS / Linux common interface defaults
        interfaces = ["en0", "lo0", "eth0", "wlan0", "any"]

    return list(dict.fromkeys(interfaces))  # Unique list preserving order


class LiveCaptureThread(QThread):
    """
    Dedicated QThread for PyShark LiveCapture / FileCapture.
    Emits PyQt signals to ensure GUI thread frame rates remain 60 FPS responsive.
    """

    packet_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    status_changed = pyqtSignal(str)

    def __init__(self, interface: str = "auto", bpf_filter: str = "", pcap_file: str = ""):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter.strip()
        self.pcap_file = pcap_file
        self.is_running = False
        self._capture = None
        self._packet_count = 0

    def run(self):
        """Execute capture loop in worker thread."""
        self.is_running = True
        self._packet_count = 0
        tshark_exec = config.find_tshark()

        # If Mock mode is forced or TShark is not installed, run Mock Generator
        if config.mock_mode or (not tshark_exec and not self.pcap_file):
            if not tshark_exec:
                self.status_changed.emit("TShark binary not found on host. Running in Mock Mode.")
            else:
                self.status_changed.emit("Mock Capture Mode Active.")
            self.run_mock_capture()
            return

        try:
            import pyshark

            if self.pcap_file:
                self.status_changed.emit(f"Reading PCAP file: {self.pcap_file}")
                self._capture = pyshark.FileCapture(
                    self.pcap_file,
                    tshark_path=tshark_exec
                )
            else:
                target_iface = self.interface if (self.interface and self.interface != "auto") else None
                self.status_changed.emit(f"Starting Live Capture on {target_iface or 'default interface'}...")
                
                kwargs = {"tshark_path": tshark_exec}
                if target_iface:
                    kwargs["interface"] = target_iface
                if self.bpf_filter:
                    kwargs["bpf_filter"] = self.bpf_filter

                self._capture = pyshark.LiveCapture(**kwargs)

            self.status_changed.emit("Capture active. Sniffing packets...")

            for packet in self._capture.sniff_continuously():
                if not self.is_running:
                    break
                self._packet_count += 1
                pkt_data = PacketDissector.dissect_pyshark_packet(packet, self._packet_count)
                self.packet_received.emit(pkt_data)

        except Exception as e:
            if self.is_running:
                err_str = str(e)
                if "permission" in err_str.lower() or "bpf" in err_str.lower():
                    error_msg = f"Live Capture Permission Error on interface '{self.interface}'. (Run with sudo or switch to Mock Mode)"
                else:
                    error_msg = f"Capture Error: {err_str}"
                
                print(f"[CaptureThread] {error_msg}")
                self.error_occurred.emit(error_msg)
                self.status_changed.emit("Falling back to Mock Traffic Generator...")
                self.run_mock_capture()
        finally:
            self.status_changed.emit("Capture stopped.")

    def run_mock_capture(self):
        """High-fidelity simulated packet traffic generator."""
        self.status_changed.emit("Mock Capture Mode Active (Simulated Traffic)")
        
        # Sample pool of source and destination IPs (including known public & suspicious IPs)
        public_destinations = [
            ("8.8.8.8", "Google DNS", "DNS"),
            ("1.1.1.1", "Cloudflare DNS", "DNS"),
            ("142.250.190.46", "Google HTTP", "HTTP"),
            ("104.16.249.249", "Cloudflare CDN", "HTTPS"),
            ("185.220.101.5", "Tor Exit Node", "TCP"),  # Suspicious public IP
            ("45.33.32.156", "Insecure Scanner", "SSH"), # Suspicious public IP
            ("93.184.216.34", "Example.com", "HTTP"),
            ("198.51.100.45", "External Host", "TCP"),
        ]

        internal_ips = ["192.168.1.105", "192.168.1.1", "10.0.0.15", "172.16.0.4"]
        methods = ["GET /index.html", "POST /api/login", "GET /favicon.ico", "CONNECT gateway:443"]

        while self.is_running:
            self._packet_count += 1
            dst_ip, dst_desc, proto_hint = random.choice(public_destinations)
            src_ip = random.choice(internal_ips)
            
            src_port = random.randint(1024, 65535)
            dst_port = 80 if proto_hint == "HTTP" else (443 if proto_hint == "HTTPS" else (53 if proto_hint == "DNS" else 22))

            time_str = time.strftime("%H:%M:%S") + f".{random.randint(100, 999):03d}"
            length = random.randint(54, 1514)

            # Generate realistic payload bytes
            if proto_hint == "HTTP":
                method_line = random.choice(methods)
                payload_str = f"{method_line} HTTP/1.1\r\nHost: {dst_desc}\r\nUser-Agent: SentinelShark/1.0\r\nAccept: */*\r\n\r\n"
                info = f"HTTP {method_line}"
                protocol = "HTTP"
            elif proto_hint == "DNS":
                payload_str = f"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                info = f"Standard query 0x{random.randint(1000,9999):04x} A example.com"
                protocol = "DNS"
            else:
                payload_str = f"SentinelShark Packet Payload #{self._packet_count} - Protocol {proto_hint} Data Stream"
                info = f"{proto_hint} {src_port} -> {dst_port} [SYN, ACK] Seq=1 Ack=1 Win=64240 Len={length-54}"
                protocol = proto_hint

            raw_bytes = payload_str.encode("utf-8", errors="ignore")
            hex_dump, ascii_str = format_hex_dump(raw_bytes)
            hashes = calculate_payload_hash(raw_bytes)

            layers_tree = [
                {
                    "name": f"Frame {self._packet_count}: {length} bytes on wire",
                    "children": [
                        f"Arrival Time: {time_str}",
                        f"Frame Length: {length} bytes",
                        f"Protocols in Frame: eth:ip:{protocol.lower()}"
                    ]
                },
                {
                    "name": f"Ethernet II, Src: 00:11:22:33:44:55, Dst: 66:77:88:99:aa:bb",
                    "children": [
                        "Destination: 66:77:88:99:aa:bb",
                        "Source: 00:11:22:33:44:55",
                        "Type: IPv4 (0x0800)"
                    ]
                },
                {
                    "name": f"Internet Protocol Version 4, Src: {src_ip}, Dst: {dst_ip}",
                    "children": [
                        "Version: 4",
                        "Header Length: 20 bytes",
                        "Time to Live (TTL): 64",
                        f"Protocol: {protocol}",
                        f"Source Address: {src_ip}",
                        f"Destination Address: {dst_ip}"
                    ]
                },
                {
                    "name": f"{protocol} Layer, Src Port: {src_port}, Dst Port: {dst_port}",
                    "children": [
                        f"Source Port: {src_port}",
                        f"Destination Port: {dst_port}",
                        f"Payload Size: {len(raw_bytes)} bytes",
                        f"MD5 Hash: {hashes['md5']}",
                        f"SHA256 Hash: {hashes['sha256']}"
                    ]
                }
            ]

            pkt_dict = {
                "no": self._packet_count,
                "time": time_str,
                "src": src_ip,
                "dst": dst_ip,
                "src_port": str(src_port),
                "dst_port": str(dst_port),
                "protocol": protocol,
                "length": length,
                "info": info,
                "raw_bytes": raw_bytes,
                "hex_dump": hex_dump,
                "ascii_str": ascii_str,
                "payload_md5": hashes["md5"],
                "payload_sha256": hashes["sha256"],
                "layers_tree": layers_tree,
                "threat_score": 0,
                "threat_data": None
            }

            self.packet_received.emit(pkt_dict)
            time.sleep(random.uniform(0.1, 0.4))

    def stop(self):
        """Stop packet capture thread cleanly."""
        self.is_running = False
        if self._capture:
            try:
                self._capture.close()
            except Exception:
                pass
        self.wait(1000)
