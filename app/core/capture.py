import json
import random
import subprocess
import time
from typing import List, Optional
from PyQt6.QtCore import QThread, pyqtSignal

from app.config import config
from app.core.parser import PacketDissector, format_hex_dump, calculate_payload_hash


def get_available_interfaces() -> List[str]:
    """Dynamically discover available network interfaces on host."""
    interfaces = []
    
    # Try PyShark / TShark interface discovery first
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


def sanitize_bpf_filter(raw_bpf: str) -> str:
    """
    Sanitizes user input into valid BPF syntax for pcap/tshark.
    Translates display filter shortcuts (http, dns, https, ssh, raw IP) to valid BPF expressions.
    """
    if not raw_bpf:
        return ""
    clean = raw_bpf.strip().lower()
    
    # Common user shortcuts -> BPF syntax translations
    if clean in ("http", "web"):
        return "tcp port 80 or tcp port 8080"
    if clean in ("https", "ssl", "tls"):
        return "tcp port 443"
    if clean == "dns":
        return "port 53"
    if clean == "ssh":
        return "tcp port 22"
    if clean == "icmp":
        return "icmp"
    if clean == "tcp":
        return "tcp"
    if clean == "udp":
        return "udp"
    
    # Check if user typed a raw IP address e.g. "8.8.8.8" or "192.168.1.1"
    parts = clean.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"host {raw_bpf.strip()}"
    
    return raw_bpf.strip()


class LiveCaptureThread(QThread):
    """
    Dedicated QThread for high-performance live network packet capture.
    Uses direct TShark line-buffered subprocess streaming for terminal-grade capture speeds (>500 pkts/s),
    with automatic fallbacks to PyShark and high-speed Mock Traffic Generation.
    """

    packet_received = pyqtSignal(dict)
    packets_batch_received = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    permission_error_occurred = pyqtSignal(str)
    status_changed = pyqtSignal(str)

    def __init__(self, interface: str = "auto", bpf_filter: str = "", pcap_file: str = ""):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter.strip()
        self.pcap_file = pcap_file
        self.is_running = False
        self._capture_proc: Optional[subprocess.Popen] = None
        self._pyshark_capture = None
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

        if self.pcap_file:
            self.run_pcap_capture(tshark_exec)
            return

        # Attempt high-speed direct TShark subprocess capture first
        success = self.run_direct_tshark_capture(tshark_exec)
        if not success and self.is_running:
            # Try PyShark LiveCapture fallback
            print("[CaptureThread] Direct TShark failed. Attempting PyShark LiveCapture fallback...")
            self.run_pyshark_live_capture(tshark_exec)

    def run_direct_tshark_capture(self, tshark_exec: str) -> bool:
        """
        High-performance direct TShark subprocess capture engine.
        Reads JSON line-buffered streaming stdout with zero PyShark DOM overhead.
        """
        target_iface = self.interface if (self.interface and self.interface != "auto") else "en0"
        self.status_changed.emit(f"Starting Live Capture on {target_iface}...")

        sanitized_bpf = sanitize_bpf_filter(self.bpf_filter)
        
        # Build tshark command line
        cmd = [
            tshark_exec,
            "-l",               # Flush stdout after each packet (CRITICAL for real-time)
            "-n",               # Don't resolve hostnames (FAST)
            "-i", target_iface,
            "-T", "json",
            "-x"                # Hex raw bytes
        ]

        if sanitized_bpf:
            cmd.extend(["-f", sanitized_bpf])

        print(f"[CaptureThread] Launching: {' '.join(cmd)}")

        try:
            self._capture_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except Exception as e:
            print(f"[CaptureThread] Failed to launch tshark process: {e}")
            return False

        # Check if process immediately exits (e.g. permission error)
        time.sleep(0.3)
        if self._capture_proc.poll() is not None:
            err_out = self._capture_proc.stderr.read() if self._capture_proc.stderr else ""
            out_str = self._capture_proc.stdout.read() if self._capture_proc.stdout else ""
            full_err = (err_out + "\n" + out_str).strip()
            print(f"[CaptureThread] TShark process exited immediately with code {self._capture_proc.returncode}: {full_err}")

            if "permission" in full_err.lower() or "bpf" in full_err.lower() or "operation not permitted" in full_err.lower() or "access is denied" in full_err.lower():
                perm_msg = f"Permission denied on capture interface '{target_iface}'."
                print(f"[CaptureThread] {perm_msg}")
                self.permission_error_occurred.emit(perm_msg)
                self.status_changed.emit("Permission error on capture interface.")
                self.run_mock_capture()
                return True
            else:
                self.error_occurred.emit(f"TShark Error: {full_err}")
                self.run_mock_capture()
                return True

        self.status_changed.emit(f"Capture active on {target_iface}. Sniffing packets...")

        json_buffer = ""
        in_object = False
        brace_count = 0
        packet_batch = []
        last_flush_time = time.time()

        try:
            while self.is_running and self._capture_proc:
                if self._capture_proc.poll() is not None:
                    break

                line = self._capture_proc.stdout.readline()
                if not line:
                    time.sleep(0.005)
                    continue

                line_str = line.strip()

                if line_str in ("{", "[") or line_str.startswith("{") or line_str.startswith('{ "'):
                    if line_str != "[":
                        in_object = True

                if in_object:
                    json_buffer += line

                    for char in line:
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1

                    if brace_count == 0 and json_buffer.strip():
                        clean_json = json_buffer.strip().rstrip(",")
                        json_buffer = ""
                        in_object = False

                        try:
                            pkt_data = json.loads(clean_json)
                            if "_source" in pkt_data:
                                self._packet_count += 1
                                parsed_pkt = PacketDissector.dissect_tshark_json_packet(pkt_data, self._packet_count)
                                packet_batch.append(parsed_pkt)
                                self.packet_received.emit(parsed_pkt)

                                now = time.time()
                                if len(packet_batch) >= 20 or (now - last_flush_time) >= 0.04:
                                    self.packets_batch_received.emit(list(packet_batch))
                                    packet_batch.clear()
                                    last_flush_time = now
                        except json.JSONDecodeError:
                            pass

                now = time.time()
                if packet_batch and (now - last_flush_time) >= 0.04:
                    self.packets_batch_received.emit(list(packet_batch))
                    packet_batch.clear()
                    last_flush_time = now

            if packet_batch:
                self.packets_batch_received.emit(list(packet_batch))

        except Exception as e:
            print(f"[CaptureThread] Direct TShark streaming error: {e}")

        if self._packet_count > 0:
            return True

        return False

    def run_pyshark_live_capture(self, tshark_exec: str):
        """PyShark LiveCapture engine fallback."""
        try:
            import pyshark
            target_iface = self.interface if (self.interface and self.interface != "auto") else None
            kwargs = {"tshark_path": tshark_exec, "include_raw": True, "use_json": True}
            if target_iface:
                kwargs["interface"] = target_iface

            sanitized_bpf = sanitize_bpf_filter(self.bpf_filter)
            if sanitized_bpf:
                kwargs["bpf_filter"] = sanitized_bpf

            self._pyshark_capture = pyshark.LiveCapture(**kwargs)
            self.status_changed.emit("PyShark Fallback active. Sniffing packets...")

            packet_batch = []
            last_flush = time.time()

            for packet in self._pyshark_capture.sniff_continuously():
                if not self.is_running:
                    break
                self._packet_count += 1
                pkt_data = PacketDissector.dissect_pyshark_packet(packet, self._packet_count)
                packet_batch.append(pkt_data)
                self.packet_received.emit(pkt_data)

                now = time.time()
                if len(packet_batch) >= 10 or (now - last_flush) >= 0.05:
                    self.packets_batch_received.emit(list(packet_batch))
                    packet_batch.clear()
                    last_flush = now

            if packet_batch:
                self.packets_batch_received.emit(list(packet_batch))

        except Exception as e:
            if self.is_running:
                err_str = str(e)
                print(f"[CaptureThread] PyShark error: {err_str}")
                if "permission" in err_str.lower() or "bpf" in err_str.lower():
                    self.permission_error_occurred.emit(f"Permission denied on '{self.interface}'.")
                self.status_changed.emit("Falling back to Mock Traffic Generator...")
                self.run_mock_capture()

    def run_pcap_capture(self, tshark_exec: str):
        """Reads PCAP file with high-speed packet batching."""
        self.status_changed.emit(f"Reading PCAP file: {self.pcap_file}")
        try:
            import pyshark
            self._pyshark_capture = pyshark.FileCapture(
                self.pcap_file,
                tshark_path=tshark_exec,
                include_raw=True,
                use_json=True
            )
            packet_batch = []
            for packet in self._pyshark_capture:
                if not self.is_running:
                    break
                self._packet_count += 1
                pkt_data = PacketDissector.dissect_pyshark_packet(packet, self._packet_count)
                packet_batch.append(pkt_data)
                self.packet_received.emit(pkt_data)

                if len(packet_batch) >= 25:
                    self.packets_batch_received.emit(list(packet_batch))
                    packet_batch.clear()

            if packet_batch:
                self.packets_batch_received.emit(list(packet_batch))
            self.status_changed.emit("Finished reading PCAP file.")

        except Exception as e:
            self.error_occurred.emit(f"Error reading PCAP: {e}")

    def run_mock_capture(self):
        """High-fidelity, high-speed simulated packet traffic generator (30 - 70 pkts/s)."""
        self.status_changed.emit("Mock Capture Mode Active (High-Speed Simulated Traffic)")
        
        public_destinations = [
            ("8.8.8.8", "Google DNS", "DNS"),
            ("1.1.1.1", "Cloudflare DNS", "DNS"),
            ("142.250.190.46", "Google HTTP", "HTTP"),
            ("104.16.249.249", "Cloudflare CDN", "HTTPS"),
            ("185.220.101.5", "Tor Exit Node", "TCP"),
            ("45.33.32.156", "Insecure Scanner", "SSH"),
            ("93.184.216.34", "Example.com", "HTTP"),
            ("198.51.100.45", "External Host", "TCP"),
            ("8.8.4.4", "Google DNS Secondary", "UDP"),
            ("1.0.0.1", "Cloudflare DNS Secondary", "UDP"),
            ("208.67.222.222", "OpenDNS", "UDP"),
        ]

        internal_ips = ["192.168.1.105", "192.168.1.1", "10.0.0.15", "172.16.0.4"]
        methods = ["GET /index.html", "POST /api/login", "GET /favicon.ico", "CONNECT gateway:443"]

        packet_batch = []
        last_flush = time.time()

        while self.is_running:
            self._packet_count += 1
            dst_ip, dst_desc, proto_hint = random.choice(public_destinations)
            src_ip = random.choice(internal_ips)
            
            src_port = random.randint(1024, 65535)
            dst_port = 80 if proto_hint == "HTTP" else (443 if proto_hint == "HTTPS" else (53 if proto_hint in ("DNS", "UDP") else 22))

            time_str = time.strftime("%H:%M:%S") + f".{random.randint(100, 999):03d}"
            length = random.randint(54, 1514)

            if proto_hint == "HTTP":
                method_line = random.choice(methods)
                payload_str = f"{method_line} HTTP/1.1\r\nHost: {dst_desc}\r\nUser-Agent: SentinelShark/1.0\r\nAccept: */*\r\n\r\n"
                info = f"HTTP {method_line}"
                protocol = "HTTP"
            elif proto_hint == "HTTPS":
                payload_str = f"\x16\x03\x01\x02\x00 Client Hello - SentinelShark TLS Session"
                info = f"HTTPS TLS/SSL Client Hello ({src_port} -> 443)"
                protocol = "HTTPS"
            elif proto_hint == "DNS":
                payload_str = f"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                info = f"Standard query 0x{random.randint(1000,9999):04x} A example.com"
                protocol = "DNS"
            elif proto_hint == "UDP":
                payload_str = f"SentinelShark UDP Packet Payload #{self._packet_count} - Datagram Stream"
                info = f"UDP {src_port} -> {dst_port} Len={length}"
                protocol = "UDP"
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

            packet_batch.append(pkt_dict)
            self.packet_received.emit(pkt_dict)

            now = time.time()
            if len(packet_batch) >= 10 or (now - last_flush) >= 0.03:
                self.packets_batch_received.emit(list(packet_batch))
                packet_batch.clear()
                last_flush = now

            time.sleep(random.uniform(0.015, 0.035))

    def stop(self):
        """Stop packet capture thread cleanly without blocking the main GUI thread."""
        self.is_running = False
        if self._capture_proc:
            try:
                self._capture_proc.kill()
            except Exception:
                pass
            self._capture_proc = None

        if self._pyshark_capture:
            try:
                self._pyshark_capture.close()
            except Exception:
                pass
            self._pyshark_capture = None

        self.quit()
