"""
Core telemetry enricher module for SentinelShark EDR.
Runs a background daemon continuously correlating system network sockets to host processes.
Supports psutil.net_connections and macOS non-root lsof fallback.
"""

import hashlib
import platform
import re
import subprocess
import threading
import time
from typing import Dict, Any, Optional
import psutil


class EndpointTelemetryEnricher:
    """
    Enriches network telemetry by correlating network sockets to host processes in real time.
    Maintains a high-frequency background socket polling daemon with bidirectional lookup maps.
    """

    def __init__(self):
        self._exact_map: Dict[tuple, Dict[str, Any]] = {}
        self._endpoint_map: Dict[tuple, Dict[str, Any]] = {}
        self._port_map: Dict[int, Dict[str, Any]] = {}
        self._proc_meta_cache: Dict[int, tuple[Dict[str, Any], float]] = {}
        self._lock = threading.Lock()
        self._running = True

        # Prime the cache synchronously before spawning the background worker
        self._poll_sockets()

        # Start dedicated background polling daemon (200-250ms cadence)
        self._daemon_thread = threading.Thread(target=self._daemon_loop, daemon=True, name="SocketCacheDaemon")
        self._daemon_thread.start()

    @staticmethod
    def _compute_sha256(file_path: str) -> str:
        """Compute the SHA256 hash of a file."""
        if not file_path:
            return ""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return ""

    def _get_proc_meta(self, pid: int, fallback_name: str = "") -> Dict[str, Any]:
        """Fetch and cache process metadata (cmdline, exe, sha256, username, ppid)."""
        now = time.time()
        if pid in self._proc_meta_cache:
            meta, ts = self._proc_meta_cache[pid]
            if (now - ts) < 60.0:
                return meta

        data = {
            "pid": pid,
            "ppid": 0,
            "name": fallback_name or f"PID-{pid}",
            "cmdline": "",
            "username": "",
            "exe_path": "",
            "sha256": "",
        }

        try:
            proc = psutil.Process(pid)
            data["name"] = proc.name() or fallback_name
            data["ppid"] = proc.ppid()
            try:
                cmdline = proc.cmdline()
                data["cmdline"] = " ".join(cmdline) if cmdline else ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                data["username"] = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                exe_path = proc.exe()
                data["exe_path"] = exe_path
                data["sha256"] = self._compute_sha256(exe_path)
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception:
            pass

        self._proc_meta_cache[pid] = (data, now)
        return data

    def _poll_mac_lsof(self) -> list[dict]:
        """Fallback for macOS: Parse lsof -i -n -P output which works without root."""
        entries = []
        try:
            res = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=1.0
            )
            if res.returncode != 0:
                return entries

            lines = res.stdout.strip().split("\n")
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 9:
                    continue
                comm = parts[0].replace("\\x20", " ")
                try:
                    pid = int(parts[1])
                except ValueError:
                    continue
                node_name = parts[8]

                lip, lp, rip, rp = "", 0, "", 0
                if "->" in node_name:
                    local_part, remote_part = node_name.split("->", 1)
                    l_match = re.search(r"(?:\[(.*?)\]|([^:]+)):(\d+)", local_part)
                    r_match = re.search(r"(?:\[(.*?)\]|([^:]+)):(\d+)", remote_part)
                    if l_match and r_match:
                        lip = l_match.group(1) or l_match.group(2)
                        lp = int(l_match.group(3))
                        rip = r_match.group(1) or r_match.group(2)
                        rp = int(r_match.group(3))
                elif ":" in node_name:
                    m = re.search(r"(?:\[(.*?)\]|([^:]+)):(\d+)", node_name)
                    if m:
                        lip = m.group(1) or m.group(2)
                        lp = int(m.group(3))

                if lp > 0:
                    entries.append({
                        "pid": pid,
                        "comm": comm,
                        "lip": lip,
                        "lp": lp,
                        "rip": rip,
                        "rp": rp
                    })
        except Exception:
            pass
        return entries

    def _poll_sockets(self):
        """Poll active system sockets using psutil or lsof fallback and rebuild lookup tables."""
        new_exact: Dict[tuple, Dict[str, Any]] = {}
        new_endpoint: Dict[tuple, Dict[str, Any]] = {}
        new_port: Dict[int, Dict[str, Any]] = {}

        has_psutil_data = False
        try:
            connections = psutil.net_connections(kind="inet")
            if connections:
                has_psutil_data = True
                for conn in connections:
                    if not conn.pid or not conn.laddr:
                        continue
                    meta = self._get_proc_meta(conn.pid)
                    lip = getattr(conn.laddr, "ip", "")
                    lp = getattr(conn.laddr, "port", 0)
                    rip = getattr(conn.raddr, "ip", "") if conn.raddr else ""
                    rp = getattr(conn.raddr, "port", 0) if conn.raddr else 0

                    if lp > 0:
                        new_port[lp] = meta
                        if lip and lip != "*":
                            new_endpoint[(lip, lp)] = meta
                        if rip and rp > 0:
                            new_exact[(lip, lp, rip, rp)] = meta
                            new_endpoint[(rip, rp)] = meta
        except (psutil.AccessDenied, Exception):
            has_psutil_data = False

        # Fallback to macOS lsof if psutil had no access or returned empty
        if not has_psutil_data and platform.system() == "Darwin":
            lsof_entries = self._poll_mac_lsof()
            for item in lsof_entries:
                meta = self._get_proc_meta(item["pid"], fallback_name=item["comm"])
                lp = item["lp"]
                lip = item["lip"]
                rip = item["rip"]
                rp = item["rp"]

                if lp > 0:
                    new_port[lp] = meta
                    if lip and lip != "*":
                        new_endpoint[(lip, lp)] = meta
                    if rip and rp > 0:
                        new_exact[(lip, lp, rip, rp)] = meta
                        new_endpoint[(rip, rp)] = meta

        # Atomic dictionary swap under lock
        with self._lock:
            self._exact_map = new_exact
            self._endpoint_map = new_endpoint
            self._port_map = new_port

    def _daemon_loop(self):
        """Continuous background thread loop executing every 200ms."""
        while self._running:
            try:
                self._poll_sockets()
            except Exception:
                pass
            time.sleep(0.2)

    def correlate_packet(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Dict[str, Any]:
        """
        Correlate bidirectional network packet telemetry to host processes.

        Args:
            src_ip: Source IP address
            src_port: Source port number
            dst_ip: Destination IP address
            dst_port: Destination port number

        Returns:
            Dictionary containing process telemetry (pid, ppid, name, cmdline, username, exe_path, sha256).
        """
        with self._lock:
            # 1. Exact match outbound: (src_ip, src_port, dst_ip, dst_port)
            if (src_ip, src_port, dst_ip, dst_port) in self._exact_map:
                return dict(self._exact_map[(src_ip, src_port, dst_ip, dst_port)])

            # 2. Exact match inbound: (dst_ip, dst_port, src_ip, src_port)
            if (dst_ip, dst_port, src_ip, src_port) in self._exact_map:
                return dict(self._exact_map[(dst_ip, dst_port, src_ip, src_port)])

            # 3. Endpoint match (local IP + port)
            if (src_ip, src_port) in self._endpoint_map:
                return dict(self._endpoint_map[(src_ip, src_port)])
            if (dst_ip, dst_port) in self._endpoint_map:
                return dict(self._endpoint_map[(dst_ip, dst_port)])

            # 4. Local port match (ephemeral client port or listening server port)
            if src_port > 0 and src_port in self._port_map:
                return dict(self._port_map[src_port])
            if dst_port > 0 and dst_port in self._port_map:
                return dict(self._port_map[dst_port])

        # 5. Clean fallback display when socket belongs to kernel, transit, or transient connection
        return {
            "pid": "—",
            "ppid": 0,
            "name": "System / Kernel",
            "cmdline": "",
            "username": "system",
            "exe_path": "",
            "sha256": "",
            "is_fallback": True
        }

    def correlate_socket(self, local_port: int, remote_ip: str = "", remote_port: int = 0) -> Dict[str, Any]:
        """Backward-compatible socket correlation method."""
        return self.correlate_packet("", local_port, remote_ip, remote_port)

    def stop(self):
        """Stop background socket daemon."""
        self._running = False


# Global singleton
telemetry_enricher = EndpointTelemetryEnricher()

