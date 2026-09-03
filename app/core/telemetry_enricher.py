"""
Core telemetry enricher module for SentinelShark EDR.
Correlates network sockets to host processes.
"""

import hashlib
import psutil
from typing import Dict, Any, Optional
import cachetools

class EndpointTelemetryEnricher:
    """
    Enriches network telemetry by correlating network sockets to host processes.
    """

    def __init__(self):
        """
        Initialize the enricher with a TTL cache for process metadata.
        Cache is keyed by (local_port, remote_ip, remote_port).
        """
        self.cache = cachetools.TTLCache(maxsize=2048, ttl=10)

    @staticmethod
    def _compute_sha256(file_path: str) -> str:
        """
        Compute the SHA256 hash of a file.

        Args:
            file_path: The path to the file.

        Returns:
            The SHA256 hex digest, or an empty string if unable to read the file.
        """
        if not file_path:
            return ""

        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError):
            return ""

    def correlate_socket(self, local_port: int, remote_ip: str, remote_port: int) -> Dict[str, Any]:
        """
        Correlate a network socket tuple to a host process.

        Args:
            local_port: The local port number.
            remote_ip: The remote IP address.
            remote_port: The remote port number.

        Returns:
            A dictionary containing process metadata.
        """
        cache_key = (local_port, remote_ip, remote_port)
        if cache_key in self.cache:
            return self.cache[cache_key]

        target_conn = None
        try:
            connections = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            return {"error": "Access denied when retrieving network connections"}
        
        # Try exact match first
        for conn in connections:
            if conn.laddr and conn.laddr.port == local_port:
                if conn.raddr and getattr(conn.raddr, 'ip', None) == remote_ip and getattr(conn.raddr, 'port', None) == remote_port:
                    target_conn = conn
                    break
        
        # Fallback to local port match only
        if not target_conn:
            for conn in connections:
                if conn.laddr and conn.laddr.port == local_port:
                    target_conn = conn
                    break
        
        if not target_conn or not target_conn.pid:
            result = {"error": "Process not found for socket"}
            self.cache[cache_key] = result
            return result

        pid = target_conn.pid
        result = {"pid": pid}

        try:
            proc = psutil.Process(pid)
            result["ppid"] = proc.ppid()
            result["name"] = proc.name()
            try:
                cmdline = proc.cmdline()
                result["cmdline"] = " ".join(cmdline) if cmdline else ""
            except psutil.AccessDenied:
                result["cmdline"] = ""
            
            try:
                result["username"] = proc.username()
            except psutil.AccessDenied:
                result["username"] = ""
                
            try:
                exe_path = proc.exe()
                result["exe_path"] = exe_path
                result["sha256"] = self._compute_sha256(exe_path)
            except psutil.AccessDenied:
                result["exe_path"] = ""
                result["sha256"] = ""
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            result["error"] = f"Error retrieving process info: {type(e).__name__}"
        except Exception as e:
            result["error"] = f"Unexpected error: {type(e).__name__}"

        self.cache[cache_key] = result
        return result

# Global singleton
telemetry_enricher = EndpointTelemetryEnricher()
