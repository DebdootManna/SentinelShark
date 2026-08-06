import time
from typing import Dict, Any, Optional
from cachetools import TTLCache
from app.config import config


class ThreatCache:
    """
    High-performance in-memory TTL manager for Threat Intelligence.
    Eliminates database file I/O overhead while preventing redundant API requests.
    """

    def __init__(self, ttl_hours: int = 24, max_memory_entries: int = 2000):
        self.ttl_seconds = ttl_hours * 3600
        self.mem_cache: TTLCache = TTLCache(maxsize=max_memory_entries, ttl=self.ttl_seconds)

    def _is_complete(self, data: Dict[str, Any]) -> bool:
        """Check if cached entry contains data for all currently configured API services."""
        if config.ipinfo_api_key:
            ipinfo = data.get("ipinfo_details")
            if not ipinfo or not isinstance(ipinfo, dict) or len(ipinfo) == 0:
                return False
        return True

    def clear_memory(self):
        """Flush in-memory TTL cache."""
        self.mem_cache.clear()

    def clear_all(self):
        """Purge all records from in-memory cache."""
        self.mem_cache.clear()

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieve threat data for an IP if present and complete."""
        if ip in self.mem_cache:
            data = self.mem_cache[ip]
            if self._is_complete(data):
                return data
            else:
                del self.mem_cache[ip]
        return None

    def set(self, ip: str, threat_data: Dict[str, Any]):
        """Save or update threat intelligence for an IP in memory."""
        now = int(time.time())
        if "ipinfo_details" in threat_data and isinstance(threat_data["ipinfo_details"], dict):
            details = threat_data["ipinfo_details"]
            threat_data.setdefault("ipinfo_org", details.get("org") or "")
            threat_data.setdefault("ipinfo_hostname", details.get("hostname") or "")
            threat_data.setdefault("ipinfo_city", details.get("city") or "")
            threat_data.setdefault("ipinfo_region", details.get("region") or "")
            threat_data.setdefault("ipinfo_country", details.get("country") or "")
            threat_data.setdefault("ipinfo_loc", details.get("loc") or "")
            threat_data.setdefault("ipinfo_timezone", details.get("timezone") or "")
            threat_data.setdefault("ipinfo_postal", details.get("postal") or "")
            threat_data.setdefault("ipinfo_anycast", details.get("anycast", False))

        threat_data["ip"] = ip
        threat_data["cached"] = True
        threat_data["updated_at"] = now
        self.mem_cache[ip] = threat_data


# Global cache singleton
cache = ThreatCache(ttl_hours=config.cache_ttl_hours)
