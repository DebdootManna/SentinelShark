import json
import sqlite3
import time
from typing import Dict, Any, Optional
from cachetools import TTLCache
from app.config import CACHE_DB_PATH, config


class ThreatCache:
    """
    SQLite persistent cache & in-memory TTL manager for Threat Intelligence.
    Ensures minimal API calls and respects TTL (default 24 hours).
    """

    def __init__(self, db_path=CACHE_DB_PATH, ttl_hours: int = 24, max_memory_entries: int = 1000):
        self.db_path = str(db_path)
        self.ttl_seconds = ttl_hours * 3600
        # In-memory cache for ultra-fast UI rendering
        self.mem_cache: TTLCache = TTLCache(maxsize=max_memory_entries, ttl=self.ttl_seconds)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create threat cache table if it does not exist and ensure migrations."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_threat_cache (
                    ip TEXT PRIMARY KEY,
                    abuse_score INTEGER DEFAULT 0,
                    vt_malicious INTEGER DEFAULT 0,
                    vt_suspicious INTEGER DEFAULT 0,
                    vt_harmless INTEGER DEFAULT 0,
                    country TEXT DEFAULT '',
                    reports_count INTEGER DEFAULT 0,
                    domain TEXT DEFAULT '',
                    ipinfo_data TEXT DEFAULT '{}',
                    updated_at INTEGER NOT NULL
                )
            """)
            cursor.execute("PRAGMA table_info(ip_threat_cache)")
            columns = [row["name"] for row in cursor.fetchall()]
            if "ipinfo_data" not in columns:
                cursor.execute("ALTER TABLE ip_threat_cache ADD COLUMN ipinfo_data TEXT DEFAULT '{}'")
            conn.commit()

    def _is_complete(self, data: Dict[str, Any]) -> bool:
        """Check if cached entry contains data for all currently configured API services."""
        if config.ipinfo_api_key:
            ipinfo = data.get("ipinfo_details")
            if not ipinfo or not isinstance(ipinfo, dict) or len(ipinfo) == 0:
                return False
        return True

    def clear_memory(self):
        """Flush in-memory TTL cache to force re-evaluation of cached records."""
        self.mem_cache.clear()

    def clear_all(self):
        """Purge all records from SQLite and in-memory cache."""
        self.mem_cache.clear()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ip_threat_cache")
            conn.commit()

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieve threat data for an IP if present, complete, and unexpired."""
        # Check in-memory cache first
        if ip in self.mem_cache:
            data = self.mem_cache[ip]
            if self._is_complete(data):
                return data
            else:
                del self.mem_cache[ip]

        now = int(time.time())
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM ip_threat_cache WHERE ip = ?", (ip,)
            )
            row = cursor.fetchone()
            if row:
                row_dict = dict(row)
                updated_at = row_dict.get("updated_at", 0)
                # Check TTL
                if (now - updated_at) < self.ttl_seconds:
                    ipinfo_raw = row_dict.get("ipinfo_data") or "{}"
                    try:
                        ipinfo_details = json.loads(ipinfo_raw) if isinstance(ipinfo_raw, str) else {}
                    except Exception:
                        ipinfo_details = {}

                    data = {
                        "ip": row_dict["ip"],
                        "abuse_score": row_dict["abuse_score"],
                        "vt_malicious": row_dict["vt_malicious"],
                        "vt_suspicious": row_dict["vt_suspicious"],
                        "vt_harmless": row_dict["vt_harmless"],
                        "country": row_dict["country"],
                        "reports_count": row_dict["reports_count"],
                        "domain": row_dict["domain"],
                        "ipinfo_details": ipinfo_details,
                        "ipinfo_org": ipinfo_details.get("org") or "",
                        "ipinfo_hostname": ipinfo_details.get("hostname") or "",
                        "ipinfo_city": ipinfo_details.get("city") or "",
                        "ipinfo_region": ipinfo_details.get("region") or "",
                        "ipinfo_country": ipinfo_details.get("country") or "",
                        "ipinfo_loc": ipinfo_details.get("loc") or "",
                        "ipinfo_timezone": ipinfo_details.get("timezone") or "",
                        "ipinfo_postal": ipinfo_details.get("postal") or "",
                        "ipinfo_anycast": ipinfo_details.get("anycast", False),
                        "cached": True,
                        "updated_at": updated_at
                    }
                    if self._is_complete(data):
                        self.mem_cache[ip] = data
                        return data
                    else:
                        # Incomplete entry for current config -> purge from SQLite
                        cursor.execute("DELETE FROM ip_threat_cache WHERE ip = ?", (ip,))
                        conn.commit()
                else:
                    # Expired entry
                    cursor.execute("DELETE FROM ip_threat_cache WHERE ip = ?", (ip,))
                    conn.commit()
        return None

    def set(self, ip: str, threat_data: Dict[str, Any]):
        """Save or update threat intelligence for an IP."""
        now = int(time.time())
        abuse_score = threat_data.get("abuse_score", 0)
        vt_malicious = threat_data.get("vt_malicious", 0)
        vt_suspicious = threat_data.get("vt_suspicious", 0)
        vt_harmless = threat_data.get("vt_harmless", 0)
        country = threat_data.get("country", "")
        reports_count = threat_data.get("reports_count", 0)
        domain = threat_data.get("domain", "")
        ipinfo_details = threat_data.get("ipinfo_details", {})
        ipinfo_json = json.dumps(ipinfo_details) if isinstance(ipinfo_details, dict) else "{}"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_threat_cache 
                (ip, abuse_score, vt_malicious, vt_suspicious, vt_harmless, country, reports_count, domain, ipinfo_data, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    abuse_score = excluded.abuse_score,
                    vt_malicious = excluded.vt_malicious,
                    vt_suspicious = excluded.vt_suspicious,
                    vt_harmless = excluded.vt_harmless,
                    country = excluded.country,
                    reports_count = excluded.reports_count,
                    domain = excluded.domain,
                    ipinfo_data = excluded.ipinfo_data,
                    updated_at = excluded.updated_at
            """, (ip, abuse_score, vt_malicious, vt_suspicious, vt_harmless, country, reports_count, domain, ipinfo_json, now))
            conn.commit()

        # Update in-memory cache
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

    def purge_expired(self):
        """Purge records older than TTL from SQLite."""
        threshold = int(time.time()) - self.ttl_seconds
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ip_threat_cache WHERE updated_at < ?", (threshold,))
            conn.commit()


# Global cache instance
cache = ThreatCache(ttl_hours=config.cache_ttl_hours)
