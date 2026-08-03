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
        """Create threat cache table if it does not exist."""
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
                    updated_at INTEGER NOT NULL
                )
            """)
            conn.commit()

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieve threat data for an IP if present and unexpired."""
        # Check in-memory cache first
        if ip in self.mem_cache:
            return self.mem_cache[ip]

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
                    data = {
                        "ip": row_dict["ip"],
                        "abuse_score": row_dict["abuse_score"],
                        "vt_malicious": row_dict["vt_malicious"],
                        "vt_suspicious": row_dict["vt_suspicious"],
                        "vt_harmless": row_dict["vt_harmless"],
                        "country": row_dict["country"],
                        "reports_count": row_dict["reports_count"],
                        "domain": row_dict["domain"],
                        "cached": True,
                        "updated_at": updated_at
                    }
                    self.mem_cache[ip] = data
                    return data
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

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_threat_cache 
                (ip, abuse_score, vt_malicious, vt_suspicious, vt_harmless, country, reports_count, domain, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    abuse_score = excluded.abuse_score,
                    vt_malicious = excluded.vt_malicious,
                    vt_suspicious = excluded.vt_suspicious,
                    vt_harmless = excluded.vt_harmless,
                    country = excluded.country,
                    reports_count = excluded.reports_count,
                    domain = excluded.domain,
                    updated_at = excluded.updated_at
            """, (ip, abuse_score, vt_malicious, vt_suspicious, vt_harmless, country, reports_count, domain, now))
            conn.commit()

        # Update in-memory cache
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
