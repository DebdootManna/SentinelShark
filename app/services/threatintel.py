import ipaddress
import httpx
from typing import Dict, Any, Optional
from app.config import config


def is_public_ip(ip_str: str) -> bool:
    """
    Returns True if ip_str is a valid routable public IP address.
    Filters out RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
    loopback, link-local, multicast, and reserved addresses.
    """
    if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255", "::"):
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False
        return True
    except ValueError:
        return False


class ThreatIntelClient:
    """Async client for querying AbuseIPDB & VirusTotal APIs via httpx."""

    def __init__(self):
        self.timeout = httpx.Timeout(10.0, connect=5.0)

    async def fetch_abuseipdb(self, client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB API for an IP address."""
        key = config.abuseipdb_api_key
        if not key:
            return {}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }

        try:
            resp = await client.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 429:
                return {"error_code": 429, "msg": "AbuseIPDB Rate Limit Exceeded"}
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore") or 0,
                "reports_count": data.get("totalReports") or 0,
                "country": data.get("countryCode") or "",
                "domain": data.get("domain") or ""
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return {"error_code": 429, "msg": "AbuseIPDB Rate Limit Exceeded"}
            print(f"[ThreatIntel] AbuseIPDB HTTP Error for {ip}: {e}")
        except Exception as e:
            print(f"[ThreatIntel] AbuseIPDB error for {ip}: {e}")
        return {}

    async def fetch_virustotal(self, client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
        """Query VirusTotal v3 API for an IP address."""
        key = config.virustotal_api_key
        if not key:
            return {}

        url = f"https://www.virustotal.com/api/v3/ipaddresses/{ip}"
        headers = {
            "x-apikey": key,
            "Accept": "application/json"
        }

        try:
            resp = await client.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 429:
                return {"error_code": 429, "msg": "VirusTotal Rate Limit Exceeded"}
            resp.raise_for_status()
            attributes = resp.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            return {
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless": stats.get("harmless", 0),
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return {"error_code": 429, "msg": "VirusTotal Rate Limit Exceeded"}
            print(f"[ThreatIntel] VirusTotal HTTP Error for {ip}: {e}")
        except Exception as e:
            print(f"[ThreatIntel] VirusTotal error for {ip}: {e}")
        return {}

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Enrich a public IP address using AbuseIPDB & VirusTotal APIs.
        Returns a aggregated threat dictionary.
        """
        if not is_public_ip(ip):
            return {
                "ip": ip,
                "abuse_score": 0,
                "vt_malicious": 0,
                "vt_suspicious": 0,
                "vt_harmless": 0,
                "country": "LOCAL",
                "reports_count": 0,
                "domain": "Internal/Non-routable",
                "is_public": False
            }

        result = {
            "ip": ip,
            "abuse_score": 0,
            "vt_malicious": 0,
            "vt_suspicious": 0,
            "vt_harmless": 0,
            "country": "",
            "reports_count": 0,
            "domain": "",
            "is_public": True,
            "has_429": False
        }

        async with httpx.AsyncClient() as client:
            abuse_data = await self.fetch_abuseipdb(client, ip)
            if abuse_data.get("error_code") == 429:
                result["has_429"] = True
            else:
                result.update(abuse_data)

            vt_data = await self.fetch_virustotal(client, ip)
            if vt_data.get("error_code") == 429:
                result["has_429"] = True
            else:
                result.update(vt_data)

        return result


# Global threat intel client
threat_client = ThreatIntelClient()
