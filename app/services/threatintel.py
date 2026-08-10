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
            if resp.status_code == 404:
                return {"vt_malicious": 0, "vt_suspicious": 0, "vt_harmless": 0}
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
            if e.response.status_code == 404:
                return {"vt_malicious": 0, "vt_suspicious": 0, "vt_harmless": 0}
            print(f"[ThreatIntel] VirusTotal HTTP Error {e.response.status_code} for {ip}")
        except Exception as e:
            print(f"[ThreatIntel] VirusTotal error for {ip}: {e}")
        return {}

    async def fetch_ipinfo(self, client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
        """Query IPinfo API for an IP address."""
        key = config.ipinfo_api_key
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"Accept": "application/json"}
        params = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"
            params["token"] = key

        try:
            resp = await client.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 429:
                return {"error_code": 429, "msg": "IPinfo Rate Limit Exceeded"}
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                data = {}
            return {
                "ipinfo_details": data,
                "ipinfo_org": data.get("org") or "",
                "ipinfo_hostname": data.get("hostname") or "",
                "ipinfo_city": data.get("city") or "",
                "ipinfo_region": data.get("region") or "",
                "ipinfo_country": data.get("country") or "",
                "ipinfo_loc": data.get("loc") or "",
                "ipinfo_timezone": data.get("timezone") or "",
                "ipinfo_postal": data.get("postal") or "",
                "ipinfo_anycast": data.get("anycast", False)
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                return {"error_code": 429, "msg": "IPinfo Rate Limit Exceeded"}
            print(f"[ThreatIntel] IPinfo HTTP Error {e.response.status_code} for {ip}")
        except Exception as e:
            print(f"[ThreatIntel] IPinfo error for {ip}: {e}")
        return {}

    async def fetch_shodan(self, client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
        """Query Shodan Host API for open ports, OS, vulnerabilities, and host information."""
        key = config.shodan_api_key
        if not key:
            return {"shodan_status": "No API Key Configured"}

        is_v6 = ":" in ip
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": key}

        try:
            resp = await client.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 401:
                print(f"[ThreatIntel] Shodan HTTP 401 (Invalid API Key) for {ip}")
                return {"shodan_status": "Invalid API Key (HTTP 401)"}
            if resp.status_code == 403:
                status_msg = "IPv6 Host Query Requires Paid Shodan Plan (HTTP 403)" if is_v6 else "Access Forbidden / Key Restricted (HTTP 403)"
                print(f"[ThreatIntel] Shodan HTTP 403 for {ip} ({status_msg})")
                return {"shodan_status": status_msg}
            if resp.status_code == 429:
                print(f"[ThreatIntel] Shodan HTTP 429 (Rate Limit Exceeded) for {ip}")
                return {"error_code": 429, "msg": "Shodan Rate Limit Exceeded", "shodan_status": "Rate Limit Exceeded (HTTP 429)"}
            if resp.status_code == 404:
                status_msg = "IPv6 Host Not Indexed in Shodan" if is_v6 else "Host Not Found in Shodan Index"
                print(f"[ThreatIntel] Shodan HTTP 404 for {ip} ({status_msg})")
                return {"shodan_status": status_msg}
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                data = {}

            vulns = data.get("vulns", [])
            if isinstance(vulns, dict):
                vulns_list = list(vulns.keys())
            elif isinstance(vulns, list):
                vulns_list = vulns
            else:
                vulns_list = []

            print(f"[ThreatIntel] Shodan HTTP 200 OK for {ip}: {len(data.get('ports', []))} ports, {len(vulns_list)} vulns")
            return {
                "shodan_details": data,
                "shodan_ports": data.get("ports", []),
                "shodan_org": data.get("org") or "",
                "shodan_os": data.get("os") or "",
                "shodan_hostnames": data.get("hostnames", []),
                "shodan_tags": data.get("tags", []),
                "shodan_vulns": vulns_list,
                "shodan_country": data.get("country_code") or "",
                "shodan_status": "OK"
            }
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            if code == 401:
                print(f"[ThreatIntel] Shodan HTTP 401 (Invalid API Key) for {ip}")
                return {"shodan_status": "Invalid API Key (HTTP 401)"}
            if code == 403:
                status_msg = "IPv6 Host Query Requires Paid Shodan Plan (HTTP 403)" if is_v6 else "Access Forbidden / Key Restricted (HTTP 403)"
                print(f"[ThreatIntel] Shodan HTTP 403 for {ip} ({status_msg})")
                return {"shodan_status": status_msg}
            if code == 429:
                print(f"[ThreatIntel] Shodan HTTP 429 (Rate Limit Exceeded) for {ip}")
                return {"error_code": 429, "msg": "Shodan Rate Limit Exceeded", "shodan_status": "Rate Limit Exceeded (HTTP 429)"}
            if code == 404:
                status_msg = "IPv6 Host Not Indexed in Shodan" if is_v6 else "Host Not Found in Shodan Index"
                print(f"[ThreatIntel] Shodan HTTP 404 for {ip} ({status_msg})")
                return {"shodan_status": status_msg}
            print(f"[ThreatIntel] Shodan HTTP Error {code} for {ip}: {e}")
            return {"shodan_status": f"HTTP Error {code}"}
        except Exception as e:
            print(f"[ThreatIntel] Shodan error for {ip}: {e}")
            return {"shodan_status": f"Lookup Error: {e}"}

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Enrich a public IP address using AbuseIPDB, VirusTotal, IPinfo & Shodan APIs.
        Returns an aggregated threat & geolocation dictionary.
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
                "is_public": False,
                "ipinfo_details": {},
                "shodan_details": {},
                "shodan_ports": [],
                "shodan_vulns": [],
                "shodan_status": "Non-Routable Private IP"
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
            "has_429": False,
            "ipinfo_details": {},
            "shodan_details": {},
            "shodan_ports": [],
            "shodan_vulns": []
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

            ipinfo_data = await self.fetch_ipinfo(client, ip)
            if ipinfo_data.get("error_code") == 429:
                result["has_429"] = True
            else:
                result.update(ipinfo_data)

            shodan_data = await self.fetch_shodan(client, ip)
            if shodan_data.get("error_code") == 429:
                result["has_429"] = True
            else:
                result.update(shodan_data)

        # Fallback country or domain if not populated by AbuseIPDB
        if not result.get("country"):
            if result.get("shodan_country"):
                result["country"] = result["shodan_country"]
            elif result.get("ipinfo_country"):
                result["country"] = result["ipinfo_country"]

        if not result.get("domain"):
            if result.get("shodan_hostnames"):
                result["domain"] = result["shodan_hostnames"][0]
            elif result.get("shodan_org"):
                result["domain"] = result["shodan_org"]
            elif result.get("ipinfo_hostname"):
                result["domain"] = result["ipinfo_hostname"]
            elif result.get("ipinfo_org"):
                result["domain"] = result["ipinfo_org"]

        return result


# Global threat intel client
threat_client = ThreatIntelClient()
