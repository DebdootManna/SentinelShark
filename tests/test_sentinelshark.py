import os
import time
import tempfile
import unittest
from pathlib import Path

from app.config import Config
from app.core.cache import ThreatCache
from app.services.threatintel import is_public_ip
from app.core.parser import PacketDissector, format_hex_dump, calculate_payload_hash


class TestSentinelSharkCore(unittest.TestCase):

    def test_is_public_ip_filtering(self):
        """Test that private (RFC 1918), loopback, link-local, and multicast IPs are filtered out."""
        # Non-routable / Private IPs -> Should return False
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("172.16.0.50"))
        self.assertFalse(is_public_ip("192.168.1.100"))
        self.assertFalse(is_public_ip("169.254.1.1"))
        self.assertFalse(is_public_ip("224.0.0.1"))
        self.assertFalse(is_public_ip("0.0.0.0"))
        self.assertFalse(is_public_ip("255.255.255.255"))
        self.assertFalse(is_public_ip("invalid_ip"))

        # Routable Public IPs -> Should return True
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertTrue(is_public_ip("1.1.1.1"))
        self.assertTrue(is_public_ip("185.220.101.5"))
        self.assertTrue(is_public_ip("93.184.216.34"))

    def test_sqlite_threat_cache(self):
        """Test SQLite persistent cache & TTL expiration logic."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        try:
            # Create cache with 1-hour TTL
            cache = ThreatCache(db_path=db_path, ttl_hours=1)
            
            # Initial lookup -> Should return None
            self.assertIsNone(cache.get("8.8.8.8"))

            # Store threat intel
            threat_data = {
                "abuse_score": 15,
                "vt_malicious": 2,
                "vt_suspicious": 1,
                "vt_harmless": 70,
                "country": "US",
                "reports_count": 5,
                "domain": "dns.google"
            }
            cache.set("8.8.8.8", threat_data)

            # Retrieve from cache
            cached = cache.get("8.8.8.8")
            self.assertIsNotNone(cached)
            self.assertEqual(cached["abuse_score"], 15)
            self.assertEqual(cached["vt_malicious"], 2)
            self.assertEqual(cached["country"], "US")
            self.assertTrue(cached["cached"])

            # Test TTL expiration simulation
            expired_cache = ThreatCache(db_path=db_path, ttl_hours=0) # 0 seconds TTL
            expired_cache.mem_cache.clear()
            self.assertIsNone(expired_cache.get("8.8.8.8"))

        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_hex_dump_and_hashing(self):
        """Test format_hex_dump and payload hash calculations."""
        raw_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        hex_dump, ascii_str = format_hex_dump(raw_payload)

        self.assertIn("0000", hex_dump)
        self.assertIn("GET /ind", ascii_str)

        hashes = calculate_payload_hash(raw_payload)
        self.assertEqual(len(hashes["md5"]), 32)
        self.assertEqual(len(hashes["sha256"]), 64)

    def test_dict_packet_dissector(self):
        """Test dictionary packet dissector formatting."""
        pkt = {
            "no": 1,
            "time": "12:00:00.000",
            "src": "192.168.1.5",
            "dst": "8.8.8.8",
            "protocol": "DNS",
            "length": 64,
            "info": "Standard Query A google.com",
            "raw_bytes": b"DNS_QUERY_DATA"
        }

        dissected = PacketDissector.dissect_dict_packet(pkt)
        self.assertIn("hex_dump", dissected)
        self.assertIn("ascii_str", dissected)
        self.assertEqual(dissected["payload_md5"], calculate_payload_hash(b"DNS_QUERY_DATA")["md5"])

    def test_config_env_storage(self):
        """Test that Config saves API keys to .env and non-secrets to config.json."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_config = Path(tmp_dir) / "config.json"
            tmp_env = Path(tmp_dir) / ".env"

            cfg = Config(config_file=tmp_config, env_file=tmp_env)
            cfg.abuseipdb_api_key = "test_abuse_key_123"
            cfg.virustotal_api_key = "test_vt_key_456"
            cfg.default_interface = "wlan0"
            cfg.save()

            # Verify .env contents
            with open(tmp_env, "r") as f:
                env_text = f.read()
            self.assertIn("ABUSEIPDB_API_KEY=test_abuse_key_123", env_text)
            self.assertIn("VIRUSTOTAL_API_KEY=test_vt_key_456", env_text)

            # Verify config.json does NOT contain API keys
            with open(tmp_config, "r") as f:
                json_text = f.read()
            self.assertNotIn("abuseipdb_api_key", json_text)
            self.assertNotIn("virustotal_api_key", json_text)
            self.assertIn('"default_interface": "wlan0"', json_text)

            # Load back up in new Config instance
            cfg2 = Config(config_file=tmp_config, env_file=tmp_env)
            self.assertEqual(cfg2.abuseipdb_api_key, "test_abuse_key_123")
            self.assertEqual(cfg2.virustotal_api_key, "test_vt_key_456")
            self.assertEqual(cfg2.default_interface, "wlan0")


if __name__ == "__main__":
    unittest.main()
