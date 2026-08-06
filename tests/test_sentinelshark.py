import json
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

    def test_in_memory_threat_cache(self):
        """Test pure in-memory TTL threat cache manager."""
        # Create cache with 1-hour TTL
        cache = ThreatCache(ttl_hours=1)
        
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
            "domain": "dns.google",
            "ipinfo_details": {
                "ip": "8.8.8.8",
                "hostname": "dns.google",
                "anycast": True,
                "city": "Mountain View",
                "region": "California",
                "country": "US",
                "loc": "37.4056,-122.0775",
                "org": "AS15169 Google LLC",
                "postal": "94043",
                "timezone": "America/Los_Angeles",
                "privacy": {"vpn": False, "proxy": False, "tor": False}
            }
        }
        cache.set("8.8.8.8", threat_data)

        # Retrieve from cache
        cached = cache.get("8.8.8.8")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["abuse_score"], 15)
        self.assertEqual(cached["vt_malicious"], 2)
        self.assertEqual(cached["country"], "US")
        self.assertEqual(cached["ipinfo_city"], "Mountain View")
        self.assertEqual(cached["ipinfo_org"], "AS15169 Google LLC")
        self.assertTrue(cached["cached"])

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
        """Test that Config saves API keys and all local machine settings to .env exclusively."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_config = Path(tmp_dir) / "config.json"
            tmp_env = Path(tmp_dir) / ".env"

            # Create default config.json
            with open(tmp_config, "w") as f:
                json.dump({"default_interface": "auto", "cache_ttl_hours": 24}, f)

            cfg = Config(config_file=tmp_config, env_file=tmp_env)
            cfg.abuseipdb_api_key = "test_abuse_key_123"
            cfg.virustotal_api_key = "test_vt_key_456"
            cfg.ipinfo_api_key = "test_ipinfo_key_789"
            cfg.default_interface = "wlan0"
            cfg.mock_mode = True
            cfg.auto_scroll = False
            cfg.cache_ttl_hours = 48
            cfg.save()

            # Verify .env contents
            with open(tmp_env, "r") as f:
                env_text = f.read()
            self.assertIn("ABUSEIPDB_API_KEY=test_abuse_key_123", env_text)
            self.assertIn("VIRUSTOTAL_API_KEY=test_vt_key_456", env_text)
            self.assertIn("IPINFO_API_KEY=test_ipinfo_key_789", env_text)
            self.assertIn("DEFAULT_INTERFACE=wlan0", env_text)
            self.assertIn("MOCK_MODE=true", env_text)
            self.assertIn("AUTO_SCROLL=false", env_text)
            self.assertIn("CACHE_TTL_HOURS=48", env_text)

            # Load back up in new Config instance
            cfg2 = Config(config_file=tmp_config, env_file=tmp_env)
            self.assertEqual(cfg2.abuseipdb_api_key, "test_abuse_key_123")
            self.assertEqual(cfg2.virustotal_api_key, "test_vt_key_456")
            self.assertEqual(cfg2.ipinfo_api_key, "test_ipinfo_key_789")
            self.assertEqual(cfg2.default_interface, "wlan0")
            self.assertTrue(cfg2.mock_mode)
            self.assertFalse(cfg2.auto_scroll)
            self.assertEqual(cfg2.cache_ttl_hours, 48)

    def test_sparkline_widget(self):
        """Test SparklineWidget history buffer management."""
        from PyQt6.QtWidgets import QApplication
        from app.ui.components.sparkline import SparklineWidget

        app = QApplication.instance() or QApplication([])
        sparkline = SparklineWidget(max_points=5)
        for i in range(10):
            sparkline.add_value(float(i))

        self.assertEqual(len(sparkline.history), 5)
        self.assertEqual(list(sparkline.history), [5.0, 6.0, 7.0, 8.0, 9.0])

    def test_interface_mapper(self):
        """Test NetworkInterfaceMapper friendly label and IP resolution."""
        from app.core.interfacemapper import interface_mapper
        label_en0 = interface_mapper.get_friendly_label("en0")
        self.assertTrue("Wi-Fi" in label_en0 or "en0" in label_en0)

        loopback_name = interface_mapper.get_psutil_name("\\Device\\NPF_Loopback")
        self.assertIsNotNone(loopback_name)


    def test_cache_invalidation_when_key_added(self):
        """Test that cache automatically invalidates entries missing IPinfo data when IPinfo API key is set."""
        from app.config import config
        cache = ThreatCache(ttl_hours=24)
        old_data = {"abuse_score": 10, "vt_malicious": 0, "ipinfo_details": {}}
        cache.set("1.1.1.1", old_data)

        # Case A: IPinfo key NOT configured -> Cache returns record
        config.ipinfo_api_key = ""
        self.assertIsNotNone(cache.get("1.1.1.1"))

        # Case B: IPinfo key IS configured -> Incomplete cache returns None (forcing fresh API lookup)
        config.ipinfo_api_key = "test_key_active"
        self.assertIsNone(cache.get("1.1.1.1"))
        config.ipinfo_api_key = ""

    def test_pcap_writer_export(self):
        """Test native PCAP/PCAPNG file creation."""
        from app.core.pcapwriter import save_pcap_file
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as tmp:
            tmp_pcap = tmp.name

        try:
            sample_packets = [
                {
                    "no": 1,
                    "time": "12:34:56.789",
                    "src": "192.168.1.5",
                    "dst": "8.8.8.8",
                    "protocol": "DNS",
                    "length": 54,
                    "raw_bytes": bytes.fromhex("00112233445566778899aabb08004500003c")
                }
            ]
            success = save_pcap_file(tmp_pcap, sample_packets)
            self.assertTrue(success)
            self.assertTrue(os.path.exists(tmp_pcap))
            self.assertGreater(os.path.getsize(tmp_pcap), 24)
        finally:
            if os.path.exists(tmp_pcap):
                os.remove(tmp_pcap)


    def test_sanitize_bpf_filter(self):
        """Test BPF filter translation and IP host wrapper."""
        from app.core.capture import sanitize_bpf_filter
        self.assertEqual(sanitize_bpf_filter("http"), "tcp port 80 or tcp port 8080")
        self.assertEqual(sanitize_bpf_filter("dns"), "port 53")
        self.assertEqual(sanitize_bpf_filter("https"), "tcp port 443")
        self.assertEqual(sanitize_bpf_filter("8.8.8.8"), "host 8.8.8.8")
        self.assertEqual(sanitize_bpf_filter("tcp port 80"), "tcp port 80")

    def test_packet_table_filtering(self):
        """Test PacketTable search/filter matching logic."""
        from PyQt6.QtWidgets import QApplication
        from app.ui.components.packettable import PacketTable

        app = QApplication.instance() or QApplication([])
        table = PacketTable()
        table.add_packet({"no": 1, "src": "192.168.1.5", "dst": "8.8.8.8", "protocol": "DNS", "info": "Standard query A example.com"})
        table.add_packet({"no": 2, "src": "192.168.1.5", "dst": "142.250.190.46", "protocol": "HTTP", "info": "GET /index.html"})

        table.set_filter_query("dns")
        self.assertFalse(table.isRowHidden(0))
        self.assertTrue(table.isRowHidden(1))

        table.set_filter_query("142.250.190.46")
        self.assertTrue(table.isRowHidden(0))
        self.assertFalse(table.isRowHidden(1))

    def test_tshark_json_packet_dissector(self):
        """Test high-speed tshark JSON packet dissector."""
        pkt_json = {
            "_source": {
                "layers": {
                    "frame": {
                        "frame.time_epoch": "1722950000.123",
                        "frame.len": "128",
                        "frame.protocols": "eth:ip:tcp:http"
                    },
                    "eth": {
                        "eth.src": "00:11:22:33:44:55",
                        "eth.dst": "66:77:88:99:aa:bb",
                        "eth.type": "0x0800"
                    },
                    "ip": {
                        "ip.src": ["192.168.1.100"],
                        "ip.dst": ["8.8.8.8"],
                        "ip.proto": ["6"],
                        "ip.ttl": ["64"]
                    },
                    "tcp": {
                        "tcp.srcport": "54321",
                        "tcp.dstport": "80",
                        "tcp.flags": "0x0002"
                    },
                    "http": {
                        "http.request.method": "GET",
                        "http.request.uri": "/index.html"
                    },
                    "frame_raw": "4500003c"
                }
            }
        }
        dissected = PacketDissector.dissect_tshark_json_packet(pkt_json, 1)
        self.assertEqual(dissected["no"], 1)
        self.assertEqual(dissected["src"], "192.168.1.100")
        self.assertEqual(dissected["dst"], "8.8.8.8")
        self.assertEqual(dissected["src_port"], "54321")
        self.assertEqual(dissected["dst_port"], "80")
        self.assertEqual(dissected["protocol"], "HTTP")
        self.assertEqual(dissected["info"], "HTTP GET /index.html")
        self.assertEqual(len(dissected["layers_tree"]), 4)

    def test_packet_table_batching(self):
        """Test PacketTable batched insertion."""
        from PyQt6.QtWidgets import QApplication
        from app.ui.components.packettable import PacketTable

        app = QApplication.instance() or QApplication([])
        table = PacketTable()
        batch = [
            {"no": 1, "src": "10.0.0.1", "dst": "8.8.8.8", "protocol": "DNS", "info": "DNS Query"},
            {"no": 2, "src": "10.0.0.1", "dst": "1.1.1.1", "protocol": "HTTPS", "info": "TLS Client Hello"}
        ]
        table.add_packets_batch(batch)
        self.assertEqual(table.rowCount(), 2)
        self.assertEqual(table.item(0, 2).text(), "10.0.0.1")
        self.assertEqual(table.item(1, 3).text(), "1.1.1.1")


if __name__ == "__main__":
    unittest.main()

