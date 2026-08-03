import json
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.json"
CACHE_DB_PATH = BASE_DIR / "threatcache.db"


class Config:
    def __init__(self, config_file: Path = CONFIG_PATH):
        self.config_file = config_file
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.cache_ttl_hours = int(os.getenv("CACHE_TTL_HOURS", 24))
        self.max_requests_per_minute = int(os.getenv("MAX_REQUESTS_PER_MINUTE", 30))
        self.tshark_path = os.getenv("TSHARK_PATH", "")
        self.default_interface = os.getenv("DEFAULT_INTERFACE", "auto")
        self.mock_mode = os.getenv("MOCK_MODE", "false").lower() in ("true", "1", "yes")
        self.auto_scroll = True

        self.load()

    def load(self):
        """Load settings from config.json if present."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.abuseipdb_api_key = data.get("abuseipdb_api_key", self.abuseipdb_api_key)
                    self.virustotal_api_key = data.get("virustotal_api_key", self.virustotal_api_key)
                    self.cache_ttl_hours = data.get("cache_ttl_hours", self.cache_ttl_hours)
                    self.max_requests_per_minute = data.get(
                        "max_requests_per_minute", self.max_requests_per_minute
                    )
                    self.tshark_path = data.get("tshark_path", self.tshark_path)
                    self.default_interface = data.get("default_interface", self.default_interface)
                    self.mock_mode = data.get("mock_mode", self.mock_mode)
                    self.auto_scroll = data.get("auto_scroll", self.auto_scroll)
            except Exception as e:
                print(f"[Config] Warning: Failed to parse {self.config_file}: {e}")

    def save(self):
        """Save settings to config.json."""
        data = {
            "abuseipdb_api_key": self.abuseipdb_api_key,
            "virustotal_api_key": self.virustotal_api_key,
            "cache_ttl_hours": self.cache_ttl_hours,
            "max_requests_per_minute": self.max_requests_per_minute,
            "tshark_path": self.tshark_path,
            "default_interface": self.default_interface,
            "mock_mode": self.mock_mode,
            "auto_scroll": self.auto_scroll,
        }
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Config] Error saving configuration: {e}")

    def find_tshark(self) -> str | None:
        """Find executable path for tshark on host."""
        if self.tshark_path and os.path.isfile(self.tshark_path):
            return self.tshark_path
        
        # Check system PATH
        path = shutil.which("tshark")
        if path:
            return path
        
        # Common macOS & Linux fallback locations
        candidates = [
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
            "/usr/bin/tshark",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    @property
    def is_tshark_available(self) -> bool:
        return self.find_tshark() is not None


# Global config singleton
config = Config()
