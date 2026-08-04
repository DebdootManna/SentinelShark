import json
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.json"
ENV_PATH = BASE_DIR / ".env"
CACHE_DB_PATH = BASE_DIR / "threatcache.db"


def parse_env_file(env_path: Path) -> dict:
    """Parse key=value pairs from a .env file."""
    env_vars = {}
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    env_vars[key.strip()] = val.strip().strip("'\"")
        except Exception as e:
            print(f"[Config] Warning: Failed to parse {env_path}: {e}")
    return env_vars


def save_env_file(env_path: Path, updates: dict):
    """Update or append key=value pairs in a .env file."""
    existing_lines = []
    keys_written = set()
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                existing_lines = f.readlines()
        except Exception:
            existing_lines = []

    new_lines = []
    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}\n")
                keys_written.add(key)
                continue
        new_lines.append(line)

    for key, val in updates.items():
        if key not in keys_written:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append(f"{key}={val}\n")
            keys_written.add(key)

    try:
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except Exception as e:
        print(f"[Config] Error saving .env file: {e}")


class Config:
    def __init__(self, config_file: Path = CONFIG_PATH, env_file: Path = ENV_PATH):
        self.config_file = config_file
        self.env_file = env_file
        self.abuseipdb_api_key = ""
        self.virustotal_api_key = ""
        self.cache_ttl_hours = 24
        self.max_requests_per_minute = 30
        self.tshark_path = ""
        self.default_interface = "auto"
        self.mock_mode = False
        self.auto_scroll = True

        self.load()

    def load(self):
        """Load settings from .env (API keys) and config.json (app settings)."""
        # 1. Read .env file & Environment Variables
        env_vars = parse_env_file(self.env_file)
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY") or env_vars.get("ABUSEIPDB_API_KEY", "")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY") or env_vars.get("VIRUSTOTAL_API_KEY", "")

        # 2. Read config.json
        needs_sanitization = False
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    # Check for legacy API keys in config.json and migrate to .env
                    legacy_abuse = data.get("abuseipdb_api_key")
                    legacy_vt = data.get("virustotal_api_key")
                    if legacy_abuse or legacy_vt:
                        needs_sanitization = True
                        if legacy_abuse and not self.abuseipdb_api_key:
                            self.abuseipdb_api_key = legacy_abuse
                        if legacy_vt and not self.virustotal_api_key:
                            self.virustotal_api_key = legacy_vt

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

        # If legacy keys were found in config.json, save to .env and sanitize config.json
        if needs_sanitization:
            print("[Config] Migrating legacy API keys from config.json to .env for security...")
            self.save()

    def save(self):
        """Save secret API keys to .env and non-sensitive app settings to config.json."""
        # Save secrets to .env
        save_env_file(
            self.env_file,
            {
                "ABUSEIPDB_API_KEY": self.abuseipdb_api_key,
                "VIRUSTOTAL_API_KEY": self.virustotal_api_key,
            },
        )
        os.environ["ABUSEIPDB_API_KEY"] = self.abuseipdb_api_key
        os.environ["VIRUSTOTAL_API_KEY"] = self.virustotal_api_key

        # Save non-sensitive data to config.json (WITHOUT API keys)
        data = {
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

