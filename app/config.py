import json
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.json"
ENV_PATH = BASE_DIR / ".env"


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
        self.ipinfo_api_key = ""
        self.cache_ttl_hours = 24
        self.max_requests_per_minute = 30
        self.tshark_path = ""
        self.default_interface = "auto"
        self.mock_mode = False
        self.auto_scroll = True

        self.load()

    def load(self):
        """
        Load settings:
        - API Keys & Local Machine Settings (DEFAULT_INTERFACE, MOCK_MODE, TSHARK_PATH) from .env / env vars.
        - Shared App Defaults from config.json.
        """
        # 1. Read .env file & Environment Variables
        env_vars = parse_env_file(self.env_file)

        # 2. Read config.json defaults
        json_data = {}
        needs_sanitization = False
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    json_data = json.load(f)

                    # Check for legacy API keys in config.json and migrate to .env
                    legacy_abuse = json_data.get("abuseipdb_api_key")
                    legacy_vt = json_data.get("virustotal_api_key")
                    legacy_ipinfo = json_data.get("ipinfo_api_key")
                    if legacy_abuse or legacy_vt or legacy_ipinfo:
                        needs_sanitization = True
                        if legacy_abuse and not self.abuseipdb_api_key:
                            self.abuseipdb_api_key = legacy_abuse
                        if legacy_vt and not self.virustotal_api_key:
                            self.virustotal_api_key = legacy_vt
                        if legacy_ipinfo and not self.ipinfo_api_key:
                            self.ipinfo_api_key = legacy_ipinfo
            except Exception as e:
                print(f"[Config] Warning: Failed to parse {self.config_file}: {e}")

        # API Keys (prefer env vars / .env file)
        self.abuseipdb_api_key = (
            os.getenv("ABUSEIPDB_API_KEY")
            or env_vars.get("ABUSEIPDB_API_KEY")
            or self.abuseipdb_api_key
        )
        self.virustotal_api_key = (
            os.getenv("VIRUSTOTAL_API_KEY")
            or env_vars.get("VIRUSTOTAL_API_KEY")
            or self.virustotal_api_key
        )
        self.ipinfo_api_key = (
            os.getenv("IPINFO_API_KEY")
            or env_vars.get("IPINFO_API_KEY")
            or self.ipinfo_api_key
        )

        # Local Machine Settings (stored exclusively in .env so config.json remains un-mutated in git)
        self.default_interface = (
            os.getenv("DEFAULT_INTERFACE")
            or env_vars.get("DEFAULT_INTERFACE")
            or json_data.get("default_interface", "auto")
        )

        mock_env = os.getenv("MOCK_MODE") or env_vars.get("MOCK_MODE")
        if mock_env is not None:
            self.mock_mode = str(mock_env).lower() in ("true", "1", "yes")
        else:
            self.mock_mode = json_data.get("mock_mode", False)

        auto_scroll_env = os.getenv("AUTO_SCROLL") or env_vars.get("AUTO_SCROLL")
        if auto_scroll_env is not None:
            self.auto_scroll = str(auto_scroll_env).lower() in ("true", "1", "yes")
        else:
            self.auto_scroll = json_data.get("auto_scroll", True)

        self.tshark_path = (
            os.getenv("TSHARK_PATH")
            or env_vars.get("TSHARK_PATH")
            or json_data.get("tshark_path", "")
        )

        ttl_env = os.getenv("CACHE_TTL_HOURS") or env_vars.get("CACHE_TTL_HOURS")
        if ttl_env is not None:
            try:
                self.cache_ttl_hours = int(ttl_env)
            except ValueError:
                self.cache_ttl_hours = json_data.get("cache_ttl_hours", 24)
        else:
            self.cache_ttl_hours = json_data.get("cache_ttl_hours", 24)

        rate_env = os.getenv("MAX_REQUESTS_PER_MINUTE") or env_vars.get("MAX_REQUESTS_PER_MINUTE")
        if rate_env is not None:
            try:
                self.max_requests_per_minute = int(rate_env)
            except ValueError:
                self.max_requests_per_minute = json_data.get("max_requests_per_minute", 30)
        else:
            self.max_requests_per_minute = json_data.get("max_requests_per_minute", 30)

        # If legacy keys were found in config.json, save to .env
        if needs_sanitization:
            print("[Config] Migrating legacy API keys to .env for security...")
            self.save()

    def save(self):
        """Save ALL local machine configuration & secrets exclusively to .env so git status remains 100% clean."""
        save_env_file(
            self.env_file,
            {
                "ABUSEIPDB_API_KEY": self.abuseipdb_api_key,
                "VIRUSTOTAL_API_KEY": self.virustotal_api_key,
                "IPINFO_API_KEY": self.ipinfo_api_key,
                "DEFAULT_INTERFACE": self.default_interface,
                "MOCK_MODE": "true" if self.mock_mode else "false",
                "AUTO_SCROLL": "true" if self.auto_scroll else "false",
                "CACHE_TTL_HOURS": str(self.cache_ttl_hours),
                "MAX_REQUESTS_PER_MINUTE": str(self.max_requests_per_minute),
                "TSHARK_PATH": self.tshark_path,
            },
        )
        os.environ["ABUSEIPDB_API_KEY"] = self.abuseipdb_api_key
        os.environ["VIRUSTOTAL_API_KEY"] = self.virustotal_api_key
        os.environ["IPINFO_API_KEY"] = self.ipinfo_api_key
        os.environ["DEFAULT_INTERFACE"] = self.default_interface
        os.environ["MOCK_MODE"] = "true" if self.mock_mode else "false"
        os.environ["AUTO_SCROLL"] = "true" if self.auto_scroll else "false"
        os.environ["CACHE_TTL_HOURS"] = str(self.cache_ttl_hours)
        os.environ["MAX_REQUESTS_PER_MINUTE"] = str(self.max_requests_per_minute)
        os.environ["TSHARK_PATH"] = self.tshark_path

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

