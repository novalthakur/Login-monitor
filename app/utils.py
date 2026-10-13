import re
import ipaddress
from datetime import datetime
from typing import Optional
import yaml
from pathlib import Path


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def parse_timestamp(ts_str: str, source: str = "linux") -> Optional[datetime]:
    formats = {
        "linux": [
            "%b %d %H:%M:%S",
            "%b %d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ],
        "windows": [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S %p",
            "%Y-%m-%d %H:%M:%S.%f",
        ],
    }

    for fmt in formats.get(source, formats["linux"]):
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    return None


def load_config(config_path: str = "config.yaml") -> dict:
    path = Path(config_path)
    if not path.exists():
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def get_severity(attempt_count: int, thresholds: dict) -> str:
    if attempt_count >= thresholds.get("critical", 51):
        return "Critical"
    elif attempt_count >= thresholds.get("high", 16):
        return "High"
    elif attempt_count >= thresholds.get("medium", 6):
        return "Medium"
    else:
        return "Low"


def normalize_ip(ip: str) -> str:
    ip = ip.strip()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def sanitize_username(username: str) -> str:
    username = username.strip()
    username = re.sub(r"[^\w\-\.@]", "", username)
    return username[:64] if username else "unknown"