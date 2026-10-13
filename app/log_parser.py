import re
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from app.models import LogEntry
from app.utils import parse_timestamp, normalize_ip, sanitize_username, load_config


def parse_linux_auth(log_path: str, config: dict = None) -> List[LogEntry]:
    if config is None:
        config = load_config()
    patterns = config.get("log_parser", {}).get("linux_patterns", {})

    failed_pattern = patterns.get(
        "failed_ssh", r"Failed password for (\S+) from (\S+) port"
    )
    success_pattern = patterns.get(
        "success_ssh", r"Accepted password for (\S+) from (\S+) port"
    )

    entries = []
    current_year = datetime.now().year

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            timestamp = None
            ip = None
            username = None
            status = None

            match = re.search(failed_pattern, line)
            if match:
                username = sanitize_username(match.group(1))
                ip = normalize_ip(match.group(2))
                status = "failed"
            else:
                match = re.search(success_pattern, line)
                if match:
                    username = sanitize_username(match.group(1))
                    ip = normalize_ip(match.group(2))
                    status = "success"

            if ip and username and status:
                ts_match = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                if ts_match:
                    ts_str = ts_match.group(1)
                    timestamp = parse_timestamp(ts_str, "linux")
                    if timestamp:
                        timestamp = timestamp.replace(year=current_year)

            if timestamp and ip and username and status:
                entries.append(
                    LogEntry(
                        timestamp=timestamp,
                        ip=ip,
                        username=username,
                        status=status,
                        source="linux",
                        raw_line=line[:500],
                    )
                )

    return entries


def parse_windows_csv(log_path: str, config: dict = None) -> List[LogEntry]:
    if config is None:
        config = load_config()
    cols = config.get("log_parser", {}).get("windows_columns", {})

    ts_col = cols.get("timestamp", "TimeCreated")
    event_col = cols.get("event_id", "EventID")
    ip_col = cols.get("ip", "IpAddress")
    user_col = cols.get("username", "TargetUserName")

    entries = []

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                event_id = int(row.get(event_col, 0))
            except (ValueError, TypeError):
                continue

            if event_id not in (4624, 4625):
                continue

            ip = normalize_ip(row.get(ip_col, ""))
            username = sanitize_username(row.get(user_col, ""))
            ts_str = row.get(ts_col, "")

            timestamp = parse_timestamp(ts_str, "windows")
            if not timestamp or not ip or not username:
                continue

            status = "success" if event_id == 4624 else "failed"

            entries.append(
                LogEntry(
                    timestamp=timestamp,
                    ip=ip,
                    username=username,
                    status=status,
                    source="windows",
                    raw_line=str(row)[:500],
                )
            )

    return entries


def parse_log_file(log_path: str, format: str = "auto", config: dict = None) -> List[LogEntry]:
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    if format == "auto":
        suffix = path.suffix.lower()
        if suffix == ".csv":
            format = "windows"
        else:
            format = "linux"

    if format == "linux":
        return parse_linux_auth(log_path, config)
    elif format == "windows":
        return parse_windows_csv(log_path, config)
    else:
        raise ValueError(f"Unknown format: {format}. Use 'linux' or 'windows'")