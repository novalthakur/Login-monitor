from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import sqlite3
from pathlib import Path


@dataclass
class LogEntry:
    timestamp: datetime
    ip: str
    username: str
    status: str  # 'failed' or 'success'
    source: str  # 'linux' or 'windows'
    raw_line: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "ip": self.ip,
            "username": self.username,
            "status": self.status,
            "source": self.source,
            "raw_line": self.raw_line,
        }


@dataclass
class Alert:
    id: Optional[int] = None
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    ip: str = ""
    username: str = ""
    severity: str = "Low"  # Low, Medium, High, Critical
    attempt_count: int = 0
    details: str = ""
    source: str = "linux"
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "ip": self.ip,
            "username": self.username,
            "severity": self.severity,
            "attempt_count": self.attempt_count,
            "details": self.details,
            "source": self.source,
            "acknowledged": self.acknowledged,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Alert":
        return cls(
            id=row["id"],
            first_seen=datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            ip=row["ip"],
            username=row["username"],
            severity=row["severity"],
            attempt_count=row["attempt_count"],
            details=row["details"],
            source=row["source"],
            acknowledged=bool(row["acknowledged"]),
        )


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ip TEXT NOT NULL,
    username TEXT NOT NULL,
    severity TEXT NOT NULL,
    attempt_count INTEGER NOT NULL,
    details TEXT,
    source TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_first_seen ON alerts(first_seen);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn