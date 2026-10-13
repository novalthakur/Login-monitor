from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import sqlite3

from app.models import LogEntry, Alert, init_db
from app.utils import load_config, get_severity


class AlertEngine:
    def __init__(self, db_path: str = None, config: dict = None):
        self.config = config or load_config()
        self.db_path = db_path or self.config.get("database", {}).get("path", "data/alerts.db")
        self.conn = init_db(self.db_path)
        self.time_window = timedelta(
            minutes=self.config.get("time_window_minutes", 15)
        )
        self.thresholds = self.config.get("thresholds", {})

    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        ip_groups = self._group_by_ip(entries)
        new_alerts = []

        for ip, ip_entries in ip_groups.items():
            alerts = self._analyze_ip(ip, ip_entries)
            new_alerts.extend(alerts)

        return new_alerts

    def _group_by_ip(self, entries: List[LogEntry]) -> Dict[str, List[LogEntry]]:
        groups = defaultdict(list)
        for entry in entries:
            groups[entry.ip].append(entry)
        return groups

    def _analyze_ip(self, ip: str, entries: List[LogEntry]) -> List[Alert]:
        failed_entries = [e for e in entries if e.status == "failed"]
        success_entries = [e for e in entries if e.status == "success"]

        if not failed_entries:
            return []

        failed_entries.sort(key=lambda e: e.timestamp)
        alerts = []

        window_start = 0
        for i in range(len(failed_entries)):
            while (
                failed_entries[i].timestamp - failed_entries[window_start].timestamp
            ) > self.time_window:
                window_start += 1

            window_entries = failed_entries[window_start : i + 1]
            attempt_count = len(window_entries)

            if attempt_count >= self.thresholds.get("low", 3):
                usernames = list(set(e.username for e in window_entries))
                first_seen = window_entries[0].timestamp
                last_seen = window_entries[-1].timestamp
                severity = get_severity(attempt_count, self.thresholds)

                has_success = any(
                    s.timestamp >= first_seen
                    and s.timestamp <= last_seen + timedelta(minutes=5)
                    for s in success_entries
                )

                if has_success and severity != "Critical":
                    severity = "Critical"

                details = self._build_details(
                    window_entries, usernames, has_success, ip
                )

                existing = self._find_existing_alert(ip, first_seen, last_seen)
                if existing:
                    existing.attempt_count = attempt_count
                    existing.last_seen = last_seen
                    existing.severity = severity
                    existing.details = details
                    self._update_alert(existing)
                    alerts.append(existing)
                else:
                    alert = Alert(
                        first_seen=first_seen,
                        last_seen=last_seen,
                        ip=ip,
                        username=", ".join(usernames),
                        severity=severity,
                        attempt_count=attempt_count,
                        details=details,
                        source=entries[0].source if entries else "linux",
                    )
                    self._save_alert(alert)
                    alerts.append(alert)

        return alerts

    def _build_details(
        self, entries: List[LogEntry], usernames: List[str], has_success: bool, ip: str
    ) -> str:
        lines = [
            f"IP: {ip}",
            f"Usernames tried: {', '.join(usernames)}",
            f"Failed attempts: {len(entries)}",
            f"Time range: {entries[0].timestamp} to {entries[-1].timestamp}",
        ]
        if has_success:
            lines.append("⚠ SUCCESSFUL LOGIN DETECTED AFTER FAILURES")
        return " | ".join(lines)

    def _find_existing_alert(
        self, ip: str, first_seen: datetime, last_seen: datetime
    ) -> Alert:
        cursor = self.conn.execute(
            """
            SELECT * FROM alerts
            WHERE ip = ? AND first_seen <= ? AND last_seen >= ?
            ORDER BY last_seen DESC LIMIT 1
            """,
            (ip, last_seen.isoformat(), first_seen.isoformat()),
        )
        row = cursor.fetchone()
        if row:
            return Alert.from_row(row)
        return None

    def _save_alert(self, alert: Alert) -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO alerts (first_seen, last_seen, ip, username, severity, attempt_count, details, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.first_seen.isoformat(),
                alert.last_seen.isoformat(),
                alert.ip,
                alert.username,
                alert.severity,
                alert.attempt_count,
                alert.details,
                alert.source,
            ),
        )
        self.conn.commit()
        alert.id = cursor.lastrowid
        return alert.id

    def _update_alert(self, alert: Alert):
        self.conn.execute(
            """
            UPDATE alerts SET last_seen=?, severity=?, attempt_count=?, details=?
            WHERE id=?
            """,
            (
                alert.last_seen.isoformat(),
                alert.severity,
                alert.attempt_count,
                alert.details,
                alert.id,
            ),
        )
        self.conn.commit()

    def get_alerts(
        self,
        severity: str = None,
        ip: str = None,
        username: str = None,
        start_date: datetime = None,
        end_date: datetime = None,
        limit: int = 100,
        offset: int = 0,
        acknowledged: bool = None,
    ) -> List[Alert]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if ip:
            query += " AND ip LIKE ?"
            params.append(f"%{ip}%")
        if username:
            query += " AND username LIKE ?"
            params.append(f"%{username}%")
        if start_date:
            query += " AND first_seen >= ?"
            params.append(start_date.isoformat())
        if end_date:
            query += " AND first_seen <= ?"
            params.append(end_date.isoformat())
        if acknowledged is not None:
            query += " AND acknowledged = ?"
            params.append(int(acknowledged))

        query += " ORDER BY first_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = self.conn.execute(query, params)
        return [Alert.from_row(row) for row in cursor.fetchall()]

    def get_stats(self) -> dict:
        cursor = self.conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
        )
        severity_counts = {row["severity"]: row["count"] for row in cursor.fetchall()}

        cursor = self.conn.execute(
            "SELECT COUNT(*) as total FROM alerts"
        )
        total = cursor.fetchone()["total"]

        cursor = self.conn.execute(
            "SELECT ip, COUNT(*) as count FROM alerts GROUP BY ip ORDER BY count DESC LIMIT 10"
        )
        top_ips = [{"ip": row["ip"], "count": row["count"]} for row in cursor.fetchall()]

        return {
            "total_alerts": total,
            "by_severity": severity_counts,
            "top_attacking_ips": top_ips,
        }

    def acknowledge_alert(self, alert_id: int) -> bool:
        cursor = self.conn.execute(
            "UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def export_alerts_csv(self, output_path: str, filters: dict = None):
        import pandas as pd

        alerts = self.get_alerts(
            severity=filters.get("severity") if filters else None,
            ip=filters.get("ip") if filters else None,
            username=filters.get("username") if filters else None,
            start_date=filters.get("start_date") if filters else None,
            end_date=filters.get("end_date") if filters else None,
            limit=10000,
        )

        data = [a.to_dict() for a in alerts]
        df = pd.DataFrame(data)
        df.to_csv(output_path, index=False)
        return len(data)

    def close(self):
        self.conn.close()