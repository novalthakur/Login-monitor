from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import pandas as pd

from app.alert_engine import AlertEngine
from app.utils import load_config


class ReportGenerator:
    def __init__(self, config: dict = None):
        self.config = config or load_config()
        self.reports_dir = Path(
            self.config.get("reports", {}).get("directory", "reports")
        )
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.engine = AlertEngine(config=self.config)

    def generate_report(
        self,
        severity: str = None,
        ip: str = None,
        username: str = None,
        start_date: datetime = None,
        end_date: datetime = None,
        filename: str = None,
    ) -> str:
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"alerts_{timestamp}.csv"

        output_path = self.reports_dir / filename

        filters = {}
        if severity:
            filters["severity"] = severity
        if ip:
            filters["ip"] = ip
        if username:
            filters["username"] = username
        if start_date:
            filters["start_date"] = start_date
        if end_date:
            filters["end_date"] = end_date

        count = self.engine.export_alerts_csv(str(output_path), filters)
        self.engine.close()

        return str(output_path), count

    def generate_summary_report(self, filename: str = None) -> str:
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"summary_{timestamp}.csv"

        output_path = self.reports_dir / filename

        stats = self.engine.get_stats()
        self.engine.close()

        summary_data = {
            "Metric": [
                "Total Alerts",
                "Critical Alerts",
                "High Alerts",
                "Medium Alerts",
                "Low Alerts",
            ],
            "Count": [
                stats["total_alerts"],
                stats["by_severity"].get("Critical", 0),
                stats["by_severity"].get("High", 0),
                stats["by_severity"].get("Medium", 0),
                stats["by_severity"].get("Low", 0),
            ],
        }

        df = pd.DataFrame(summary_data)
        df.to_csv(output_path, index=False)

        return str(output_path)

    def list_reports(self) -> list:
        reports = []
        for f in sorted(self.reports_dir.glob("*.csv"), reverse=True):
            stat = f.stat()
            reports.append(
                {
                    "filename": f.name,
                    "path": str(f),
                    "size_bytes": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                }
            )
        return reports