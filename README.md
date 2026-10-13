# Login Monitor

A beginner-friendly tool for monitoring login attempts, detecting brute force attacks, and generating security alerts with a web dashboard and CSV reports.

## Features

- **Multi-format log parsing**: Linux `auth.log` (SSH) and Windows Security Event Log CSV exports
- **Brute force detection**: Sliding window analysis with configurable thresholds
- **Severity classification**: Low / Medium / High / Critical alerts
- **Web dashboard**: Real-time alert viewing, filtering, and acknowledgment
- **CSV reports**: Export filtered alerts for compliance and analysis
- **Docker support**: Containerized deployment with Docker Compose
- **Sample data**: Built-in log generator for testing

## Quick Start

### Prerequisites
- Docker and Docker Compose installed

### 1. Clone and Build
```bash
git clone <repository>
cd login-monitor
docker-compose build
```

### 2. Generate Sample Logs
```bash
docker-compose --profile generate run --rm log-generator
```

### 3. Analyze Logs (One-time)
```bash
# Analyze Linux auth.log
docker-compose --profile analyze run --rm analyzer

# Analyze Windows CSV export
docker-compose --profile analyze run --rm analyzer \
  python -m app --log-file /app/logs/sample_security.csv --format windows
```

### 4. Start Dashboard (Persistent)
```bash
docker-compose up -d dashboard
```
Open http://localhost:5000 in your browser.

## Project Structure

```
login-monitor/
├── app/                    # Main application package
│   ├── main.py            # CLI entry point
│   ├── log_parser.py      # Log parsing (Linux + Windows CSV)
│   ├── alert_engine.py    # Brute force detection & alerting
│   ├── dashboard.py       # Flask web dashboard
│   ├── report_generator.py # CSV export
│   ├── models.py          # Data models & SQLite schema
│   └── utils.py           # Helpers
├── logs/                  # Input log files
│   ├── sample_auth.log    # Linux SSH logs
│   └── sample_security.csv # Windows Event Log CSV
├── data/                  # SQLite database (auto-created)
├── reports/               # Generated CSV reports
├── templates/             # Jinja2 HTML templates
├── static/                # CSS/JS assets
├── scripts/
│   └── generate_logs.py   # Sample data generator
├── config.yaml            # Configuration
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Log Format Support

### Linux auth.log (SSH)
Standard OpenSSH format:
```
Oct 13 10:15:22 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Oct 13 10:15:25 server sshd[1235]: Accepted password for admin from 192.168.1.10 port 22 ssh2
```

### Windows Security Event Log (CSV Export)
Export from Event Viewer → Security log → "Save All Events As" → CSV.
Required columns: `TimeCreated`, `EventID`, `IpAddress`, `TargetUserName`, `LogonType`

| EventID | Meaning |
|---------|---------|
| 4624 | Successful logon |
| 4625 | Failed logon |

## Configuration

Edit `config.yaml` to customize:

```yaml
thresholds:
  low: 3          # 3-5 attempts = Low
  medium: 6       # 6-15 attempts = Medium
  high: 16        # 16-50 attempts = High
  critical: 51    # 51+ attempts = Critical

time_window_minutes: 15  # Sliding window size

dashboard:
  host: "0.0.0.0"
  port: 5000
  auto_refresh_seconds: 10
  alerts_per_page: 50
```

## CLI Usage

```bash
# Analyze a log file
python -m app --log-file logs/sample_auth.log --format linux
python -m app --log-file logs/sample_security.csv --format windows

# Run dashboard
python -m app --mode dashboard

# With custom config
python -m app --config custom.yaml --log-file /path/to/log --format linux
```

## Dashboard Features

- **Summary cards**: Alert counts by severity
- **Charts**: Severity distribution (doughnut chart)
- **Top attackers**: Most active IPs
- **Recent alerts**: Latest 10 alerts on home page
- **All alerts page**: Paginated, filterable table
  - Filter by severity, IP, username, date range, acknowledgment status
  - One-click acknowledge
  - Export filtered results to CSV
- **Auto-refresh**: Updates every 10 seconds (configurable)

## CSV Reports

Reports saved to `reports/` directory:
- `alerts_YYYYMMDD_HHMMSS.csv` - Full alert export with filters
- `summary_YYYYMMDD_HHMMSS.csv` - Severity summary

Columns: `id`, `first_seen`, `last_seen`, `ip`, `username`, `severity`, `attempt_count`, `details`, `source`, `acknowledged`

## Detection Logic

The alert engine groups failed login attempts by IP address using a **sliding time window** (default 15 minutes).

| Severity | Failed Attempts in Window |
|----------|---------------------------|
| Low | 3-5 |
| Medium | 6-15 |
| High | 16-50 |
| Critical | 51+ OR successful login after failures |

Alerts are stored in SQLite (`data/alerts.db`) and persist across container restarts.

## Development (Without Docker)

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Generate sample logs
python scripts/generate_logs.py

# Analyze logs
python -m app --log-file logs/sample_auth.log --format linux

# Run dashboard
python -m app --mode dashboard
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Dashboard not accessible | Check `docker-compose logs dashboard` |
| No alerts generated | Verify log format matches parser; check thresholds in config.yaml |
| Database locked | Ensure only one analyzer runs at a time |
| CSV export empty | Check filters; verify alerts exist in database |
| Port 5000 in use | Change `dashboard.port` in config.yaml |

## License

MIT License - Feel free to use and modify for your SOC operations.