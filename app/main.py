#!/usr/bin/env python3
"""
SOC Login Monitor - Main Entry Point

Usage:
    python -m app --log-file logs/sample_auth.log --format linux
    python -m app --log-file logs/sample_security.csv --format windows
    python -m app --mode dashboard
"""
import argparse
import sys
from pathlib import Path

from app.log_parser import parse_log_file
from app.alert_engine import AlertEngine
from app.dashboard import create_app
from app.utils import load_config


def analyze_logs(args, config):
    print(f"[*] Loading config...")
    print(f"[*] Parsing log file: {args.log_file} (format: {args.format})")

    try:
        entries = parse_log_file(args.log_file, args.format, config)
        print(f"[+] Parsed {len(entries)} log entries")
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error parsing log: {e}")
        sys.exit(1)

    if not entries:
        print("[!] No valid log entries found")
        return

    print("[*] Analyzing for brute force patterns...")
    engine = AlertEngine(config=config)
    alerts = engine.analyze(entries)
    engine.close()

    if alerts:
        print(f"[+] Generated {len(alerts)} alert(s):")
        for alert in alerts:
            print(f"    [{alert.severity}] {alert.ip} - {alert.attempt_count} attempts - {alert.username}")
    else:
        print("[+] No alerts generated (no brute force patterns detected)")

    print("\n[*] Generating summary report...")
    from app.report_generator import ReportGenerator
    generator = ReportGenerator(config=config)
    report_path, count = generator.generate_report()
    print(f"[+] Report saved to: {report_path} ({count} alerts)")


def run_dashboard(args, config):
    print("[*] Starting web dashboard...")
    app = create_app(config)
    dashboard_config = config.get("dashboard", {})
    host = dashboard_config.get("host", "0.0.0.0")
    port = dashboard_config.get("port", 5000)
    print(f"[+] Dashboard available at http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(
        description="SOC Login Monitor - Detect brute force login attempts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze Linux auth.log
  python -m app --log-file logs/sample_auth.log --format linux

  # Analyze Windows Security Event Log CSV export
  python -m app --log-file logs/sample_security.csv --format windows

  # Run web dashboard
  python -m app --mode dashboard
        """
    )

    parser.add_argument(
        "--log-file",
        help="Path to log file to analyze"
    )
    parser.add_argument(
        "--format",
        choices=["linux", "windows", "auto"],
        default="auto",
        help="Log format (default: auto-detect from extension)"
    )
    parser.add_argument(
        "--mode",
        choices=["analyze", "dashboard"],
        default="analyze",
        help="Operation mode (default: analyze)"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml)"
    )

    args = parser.parse_args()

    config = load_config(args.config)

    if args.mode == "dashboard":
        run_dashboard(args, config)
    else:
        if not args.log_file:
            parser.error("--log-file is required in analyze mode")
        analyze_logs(args, config)


if __name__ == "__main__":
    main()