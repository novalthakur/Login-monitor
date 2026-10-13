from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
import os

from app.alert_engine import AlertEngine
from app.report_generator import ReportGenerator
from app.utils import load_config


def create_app(config: dict = None):
    app = Flask(__name__)
    app.config["CONFIG"] = config or load_config()

    dashboard_config = app.config["CONFIG"].get("dashboard", {})
    app.config["AUTO_REFRESH"] = dashboard_config.get("auto_refresh_seconds", 10)
    app.config["PER_PAGE"] = dashboard_config.get("alerts_per_page", 50)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

    @app.route("/")
    def index():
        engine = AlertEngine(config=app.config["CONFIG"])
        stats = engine.get_stats()
        engine.close()

        recent_alerts = engine.get_alerts(limit=10)
        engine.close()

        return render_template(
            "index.html",
            stats=stats,
            recent_alerts=recent_alerts,
            auto_refresh=app.config["AUTO_REFRESH"],
        )

    @app.route("/alerts")
    def alerts():
        page = request.args.get("page", 1, type=int)
        severity = request.args.get("severity", "")
        ip = request.args.get("ip", "")
        username = request.args.get("username", "")
        acknowledged = request.args.get("acknowledged", "")

        start_date = request.args.get("start_date", "")
        end_date = request.args.get("end_date", "")

        engine = AlertEngine(config=app.config["CONFIG"])

        filters = {}
        if severity:
            filters["severity"] = severity
        if ip:
            filters["ip"] = ip
        if username:
            filters["username"] = username
        if acknowledged:
            filters["acknowledged"] = acknowledged == "true"
        if start_date:
            filters["start_date"] = datetime.fromisoformat(start_date)
        if end_date:
            filters["end_date"] = datetime.fromisoformat(end_date) + timedelta(days=1)

        per_page = app.config["PER_PAGE"]
        offset = (page - 1) * per_page

        alerts_list = engine.get_alerts(limit=per_page, offset=offset, **filters)
        total = len(engine.get_alerts(limit=10000, **filters))
        engine.close()

        total_pages = (total + per_page - 1) // per_page

        return render_template(
            "alerts.html",
            alerts=alerts_list,
            page=page,
            total_pages=total_pages,
            total=total,
            filters=request.args,
            severities=["Critical", "High", "Medium", "Low"],
        )

    @app.route("/alerts/<int:alert_id>")
    def alert_detail(alert_id):
        engine = AlertEngine(config=app.config["CONFIG"])
        alerts_list = engine.get_alerts(limit=1, offset=0)
        engine.close()

        alert = next((a for a in alerts_list if a.id == alert_id), None)
        if not alert:
            return "Alert not found", 404

        return render_template("alert_detail.html", alert=alert)

    @app.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
    def acknowledge_alert(alert_id):
        engine = AlertEngine(config=app.config["CONFIG"])
        success = engine.acknowledge_alert(alert_id)
        engine.close()
        return jsonify({"success": success})

    @app.route("/export")
    def export():
        severity = request.args.get("severity", "")
        ip = request.args.get("ip", "")
        username = request.args.get("username", "")
        start_date = request.args.get("start_date", "")
        end_date = request.args.get("end_date", "")

        generator = ReportGenerator(config=app.config["CONFIG"])

        filters = {}
        if severity:
            filters["severity"] = severity
        if ip:
            filters["ip"] = ip
        if username:
            filters["username"] = username
        if start_date:
            filters["start_date"] = datetime.fromisoformat(start_date)
        if end_date:
            filters["end_date"] = datetime.fromisoformat(end_date) + timedelta(days=1)

        filepath, count = generator.generate_report(**filters)

        return send_file(
            filepath,
            mimetype="text/csv",
            as_attachment=True,
            download_name=os.path.basename(filepath),
        )

    @app.route("/api/stats")
    def api_stats():
        engine = AlertEngine(config=app.config["CONFIG"])
        stats = engine.get_stats()
        engine.close()
        return jsonify(stats)

    @app.route("/api/alerts")
    def api_alerts():
        page = request.args.get("page", 1, type=int)
        severity = request.args.get("severity", "")
        ip = request.args.get("ip", "")

        engine = AlertEngine(config=app.config["CONFIG"])
        alerts_list = engine.get_alerts(
            severity=severity if severity else None,
            ip=ip if ip else None,
            limit=app.config["PER_PAGE"],
            offset=(page - 1) * app.config["PER_PAGE"],
        )
        engine.close()

        return jsonify(
            {
                "alerts": [a.to_dict() for a in alerts_list],
                "page": page,
                "per_page": app.config["PER_PAGE"],
            }
        )

    return app


if __name__ == "__main__":
    config = load_config()
    dashboard_config = config.get("dashboard", {})
    app = create_app(config)
    app.run(
        host=dashboard_config.get("host", "0.0.0.0"),
        port=dashboard_config.get("port", 5000),
        debug=True,
    )