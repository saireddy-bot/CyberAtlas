import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from sqlalchemy.orm import Session

# Import our existing database models and core modules
from Backend.app.database import SessionLocal, Base, engine
from Backend.app import models
from Backend.app.asset_discovery import discover_asset
from Backend.app.security_assessment import assess_asset_security
from Backend.app.scanner import run_security_scan
from Backend.app.ai_assistant import ask_cybertwin_ai
from Backend.app.availability_monitor import check_host_reachability
from Backend.app.firewall import (
    get_firewall_status,
    get_firewall_rules,
    create_firewall_rule,
    toggle_firewall_rule,
    delete_firewall_rule,
    apply_defense_baseline,
    block_port_with_firewall
)
from Backend.app.alerts import (
    get_all_alerts,
    acknowledge_alert,
    get_department_alert_summary
)
from Backend.app.scan_history import (
    create_scan_record,
    get_scan_history,
    get_all_scan_history,
    get_scan,
    clear_all_scan_history
)
from Backend.app.auto_scanner import (
    start_automatic_scanner,
    stop_automatic_scanner,
    get_automatic_scanner_status,
    run_automatic_scan,
    set_scan_interval
)

# Initialize database schema
Base.metadata.create_all(bind=engine)

# Path to built React Frontend (if built)
FRONTEND_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Frontend", "dist"))

app = Flask(__name__, static_folder=os.path.join(FRONTEND_DIST, "assets"), static_url_path="/assets-static")
CORS(app, resources={r"/*": {"origins": "*"}})


def get_db():
    db = SessionLocal()
    try:
        return db
    finally:
        pass


# ============================================================
# 1. FRONTEND SINGLE PAGE APP (SPA) ROUTING
# ============================================================

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if os.path.exists(FRONTEND_DIST):
        # Serve static assets
        if path != "" and os.path.exists(os.path.join(FRONTEND_DIST, path)):
            return send_from_directory(FRONTEND_DIST, path)
        # Fallback to index.html for React router
        index_file = os.path.join(FRONTEND_DIST, "index.html")
        if os.path.exists(index_file):
            return send_from_directory(FRONTEND_DIST, "index.html")

    return jsonify({
        "status": "online",
        "service": "CyberTwin Flask Server",
        "message": "Flask Server is running. To serve the built UI, build Frontend with 'npm run build' or access API directly.",
        "api_docs_endpoints": [
            "/assets/",
            "/assets/findings/",
            "/assets/alerts/",
            "/assets/firewall/status",
            "/assets/scans/all",
            "/assets/automatic-scan/status"
        ]
    })


# ============================================================
# 2. HEALTH & SERVER STATUS
# ============================================================

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "server": "Flask",
        "timestamp": datetime.utcnow().isoformat()
    })


# ============================================================
# 3. ASSETS & SCANNING APIS
# ============================================================

@app.route("/assets/", methods=["GET"])
def list_assets():
    db = SessionLocal()
    try:
        assets = db.query(models.Asset).all()
        return jsonify([
            {
                "id": a.id,
                "name": a.name,
                "asset_type": a.asset_type,
                "ip_address": a.ip_address,
                "status": a.status,
                "criticality": a.criticality,
                "risk_level": a.risk_level
            }
            for a in assets
        ])
    finally:
        db.close()


@app.route("/assets/findings/", methods=["GET"])
def list_findings():
    db = SessionLocal()
    try:
        findings = db.query(models.SecurityFinding).all()
        return jsonify([
            {
                "id": f.id,
                "asset_id": f.asset_id,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "vulnerability_type": f.vulnerability_type,
                "affected_component": f.affected_component,
                "host": f.host,
                "port": f.port,
                "status": f.status,
                "remediation": f.remediation
            }
            for f in findings
        ])
    finally:
        db.close()


@app.route("/assets/scan-all-manual", methods=["POST"])
def scan_all_systems():
    db = SessionLocal()
    try:
        result = run_automatic_scan()
        return jsonify({
            "status": "completed",
            "scan_type": "manual_all",
            "total_systems_scanned": result.get("total_scanned", 0),
            "online_systems": result.get("online_count", 0),
            "offline_systems": result.get("offline_count", 0),
            "total_findings_detected": result.get("total_findings", 0)
        })
    finally:
        db.close()


@app.route("/assets/<int:asset_id>/scan-manual", methods=["POST"])
def scan_single_asset(asset_id):
    db = SessionLocal()
    try:
        asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
        if not asset:
            return jsonify({"error": "Asset not found"}), 404

        scan_result = run_security_scan(ip_address=asset.ip_address, asset_type=asset.asset_type, asset_name=asset.name)
        is_online = (asset.status or "").lower() == "online"

        create_scan_record(
            db=db,
            asset_id=asset.id,
            target=asset.ip_address,
            asset_type=asset.asset_type,
            total_findings=len(scan_result.get("findings", [])),
            risk_score=float(len(scan_result.get("findings", [])) * 2.5),
            status="completed",
            scan_type="manual_single",
            is_online=is_online,
            scan_summary=scan_result.get("findings", [])
        )

        return jsonify({
            "status": "completed",
            "asset_id": asset.id,
            "asset_name": asset.name,
            "target": asset.ip_address,
            "is_online": is_online,
            "total_findings": len(scan_result.get("findings", [])),
            "findings": scan_result.get("findings", [])
        })
    finally:
        db.close()


# ============================================================
# 4. AUTOMATED SCANNER CONTROLS
# ============================================================

@app.route("/assets/automatic-scan/start", methods=["POST"])
def start_auto_scan():
    data = request.get_json(silent=True) or {}
    interval_seconds = data.get("interval_seconds", 60)
    return jsonify(start_automatic_scanner(interval_seconds=interval_seconds))


@app.route("/assets/automatic-scan/stop", methods=["POST"])
def stop_auto_scan():
    return jsonify(stop_automatic_scanner())


@app.route("/assets/automatic-scan/status", methods=["GET"])
def auto_scan_status():
    return jsonify(get_automatic_scanner_status())


@app.route("/assets/automatic-scan/set-interval", methods=["POST"])
def set_auto_scan_interval():
    data = request.get_json(silent=True) or {}
    interval = data.get("interval_seconds", 60)
    return jsonify(set_scan_interval(interval_seconds=interval))


@app.route("/assets/automatic-scan/trigger", methods=["POST"])
def trigger_auto_scan_now():
    res = run_automatic_scan(scan_type="automatic")
    return jsonify({"status": "executed", "summary": res})


# ============================================================
# 5. SCAN HISTORY & CLEARING
# ============================================================

@app.route("/assets/scans/all", methods=["GET"])
def get_all_scans():
    db = SessionLocal()
    try:
        limit = int(request.args.get("limit", 100))
        return jsonify(get_all_scan_history(db=db, limit=limit))
    finally:
        db.close()


@app.route("/assets/scans/<int:scan_id>", methods=["GET"])
def get_single_scan_by_id(scan_id):
    db = SessionLocal()
    try:
        scan = get_scan(db=db, scan_id=scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(scan)
    finally:
        db.close()


@app.route("/assets/scans/clear", methods=["DELETE", "POST"])
def clear_scans():
    db = SessionLocal()
    try:
        return jsonify(clear_all_scan_history(db=db))
    finally:
        db.close()


# ============================================================
# 6. DEPARTMENT & MANAGER ALERTS
# ============================================================

@app.route("/assets/alerts/", methods=["GET"])
def get_alerts():
    db = SessionLocal()
    try:
        dept = request.args.get("department", "all")
        return jsonify(get_all_alerts(db=db, department=dept))
    finally:
        db.close()


@app.route("/assets/alerts/department-summary", methods=["GET"])
def get_alert_summary():
    db = SessionLocal()
    try:
        return jsonify(get_department_alert_summary(db=db))
    finally:
        db.close()


@app.route("/assets/alerts/<int:alert_id>/acknowledge", methods=["PUT", "POST"])
def ack_alert(alert_id):
    db = SessionLocal()
    try:
        res = acknowledge_alert(db=db, alert_id=alert_id)
        if not res:
            return jsonify({"error": "Alert not found"}), 404
        return jsonify(res)
    finally:
        db.close()


# ============================================================
# 7. FIREWALL MANAGEMENT
# ============================================================

@app.route("/assets/firewall/status", methods=["GET"])
def firewall_status():
    return jsonify(get_firewall_status())


@app.route("/assets/firewall/rules", methods=["GET"])
def list_firewall_rules():
    db = SessionLocal()
    try:
        return jsonify(get_firewall_rules(db=db))
    finally:
        db.close()


@app.route("/assets/firewall/rules", methods=["POST"])
def add_firewall_rule():
    db = SessionLocal()
    try:
        data = request.get_json(force=True)
        return jsonify(create_firewall_rule(db=db, rule_data=data))
    finally:
        db.close()


@app.route("/assets/firewall/rules/<int:rule_id>/toggle", methods=["PUT", "POST"])
def toggle_rule(rule_id):
    db = SessionLocal()
    try:
        res = toggle_firewall_rule(db=db, rule_id=rule_id)
        if not res:
            return jsonify({"error": "Rule not found"}), 404
        return jsonify(res)
    finally:
        db.close()


@app.route("/assets/firewall/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    db = SessionLocal()
    try:
        success = delete_firewall_rule(db=db, rule_id=rule_id)
        if not success:
            return jsonify({"error": "Rule not found"}), 404
        return jsonify({"status": "deleted", "message": f"Firewall rule #{rule_id} removed."})
    finally:
        db.close()


@app.route("/assets/firewall/apply-baseline", methods=["POST"])
def apply_baseline():
    db = SessionLocal()
    try:
        return jsonify(apply_defense_baseline(db=db))
    finally:
        db.close()


@app.route("/assets/firewall/block-port", methods=["POST"])
def block_port():
    db = SessionLocal()
    try:
        data = request.get_json(force=True)
        port = data.get("port")
        service = data.get("service_name", "Exposed Service")
        return jsonify(block_port_with_firewall(db=db, port=str(port), service_name=service))
    finally:
        db.close()


# ============================================================
# 8. AI CYBERSECURITY COPILOT
# ============================================================

@app.route("/assets/ai/ask", methods=["POST"])
def ask_ai():
    data = request.get_json(silent=True) or {}
    question = data.get("question", "")
    if not question.strip():
        return jsonify({"error": "Question is required"}), 400
    return jsonify(ask_cybertwin_ai(question=question))


# ============================================================
# 9. DATA EXPORT BACKUP
# ============================================================

@app.route("/assets/data/export", methods=["GET"])
def export_data():
    db = SessionLocal()
    try:
        assets = db.query(models.Asset).all()
        findings = db.query(models.SecurityFinding).all()
        scans = get_all_scan_history(db, limit=200)
        incidents = db.query(models.SecurityIncident).all()
        alerts = get_all_alerts(db)
        firewall_rules = get_firewall_rules(db)

        return jsonify({
            "export_metadata": {
                "platform": "CyberTwin Flask Server",
                "version": "2.0.0",
                "exported_at": datetime.utcnow().isoformat(),
                "total_assets": len(assets),
                "total_findings": len(findings),
                "total_scans": len(scans),
                "total_alerts": len(alerts),
                "total_firewall_rules": len(firewall_rules)
            },
            "assets": [
                {
                    "id": a.id,
                    "name": a.name,
                    "asset_type": a.asset_type,
                    "ip_address": a.ip_address,
                    "status": a.status,
                    "criticality": a.criticality,
                    "risk_level": a.risk_level
                }
                for a in assets
            ],
            "findings": [
                {
                    "id": f.id,
                    "asset_id": f.asset_id,
                    "title": f.title,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "vulnerability_type": f.vulnerability_type,
                    "affected_component": f.affected_component,
                    "host": f.host,
                    "port": f.port,
                    "status": f.status,
                    "remediation": f.remediation
                }
                for f in findings
            ],
            "scans": scans,
            "alerts": alerts,
            "firewall_rules": firewall_rules
        })
    finally:
        db.close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"==================================================")
    print(f"🚀 CyberTwin Flask Server Starting on port {port}")
    print(f"👉 Local Access:   http://127.0.0.1:{port}")
    print(f"👉 Network Access: http://0.0.0.0:{port}")
    print(f"==================================================")
    app.run(host="0.0.0.0", port=port, debug=False)
