import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Asset, SecurityFinding
from .scanner import run_security_scan, check_host_reachability
from .scan_history import create_scan_record
from .alerts import check_finding_for_alert


# ============================================================
# AUTOMATIC SCANNER CONFIGURATION & STATE
# ============================================================

SCAN_INTERVAL_SECONDS = 60

_auto_scanner_running = False
_auto_scanner_thread: Optional[threading.Thread] = None
_last_scan_time: Optional[datetime] = None
_total_scans_executed = 0
_last_scan_summary: Dict[str, Any] = {
    "total_scanned": 0,
    "online_count": 0,
    "offline_count": 0,
    "total_findings": 0
}


# ============================================================
# SAVE OR UPDATE FINDING
# ============================================================

def save_scan_finding(
    db: Session,
    asset: Asset,
    scan_finding: dict
):
    """
    Save a scanner finding into the database.
    If the same finding already exists, update it. Otherwise create a new finding.
    """
    title = scan_finding.get("title", "Unknown Security Finding")
    affected_component = scan_finding.get("affected_component")
    host = scan_finding.get("host")
    port = scan_finding.get("port")
    endpoint = scan_finding.get("endpoint")
    database_name = scan_finding.get("database_name")
    file_path = scan_finding.get("file_path")

    existing_finding = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.asset_id == asset.id,
            SecurityFinding.title == title,
            SecurityFinding.affected_component == affected_component,
            SecurityFinding.host == host,
            SecurityFinding.port == port,
            SecurityFinding.endpoint == endpoint,
            SecurityFinding.database_name == database_name,
            SecurityFinding.file_path == file_path
        )
        .first()
    )

    if existing_finding:
        was_resolved = (existing_finding.status or "").lower() == "resolved"
        existing_finding.description = scan_finding.get("description")
        existing_finding.severity = scan_finding.get("severity", existing_finding.severity)
        existing_finding.cvss_score = str(scan_finding.get("cvss_score", existing_finding.cvss_score or ""))
        existing_finding.vulnerability_type = scan_finding.get("vulnerability_type")
        existing_finding.affected_component = affected_component
        existing_finding.host = host
        existing_finding.port = port
        existing_finding.endpoint = endpoint
        existing_finding.database_name = database_name
        existing_finding.file_path = file_path
        existing_finding.remediation = scan_finding.get("remediation")

        if was_resolved:
            existing_finding.status = "open"

        db.commit()
        db.refresh(existing_finding)
        return existing_finding, False, was_resolved

    new_finding = SecurityFinding(
        asset_id=asset.id,
        title=title,
        description=scan_finding.get("description"),
        severity=scan_finding.get("severity", "Low"),
        cvss_score=str(scan_finding.get("cvss_score", "")),
        vulnerability_type=scan_finding.get("vulnerability_type"),
        affected_component=affected_component,
        host=host,
        port=port,
        endpoint=endpoint,
        database_name=database_name,
        file_path=file_path,
        status="open",
        remediation=scan_finding.get("remediation")
    )

    db.add(new_finding)
    db.commit()
    db.refresh(new_finding)
    return new_finding, True, False


# ============================================================
# RUN AUTOMATIC SCAN (ALL SYSTEMS: BOTH ONLINE & OFFLINE)
# ============================================================

def run_automatic_scan() -> Dict[str, Any]:
    """
    Executes a complete scan across ALL registered systems and servers.
    Audits active exposures for Online (ON) systems and downtime/dormant posture
    for Offline (OFF) systems.
    """
    global _last_scan_time, _total_scans_executed, _last_scan_summary

    db: Session = SessionLocal()
    scanned_count = 0
    online_count = 0
    offline_count = 0
    total_findings_detected = 0

    try:
        # Audit ALL registered assets (do not exclude offline servers)
        assets = db.query(Asset).all()

        for asset in assets:
            if not asset.ip_address or asset.ip_address.lower() == "string":
                continue

            scanned_count += 1

            try:
                # 1. Probe live reachability & update asset status
                reachability = check_host_reachability(asset.ip_address)
                current_is_online = reachability.get("reachable", False)

                if current_is_online:
                    asset.status = "online"
                    online_count += 1
                else:
                    asset.status = "offline"
                    offline_count += 1

                db.commit()

                # 2. Count existing open findings
                open_findings = (
                    db.query(SecurityFinding)
                    .filter(
                        SecurityFinding.asset_id == asset.id,
                        SecurityFinding.status == "open"
                    )
                    .all()
                )

                # 3. Execute Dual-mode Security Scan (Active or Dormant/Offline)
                scan_result = run_security_scan(
                    ip_address=asset.ip_address,
                    asset_type=asset.asset_type,
                    asset_name=asset.name,
                    criticality=getattr(asset, "criticality", 5) or 5,
                    existing_findings_count=len(open_findings)
                )

                findings = scan_result.get("findings", [])
                total_findings_detected += len(findings)

                # 4. Save findings and dispatch alerts
                for scan_finding in findings:
                    finding, is_new, was_resolved = save_scan_finding(
                        db=db,
                        asset=asset,
                        scan_finding=scan_finding
                    )

                    if is_new or was_resolved:
                        alert = check_finding_for_alert(
                            db=db,
                            finding=finding,
                            is_new=is_new
                        )
                        if alert:
                            print(
                                f"[CYBERTWIN ALERT] {finding.severity.upper()}: "
                                f"{finding.title} on {asset.name} ({asset.status.upper()})"
                            )

                # 5. Record scan in audit history
                create_scan_record(
                    db=db,
                    asset_id=asset.id,
                    target=asset.ip_address,
                    asset_type=asset.asset_type,
                    total_findings=len(findings),
                    risk_score=float(len(findings) * 2.5),
                    status=scan_result.get("status", "completed"),
                    scan_type="automatic",
                    is_online=(asset.status == "online"),
                    scan_summary=[
                        {
                            "title": f.get("title"),
                            "severity": f.get("severity"),
                            "cvss_score": f.get("cvss_score"),
                            "port": f.get("port"),
                            "vulnerability_type": f.get("vulnerability_type")
                        }
                        for f in findings
                    ]
                )

            except Exception as error:
                print(f"[CYBERTWIN SCANNER ERROR] Asset {asset.name} scan failed: {error}")
                try:
                    create_scan_record(
                        db=db,
                        asset_id=asset.id,
                        target=asset.ip_address,
                        asset_type=asset.asset_type,
                        total_findings=0,
                        risk_score=0,
                        status="failed",
                        scan_type="automatic",
                        is_online=(asset.status == "online"),
                        scan_summary={"error": str(error)}
                    )
                except Exception:
                    pass

        _last_scan_time = datetime.utcnow()
        _total_scans_executed += 1
        _last_scan_summary = {
            "total_scanned": scanned_count,
            "online_count": online_count,
            "offline_count": offline_count,
            "total_findings": total_findings_detected,
            "timestamp": _last_scan_time.isoformat()
        }

        return _last_scan_summary

    finally:
        db.close()


# ============================================================
# AUTOMATIC SCANNER LOOP
# ============================================================

def automatic_scanner_loop():
    global _auto_scanner_running

    while _auto_scanner_running:
        try:
            run_automatic_scan()
        except Exception as error:
            print(f"[CYBERTWIN AUTO-SCANNER] Error in cycle: {error}")

        # Sleep interval with interruptible polling
        for _ in range(SCAN_INTERVAL_SECONDS):
            if not _auto_scanner_running:
                break
            time.sleep(1)


# ============================================================
# START / UPDATE AUTOMATIC SCANNER
# ============================================================

def set_scan_interval(interval_seconds: int) -> Dict[str, Any]:
    global SCAN_INTERVAL_SECONDS
    if interval_seconds < 5:
        interval_seconds = 5  # minimum safety guard

    SCAN_INTERVAL_SECONDS = interval_seconds
    return {
        "status": "updated",
        "interval_seconds": SCAN_INTERVAL_SECONDS,
        "message": f"Scan timer interval updated to {SCAN_INTERVAL_SECONDS} seconds."
    }


def start_automatic_scanner(interval_seconds: int = 60) -> Dict[str, Any]:
    global _auto_scanner_running, _auto_scanner_thread, SCAN_INTERVAL_SECONDS

    if interval_seconds < 5:
        interval_seconds = 5
    SCAN_INTERVAL_SECONDS = interval_seconds

    if _auto_scanner_running:
        return {
            "status": "already_running",
            "message": f"Automatic scanner timer updated to every {SCAN_INTERVAL_SECONDS}s.",
            "interval_seconds": SCAN_INTERVAL_SECONDS,
            "last_scan": _last_scan_summary
        }

    _auto_scanner_running = True
    _auto_scanner_thread = threading.Thread(
        target=automatic_scanner_loop,
        daemon=True,
        name="CyberTwin-AutoScanner"
    )
    _auto_scanner_thread.start()

    return {
        "status": "started",
        "message": f"Automatic continuous scanner started successfully (Auditing all ON/OFF systems every {SCAN_INTERVAL_SECONDS}s).",
        "interval_seconds": SCAN_INTERVAL_SECONDS
    }


# ============================================================
# STOP AUTOMATIC SCANNER
# ============================================================

def stop_automatic_scanner() -> Dict[str, Any]:
    global _auto_scanner_running

    if not _auto_scanner_running:
        return {
            "status": "already_stopped",
            "message": "Automatic scanner is already stopped."
        }

    _auto_scanner_running = False
    return {
        "status": "stopped",
        "message": "Automatic scanner stopped successfully."
    }


# ============================================================
# GET AUTOMATIC SCANNER STATUS
# ============================================================

def get_automatic_scanner_status() -> Dict[str, Any]:
    thread_alive = (
        _auto_scanner_thread is not None
        and _auto_scanner_thread.is_alive()
    )

    return {
        "running": _auto_scanner_running,
        "thread_alive": thread_alive,
        "interval_seconds": SCAN_INTERVAL_SECONDS,
        "total_scans_executed": _total_scans_executed,
        "last_scan_time": _last_scan_time.isoformat() if _last_scan_time else None,
        "last_scan_summary": _last_scan_summary
    }