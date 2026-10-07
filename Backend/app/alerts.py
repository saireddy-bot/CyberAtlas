from datetime import datetime
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session

from .models import (
    SecurityAlert,
    SecurityFinding,
    Asset
)


# ============================================================
# ALERT SEVERITY LEVELS
# ============================================================

ALERT_SEVERITIES = {
    "critical",
    "high",
    "medium"
}


# ============================================================
# SMART DEPARTMENT ROUTING
# ============================================================

def classify_department_and_manager(
    finding: SecurityFinding,
    asset: Optional[Asset] = None
) -> Dict[str, Any]:
    """
    Intelligently routes a detected security bug or exposure to the respective
    department and company security management leadership.
    """
    port_str = str(finding.port or "")
    vuln_type = (finding.vulnerability_type or "").lower()
    title = (finding.title or "").lower()
    asset_type = (asset.asset_type if asset else "").lower()

    department = "Information Security Team"
    channel = "In-App Dashboard & SOC Feed"

    if any(p in port_str for p in ["3306", "5432", "27017", "6379"]) or "database" in vuln_type or "database" in asset_type:
        department = "Database Administration (DBA)"
        channel = "DBA Team Pager & Automated SecOps Feed"
    elif any(p in port_str for p in ["80", "443", "8000", "8080"]) or finding.endpoint or "web" in vuln_type or "web" in asset_type:
        department = "Application Security & WebDev (AppSec)"
        channel = "AppSec Slack/Teams Webhook & Jira Ticket"
    elif any(p in port_str for p in ["21", "22", "23", "3389"]) or "outage" in title or "unreachable" in title or "server" in asset_type:
        department = "DevOps & Infrastructure Team"
        channel = "DevOps Incident Bridge & Email Alert"
    elif "firewall" in vuln_type or "firewall" in title:
        department = "IT & Network Security Team"
        channel = "Network Ops Urgent Dispatch & Email"
    elif asset and getattr(asset, "criticality", 0) >= 5:
        department = "Payment & Financial Compliance SecOps"
        channel = "Executive Compliance Notification & Audit Log"

    # Company manager is alerted on all Critical and High security bugs
    severity = (finding.severity or "Low").strip().lower()
    manager_notified = severity in ["critical", "high"]
    manager_role = "Company Security Manager / CISO" if manager_notified else "Team Lead"

    return {
        "department": department,
        "manager_notified": manager_notified,
        "manager_role": manager_role,
        "notification_channel": channel
    }


# ============================================================
# CREATE AND STORE SECURITY ALERT
# ============================================================

def create_security_alert(
    db: Session,
    finding: SecurityFinding,
    alert_type: str = "new_finding"
) -> Optional[SecurityAlert]:
    """
    Create and permanently store an automated security alert with department and manager routing.
    """
    severity = (finding.severity or "Low").strip().lower()

    if severity not in ALERT_SEVERITIES:
        return None

    asset = (
        db.query(Asset)
        .filter(Asset.id == finding.asset_id)
        .first()
    )

    asset_name = asset.name if asset else "Unknown Asset"

    # Prevent duplicate active alerts
    existing_alert = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.finding_id == finding.id,
            SecurityAlert.status == "unread"
        )
        .first()
    )

    if existing_alert:
        return existing_alert

    # Classify target department and management
    routing = classify_department_and_manager(finding, asset)

    message = (
        f"[{routing['department'].upper()}] {severity.upper()} bug detected on {asset_name}: {finding.title}. "
        f"Escalated to {routing['manager_role']} via {routing['notification_channel']}."
    )

    alert = SecurityAlert(
        finding_id=finding.id,
        asset_id=finding.asset_id,
        alert_type=alert_type,
        severity=severity,
        department=routing["department"],
        manager_notified=routing["manager_notified"],
        manager_role=routing["manager_role"],
        notification_channel=routing["notification_channel"],
        title=finding.title,
        message=message,
        host=finding.host,
        port=finding.port,
        endpoint=finding.endpoint,
        database_name=finding.database_name,
        file_path=finding.file_path,
        status="unread",
        created_at=datetime.utcnow()
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    print(
        f"[AUTOMATED ALERT DISPATCHED] -> To: {routing['department']} & {routing['manager_role']} "
        f"| Severity: {severity.upper()} | Bug: {finding.title}"
    )

    return alert


def check_finding_for_alert(
    db: Session,
    finding: SecurityFinding,
    is_new: bool = True
) -> Optional[SecurityAlert]:
    """Check whether a finding requires an alert and dispatch it."""
    severity = (finding.severity or "").strip().lower()

    if severity not in ALERT_SEVERITIES:
        return None

    alert_type = "new_finding" if is_new else "existing_finding_detected"
    return create_security_alert(
        db=db,
        finding=finding,
        alert_type=alert_type
    )


# ============================================================
# GET ALL ALERTS (WITH DEPARTMENT FILTERING)
# ============================================================

def get_all_alerts(
    db: Session,
    department: Optional[str] = None,
    status: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Return all stored security alerts with routing information."""
    query = db.query(SecurityAlert)

    if department and department.lower() != "all":
        query = query.filter(SecurityAlert.department.ilike(f"%{department}%"))

    if status and status.lower() != "all":
        query = query.filter(SecurityAlert.status == status)

    alerts = query.order_by(SecurityAlert.id.desc()).all()

    return [
        {
            "alert_id": alert.id,
            "finding_id": alert.finding_id,
            "asset_id": alert.asset_id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "department": alert.department or "Information Security Team",
            "manager_notified": alert.manager_notified if alert.manager_notified is not None else True,
            "manager_role": alert.manager_role or "Company Security Manager / CISO",
            "notification_channel": alert.notification_channel or "Dashboard",
            "title": alert.title,
            "message": alert.message,
            "host": alert.host,
            "port": alert.port,
            "endpoint": alert.endpoint,
            "database_name": alert.database_name,
            "file_path": alert.file_path,
            "status": alert.status,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
        }
        for alert in alerts
    ]


def get_alert(
    db: Session,
    alert_id: int
) -> Optional[Dict[str, Any]]:
    """Return single security alert by ID."""
    alert = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.id == alert_id)
        .first()
    )
    if not alert:
        return None

    return {
        "alert_id": alert.id,
        "finding_id": alert.finding_id,
        "asset_id": alert.asset_id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "department": alert.department or "Information Security Team",
        "manager_notified": alert.manager_notified if alert.manager_notified is not None else True,
        "manager_role": alert.manager_role or "Company Security Manager / CISO",
        "notification_channel": alert.notification_channel or "Dashboard",
        "title": alert.title,
        "message": alert.message,
        "host": alert.host,
        "port": alert.port,
        "endpoint": alert.endpoint,
        "database_name": alert.database_name,
        "file_path": alert.file_path,
        "status": alert.status,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
    }


def acknowledge_alert(
    db: Session,
    alert_id: int
) -> Optional[Dict[str, Any]]:
    """Mark an alert as acknowledged by department or manager."""
    alert = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.id == alert_id)
        .first()
    )

    if not alert:
        return None

    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.utcnow()

    db.commit()
    db.refresh(alert)

    return {
        "alert_id": alert.id,
        "status": alert.status,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "department": alert.department,
        "message": f"Alert #{alert.id} acknowledged by {alert.department}."
    }


# ============================================================
# DEPARTMENT ALERT SUMMARY
# ============================================================

def get_department_alert_summary(
    db: Session
) -> Dict[str, Any]:
    """Returns alerts aggregated by department and company management."""
    alerts = db.query(SecurityAlert).all()

    dept_counts: Dict[str, Dict[str, int]] = {}
    manager_alerts_count = 0
    unread_count = 0

    for a in alerts:
        dept = a.department or "Information Security Team"
        if dept not in dept_counts:
            dept_counts[dept] = {"total": 0, "critical": 0, "high": 0, "unread": 0}

        dept_counts[dept]["total"] += 1
        sev = (a.severity or "").lower()
        if sev == "critical":
            dept_counts[dept]["critical"] += 1
        elif sev == "high":
            dept_counts[dept]["high"] += 1

        if (a.status or "").lower() == "unread":
            dept_counts[dept]["unread"] += 1
            unread_count += 1

        if a.manager_notified:
            manager_alerts_count += 1

    return {
        "total_alerts": len(alerts),
        "total_unread": unread_count,
        "manager_alerts_count": manager_alerts_count,
        "departments": dept_counts
    }