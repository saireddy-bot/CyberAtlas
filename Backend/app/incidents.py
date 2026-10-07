from sqlalchemy.orm import Session

from .models import (
    Asset,
    SecurityFinding,
    SecurityIncident
)


# ============================================================
# CREATE SECURITY INCIDENT
# ============================================================

def create_incident(
    db: Session,
    finding_id: int
):
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.id == finding_id
    ).first()

    if not finding:
        return {
            "error": "Security finding not found"
        }

    asset = db.query(Asset).filter(
        Asset.id == finding.asset_id
    ).first()

    if not asset:
        return {
            "error": "Associated asset not found"
        }

    # Convert finding severity into incident severity
    severity = (finding.severity or "Low").strip().lower()

    if severity == "critical":
        incident_severity = "Critical"
    elif severity == "high":
        incident_severity = "High"
    elif severity == "medium":
        incident_severity = "Medium"
    else:
        incident_severity = "Low"

    # Prevent duplicate incidents for the same finding
    existing_incident = db.query(SecurityIncident).filter(
        SecurityIncident.finding_id == finding.id
    ).first()

    if existing_incident:
        return {
            "incident_id": existing_incident.id,
            "finding_id": finding.id,
            "asset_id": asset.id,
            "asset": asset.name,
            "title": existing_incident.title,
            "severity": existing_incident.severity,
            "status": existing_incident.status,
            "description": existing_incident.description,
            "vulnerability_type": finding.vulnerability_type,
            "affected_component": finding.affected_component,
            "message": "Incident already exists for this finding."
        }

    # Create a new persistent incident
    incident = SecurityIncident(
        finding_id=finding.id,
        asset_id=asset.id,
        title=f"Security Incident: {finding.title}",
        severity=incident_severity,
        status="Open",
        description=finding.description
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return {
        "incident_id": incident.id,
        "finding_id": finding.id,
        "asset_id": asset.id,
        "asset": asset.name,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "description": incident.description,
        "vulnerability_type": finding.vulnerability_type,
        "affected_component": finding.affected_component,
        "message": "Security incident created successfully."
    }


# ============================================================
# GET SINGLE INCIDENT
# ============================================================

def get_incident(
    db: Session,
    incident_id: int
):
    incident = db.query(SecurityIncident).filter(
        SecurityIncident.id == incident_id
    ).first()

    if not incident:
        return {
            "error": "Security incident not found"
        }

    finding = db.query(SecurityFinding).filter(
        SecurityFinding.id == incident.finding_id
    ).first()

    asset = db.query(Asset).filter(
        Asset.id == incident.asset_id
    ).first()

    return {
        "incident_id": incident.id,
        "finding_id": incident.finding_id,
        "asset_id": incident.asset_id,
        "asset": asset.name if asset else None,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "description": incident.description,
        "vulnerability_type": (
            finding.vulnerability_type
            if finding
            else None
        ),
        "affected_component": (
            finding.affected_component
            if finding
            else None
        )
    }


# ============================================================
# LIST ALL INCIDENTS
# ============================================================

def list_incidents(
    db: Session
):
    incidents = db.query(SecurityIncident).order_by(
        SecurityIncident.id.desc()
    ).all()

    result = []

    for incident in incidents:

        finding = db.query(SecurityFinding).filter(
            SecurityFinding.id == incident.finding_id
        ).first()

        asset = db.query(Asset).filter(
            Asset.id == incident.asset_id
        ).first()

        result.append({
            "incident_id": incident.id,
            "finding_id": incident.finding_id,
            "asset_id": incident.asset_id,
            "asset": asset.name if asset else None,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "description": incident.description,
            "vulnerability_type": (
                finding.vulnerability_type
                if finding
                else None
            ),
            "affected_component": (
                finding.affected_component
                if finding
                else None
            )
        })

    return result


# ============================================================
# UPDATE INCIDENT STATUS
# ============================================================

def update_incident_status(
    db: Session,
    incident_id: int,
    status: str
):
    incident = db.query(SecurityIncident).filter(
        SecurityIncident.id == incident_id
    ).first()

    if not incident:
        return {
            "error": "Security incident not found"
        }

    allowed_statuses = [
        "Open",
        "Investigating",
        "Contained",
        "Resolved",
        "Closed"
    ]

    if not status:
        return {
            "error": (
                "Incident status is required."
            )
        }

    normalized_status = status.strip().capitalize()

    if normalized_status not in allowed_statuses:
        return {
            "error": (
                "Invalid incident status. "
                "Allowed values: Open, Investigating, "
                "Contained, Resolved, Closed."
            )
        }

    incident.status = normalized_status

    db.commit()
    db.refresh(incident)

    return {
        "incident_id": incident.id,
        "finding_id": incident.finding_id,
        "asset_id": incident.asset_id,
        "status": incident.status,
        "message": "Incident status updated successfully."
    }