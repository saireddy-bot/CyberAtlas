from sqlalchemy.orm import Session

from .models import Asset, SecurityFinding


def assess_asset_security(
    db: Session,
    asset_id: int
):
    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if not asset:
        return {
            "error": "Asset not found"
        }

    findings = db.query(SecurityFinding).filter(
        SecurityFinding.asset_id == asset_id
    ).all()

    critical = sum(
        1 for finding in findings
        if finding.severity.lower() == "critical"
    )

    high = sum(
        1 for finding in findings
        if finding.severity.lower() == "high"
    )

    medium = sum(
        1 for finding in findings
        if finding.severity.lower() == "medium"
    )

    low = sum(
        1 for finding in findings
        if finding.severity.lower() == "low"
    )

    open_findings = sum(
        1 for finding in findings
        if finding.status.lower() == "open"
    )

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "asset_type": asset.asset_type,
        "ip_address": asset.ip_address,
        "total_findings": len(findings),
        "critical_findings": critical,
        "high_findings": high,
        "medium_findings": medium,
        "low_findings": low,
        "open_findings": open_findings,
        "assessment_status": (
            "Requires Attention"
            if open_findings > 0
            else "No Open Findings"
        )
    }