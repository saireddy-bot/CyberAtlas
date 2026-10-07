from sqlalchemy.orm import Session

from .models import Asset, SecurityFinding


def calculate_exposure(db: Session, asset_id: int):

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

    if not findings:
        return {
            "asset_id": asset.id,
            "asset": asset.name,
            "exposure_level": "Low",
            "highest_cvss": 0,
            "open_findings": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "exposure_reasons": [
                "No security findings are currently associated with this asset"
            ]
        }

    cvss_scores = [
        float(finding.cvss_score or 0)
        for finding in findings
    ]

    highest_cvss = max(cvss_scores)

    open_findings = sum(
        1 for finding in findings
        if finding.status.lower() == "open"
    )

    critical_findings = sum(
        1 for finding in findings
        if finding.severity.lower() == "critical"
    )

    high_findings = sum(
        1 for finding in findings
        if finding.severity.lower() == "high"
    )

    medium_findings = sum(
        1 for finding in findings
        if finding.severity.lower() == "medium"
    )

    low_findings = sum(
        1 for finding in findings
        if finding.severity.lower() == "low"
    )

    exposure_reasons = []

    if critical_findings > 0:
        exposure_reasons.append(
            "Critical security vulnerability detected"
        )

    if highest_cvss >= 9:
        exposure_reasons.append(
            "Very high CVSS score detected"
        )
    elif highest_cvss >= 7:
        exposure_reasons.append(
            "High CVSS score detected"
        )

    if open_findings > 0:
        exposure_reasons.append(
            "Open security findings require remediation"
        )

    if asset.asset_type.lower() in [
        "server",
        "web server",
        "application server",
        "database",
        "payment server"
    ]:
        exposure_reasons.append(
            "Asset type may represent a business-critical infrastructure component"
        )

    if critical_findings > 0 or highest_cvss >= 9:
        exposure_level = "Critical"
    elif high_findings > 0 or highest_cvss >= 7:
        exposure_level = "High"
    elif medium_findings > 0 or highest_cvss >= 4:
        exposure_level = "Medium"
    else:
        exposure_level = "Low"

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "exposure_level": exposure_level,
        "highest_cvss": highest_cvss,
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "low_findings": low_findings,
        "exposure_reasons": exposure_reasons
    }