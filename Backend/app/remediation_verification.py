from sqlalchemy.orm import Session

from .models import SecurityFinding, Asset
from .risk_engine import calculate_risk
from .scanner import run_security_scan


def verify_remediation(db: Session, finding_id: int):

    finding = db.query(SecurityFinding).filter(
        SecurityFinding.id == finding_id
    ).first()

    if not finding:
        return {
            "error": "Security finding not found"
        }

    if finding.status.lower() != "resolved":
        return {
            "finding_id": finding.id,
            "finding": finding.title,
            "status": finding.status,
            "verification": "NOT_VERIFIED",
            "message": "Finding must be marked as resolved before verification."
        }

    asset = db.query(Asset).filter(
        Asset.id == finding.asset_id
    ).first()

    if not asset:
        return {
            "finding_id": finding.id,
            "verification": "NOT_VERIFIED",
            "message": "Associated asset not found."
        }

    # Run a fresh security scan
    scan_result = run_security_scan(
        ip_address=asset.ip_address,
        asset_type=asset.asset_type
    )

    # Check whether the same finding still exists
    matching_finding = None

    for scan_finding in scan_result.get("findings", []):

        if (
            scan_finding.get("title") == finding.title
            and
            scan_finding.get("host") == finding.host
            and
            scan_finding.get("port") == finding.port
            and
            scan_finding.get("endpoint") == finding.endpoint
            and
            scan_finding.get("database_name") == finding.database_name
            and
            scan_finding.get("file_path") == finding.file_path
        ):
            matching_finding = scan_finding
            break

    # Vulnerability still exists
    if matching_finding:

        finding.status = "open"

        db.commit()
        db.refresh(finding)

        return {
            "finding_id": finding.id,
            "asset_id": finding.asset_id,
            "finding": finding.title,
            "status": "open",
            "verification": "FAILED",
            "message": "Remediation verification failed. The finding is still detected by the latest security scan.",
            "verification_result": "Finding still exists"
        }

    # Vulnerability is no longer detected
    risk_result = calculate_risk(
        cvss_score=float(finding.cvss_score or 0),
        asset_criticality=9,
        exposure=8,
        exploitability=9,
        business_impact=9
    )

    return {
        "finding_id": finding.id,
        "asset_id": finding.asset_id,
        "finding": finding.title,
        "status": finding.status,
        "verification": "VERIFIED",
        "message": "Remediation verified successfully. The finding is no longer detected by the latest security scan.",
        "previous_risk_score": risk_result["risk_score"],
        "verification_result": "Finding no longer detected"
    }