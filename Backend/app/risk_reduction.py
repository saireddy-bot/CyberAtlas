from sqlalchemy.orm import Session

from .models import SecurityFinding, Asset
from .risk_engine import calculate_risk


def calculate_risk_reduction(
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

    # Find the asset associated with this finding
    asset = db.query(Asset).filter(
        Asset.id == finding.asset_id
    ).first()

    # Use the real asset criticality
    asset_criticality = (
        asset.criticality
        if asset
        else 5
    )

    cvss_score = float(
        finding.cvss_score or 0
    )

    # ========================================================
    # RISK BEFORE REMEDIATION
    # ========================================================

    before_result = calculate_risk(
        cvss_score=cvss_score,
        asset_criticality=asset_criticality,
        exposure=8,
        exploitability=9,
        business_impact=9
    )

    before_risk = before_result["risk_score"]

    # ========================================================
    # RISK AFTER REMEDIATION
    # ========================================================

    if finding.status.lower() == "resolved":

        after_result = calculate_risk(
            cvss_score=0,
            asset_criticality=asset_criticality,
            exposure=2,
            exploitability=1,
            business_impact=3
        )

        after_risk = after_result["risk_score"]

        if before_risk > 0:

            risk_reduction = round(
                (
                    (before_risk - after_risk)
                    / before_risk
                ) * 100,
                2
            )

        else:
            risk_reduction = 0

        return {
            "finding_id": finding.id,
            "asset_id": finding.asset_id,
            "finding": finding.title,

            "status": finding.status,

            "asset_criticality": asset_criticality,

            "before_risk_score": before_risk,
            "before_risk_level": before_result[
                "risk_level"
            ],

            "after_risk_score": after_risk,
            "after_risk_level": after_result[
                "risk_level"
            ],

            "risk_reduction_percent": risk_reduction,

            "message": (
                "Risk reduction calculated "
                "after remediation."
            )
        }

    # ========================================================
    # FINDING IS STILL OPEN
    # ========================================================

    return {
        "finding_id": finding.id,
        "asset_id": finding.asset_id,
        "finding": finding.title,

        "status": finding.status,

        "asset_criticality": asset_criticality,

        "before_risk_score": before_risk,
        "before_risk_level": before_result[
            "risk_level"
        ],

        "after_risk_score": None,
        "after_risk_level": None,

        "risk_reduction_percent": 0,

        "message": (
            "Risk reduction cannot be calculated "
            "until the finding is resolved."
        )
    }