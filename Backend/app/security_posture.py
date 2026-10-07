from sqlalchemy.orm import Session

from .models import Asset, SecurityFinding
from .risk_engine import calculate_risk
from .business_impact import calculate_business_impact
from .risk_priority import calculate_priority


def calculate_security_posture(db: Session):

    assets = db.query(Asset).all()
    findings = db.query(SecurityFinding).all()

    if not assets:
        return {
            "overall_risk": 0,
            "overall_risk_level": "Low",
            "assessment_coverage": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "open_findings": 0,
            "top_risks": []
        }

    risk_results = []

    for finding in findings:

        cvss_score = float(finding.cvss_score or 0)

        risk_result = calculate_risk(
            cvss_score=cvss_score,
            asset_criticality=9,
            exposure=8,
            exploitability=9,
            business_impact=9
        )

        impact_result = calculate_business_impact(
            asset_criticality=9,
            data_sensitivity=9,
            operational_dependency=10,
            customer_impact=9,
            financial_impact=10
        )

        priority_result = calculate_priority(
            risk_score=risk_result["risk_score"],
            business_impact_score=impact_result["business_impact_score"]
        )

        risk_results.append({
            "finding_id": finding.id,
            "asset_id": finding.asset_id,
            "finding": finding.title,
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "business_impact_score": impact_result["business_impact_score"],
            "priority": priority_result["priority"]
        })

    if risk_results:
        overall_risk = round(
            sum(item["risk_score"] for item in risk_results)
            / len(risk_results),
            2
        )
    else:
        overall_risk = 0

    if overall_risk >= 80:
        overall_risk_level = "Critical"
    elif overall_risk >= 60:
        overall_risk_level = "High"
    elif overall_risk >= 40:
        overall_risk_level = "Medium"
    else:
        overall_risk_level = "Low"

    critical_findings = sum(
        1 for item in risk_results
        if item["risk_level"] == "Critical"
    )

    high_findings = sum(
        1 for item in risk_results
        if item["risk_level"] == "High"
    )

    medium_findings = sum(
        1 for item in risk_results
        if item["risk_level"] == "Medium"
    )

    low_findings = sum(
        1 for item in risk_results
        if item["risk_level"] == "Low"
    )

    open_findings = sum(
        1 for finding in findings
        if finding.status.lower() == "open"
    )

    assessed_asset_ids = {
        finding.asset_id
        for finding in findings
        if finding.asset_id is not None
    }

    assessment_coverage = round(
        (len(assessed_asset_ids) / len(assets)) * 100,
        2
    )

    top_risks = sorted(
        risk_results,
        key=lambda item: item["risk_score"],
        reverse=True
    )[:5]

    return {
        "overall_risk": overall_risk,
        "overall_risk_level": overall_risk_level,
        "assessment_coverage": assessment_coverage,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "low_findings": low_findings,
        "open_findings": open_findings,
        "top_risks": top_risks
    }