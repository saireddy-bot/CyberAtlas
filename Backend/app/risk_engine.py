def calculate_risk(
    cvss_score: float,
    asset_criticality: float,
    exposure: float,
    exploitability: float,
    business_impact: float
):
    """
    Calculate CyberTwin's overall risk score.

    All input factors are expected to be between 0 and 10.
    The returned risk score is between 0 and 100.
    """

    # Weighted risk calculation
    risk_score = (
        (cvss_score * 0.30) +
        (asset_criticality * 0.20) +
        (exposure * 0.15) +
        (exploitability * 0.15) +
        (business_impact * 0.20)
    ) * 10

    risk_score = round(risk_score, 2)

    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level
    }