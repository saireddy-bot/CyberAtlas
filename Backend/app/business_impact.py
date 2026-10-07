def calculate_business_impact(
    asset_criticality: int,
    data_sensitivity: int,
    operational_dependency: int,
    customer_impact: int,
    financial_impact: int
):
    """
    Calculate the potential business impact of a security risk.

    All factors are scored from 1 to 10.
    Returns a business impact score from 0 to 100.
    """

    impact_score = (
        (asset_criticality * 0.25) +
        (data_sensitivity * 0.20) +
        (operational_dependency * 0.20) +
        (customer_impact * 0.15) +
        (financial_impact * 0.20)
    ) * 10

    impact_score = round(impact_score, 2)

    if impact_score >= 80:
        impact_level = "Critical"
    elif impact_score >= 60:
        impact_level = "High"
    elif impact_score >= 40:
        impact_level = "Medium"
    else:
        impact_level = "Low"

    return {
        "business_impact_score": impact_score,
        "business_impact_level": impact_level
    }