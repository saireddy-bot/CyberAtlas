def calculate_priority(
    risk_score: float,
    business_impact_score: float
):
    """
    Calculate the priority of a security finding.

    Both risk_score and business_impact_score are expected
    to be between 0 and 100.
    """

    priority_score = (
        (risk_score * 0.5) +
        (business_impact_score * 0.5)
    )

    priority_score = round(priority_score, 2)

    if priority_score >= 80:
        priority = "Critical"
    elif priority_score >= 60:
        priority = "High"
    elif priority_score >= 40:
        priority = "Medium"
    else:
        priority = "Low"

    return {
        "priority_score": priority_score,
        "priority": priority
    }