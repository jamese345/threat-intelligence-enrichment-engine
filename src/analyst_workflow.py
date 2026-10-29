RISK_ORDER = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def calculate_risk_summary(results):
    """
    Calculate an overall risk summary from enriched IOC results.
    """

    if not results:
        return {
            "overall_risk": "UNKNOWN",
            "highest_ioc_risk": "UNKNOWN",
            "high_risk_iocs": 0,
            "medium_risk_iocs": 0,
            "low_risk_iocs": 0,
            "unknown_risk_iocs": 0,
        }

    risk_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    highest_risk = "UNKNOWN"

    for result in results:
        risk = result.get("ioc_risk", "UNKNOWN")

        if risk not in risk_counts:
            risk = "UNKNOWN"

        risk_counts[risk] += 1

        if RISK_ORDER[risk] > RISK_ORDER[highest_risk]:
            highest_risk = risk

    return {
        "overall_risk": highest_risk,
        "highest_ioc_risk": highest_risk,
        "high_risk_iocs": risk_counts["HIGH"],
        "medium_risk_iocs": risk_counts["MEDIUM"],
        "low_risk_iocs": risk_counts["LOW"],
        "unknown_risk_iocs": risk_counts["UNKNOWN"],
    }


def calculate_overall_confidence(results):
    """
    Determine overall confidence based on IOC enrichment confidence.
    """

    if not results:
        return "LOW"

    confidence_values = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }

    scores = []

    for result in results:
        confidence = result.get("confidence", "LOW")
        scores.append(
            confidence_values.get(confidence, 1)
        )

    average_score = sum(scores) / len(scores)

    if average_score >= 2.5:
        return "HIGH"

    if average_score >= 1.5:
        return "MEDIUM"

    return "LOW"


def determine_analyst_action(overall_risk, urgency_modifier):
    """
    Determine the recommended SOC analyst action.
    """

    if overall_risk == "HIGH":
        return "ESCALATE"

    if overall_risk == "MEDIUM":
        if urgency_modifier in {"HIGH", "VERY_HIGH"}:
            return "INVESTIGATE"

        return "MONITOR"

    if overall_risk == "LOW":
        if urgency_modifier == "VERY_HIGH":
            return "INVESTIGATE"

        return "MONITOR"

    return "REVIEW"


def generate_analyst_summary(
    overall_risk,
    confidence,
    action,
    risk_summary,
):
    """
    Generate a concise analyst-facing explanation.
    """

    total = sum([
        risk_summary["high_risk_iocs"],
        risk_summary["medium_risk_iocs"],
        risk_summary["low_risk_iocs"],
        risk_summary["unknown_risk_iocs"],
    ])

    if total == 0:
        return "No indicators were available for analysis."

    return (
        f"Alert assessed as {overall_risk} risk with "
        f"{confidence} confidence. "
        f"{risk_summary['high_risk_iocs']} high-risk, "
        f"{risk_summary['medium_risk_iocs']} medium-risk, "
        f"{risk_summary['low_risk_iocs']} low-risk, and "
        f"{risk_summary['unknown_risk_iocs']} unknown-risk "
        f"indicators were identified. "
        f"Recommended action: {action}."
    )


def build_analyst_assessment(
    results,
    urgency_modifier="UNKNOWN",
):
    """
    Build the complete SOC analyst assessment.
    """

    risk_summary = calculate_risk_summary(results)

    confidence = calculate_overall_confidence(results)

    action = determine_analyst_action(
        risk_summary["overall_risk"],
        urgency_modifier,
    )

    summary = generate_analyst_summary(
        risk_summary["overall_risk"],
        confidence,
        action,
        risk_summary,
    )

    return {
        **risk_summary,
        "overall_confidence": confidence,
        "recommended_action": action,
        "analyst_summary": summary,
    }