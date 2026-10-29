def interpret_global_context(context):
    """
    Convert global threat context into
    an operational urgency modifier.
    """

    if context.get("status") != "success":
        return {
            "context_available": False,
            "urgency_modifier": "UNKNOWN",
            "explanation": (
                "Global threat context unavailable."
            )
        }

    band = context.get("band")

    if band == "CRITICAL":
        modifier = "VERY_HIGH"

    elif band == "HIGH":
        modifier = "HIGH"

    elif band == "ELEVATED":
        modifier = "MODERATE"

    elif band in {"GUARDED", "NORMAL"}:
        modifier = "LOW"

    else:
        modifier = "UNKNOWN"

    return {
        "context_available": True,
        "urgency_modifier": modifier,
        "explanation": (
            f"Global threat environment is {band}."
        )
    }


def determine_ioc_risk(ioc_result):
    """
    Determine risk from IOC threat-intelligence
    evidence.
    """

    if ioc_result.get("status") != "success":
        return {
            "ioc_risk": "UNKNOWN",
            "confidence": "LOW",
            "reasons": [
                "Threat intelligence unavailable."
            ]
        }

    pulse_count = ioc_result.get(
        "pulse_count",
        0
    )

    reputation = ioc_result.get(
        "reputation",
        0
    )

    reasons = []

    if pulse_count >= 10:
        reasons.append(
            "Indicator appears in many threat-intelligence pulses."
        )

    elif pulse_count > 0:
        reasons.append(
            "Indicator appears in threat-intelligence data."
        )

    if reputation > 0:
        reasons.append(
            "Threat-intelligence reputation is positive."
        )

    if reputation > 0 and pulse_count >= 10:
        risk = "HIGH"
        confidence = "HIGH"

    elif reputation > 0 or pulse_count >= 5:
        risk = "MEDIUM"
        confidence = "MEDIUM"

    elif pulse_count > 0:
        risk = "LOW"
        confidence = "LOW"

    else:
        risk = "UNKNOWN"
        confidence = "LOW"
        reasons.append(
            "No strong malicious evidence was identified."
        )

    return {
        "ioc_risk": risk,
        "confidence": confidence,
        "reasons": reasons
    }


def generate_recommendation(
    ioc_risk,
    global_modifier
):
    """
    Generate an explainable SOC recommendation.

    Global threat context influences urgency but
    does not independently make an IOC malicious.
    """

    if ioc_risk == "HIGH":

        if global_modifier in {
            "HIGH",
            "VERY_HIGH"
        }:
            return "ESCALATE"

        return "INVESTIGATE"

    if ioc_risk == "MEDIUM":

        if global_modifier == "VERY_HIGH":
            return "ESCALATE"

        if global_modifier == "HIGH":
            return "INVESTIGATE"

        return "MONITOR"

    if ioc_risk == "LOW":

        if global_modifier == "VERY_HIGH":
            return "INVESTIGATE"

        return "MONITOR"

    return "REVIEW"