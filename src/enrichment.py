from src.normalize_iocs import normalize_iocs
from src.analyst_workflow import build_analyst_assessment
from src.extract_iocs import extract_iocs
from src.threat_intelligence import safe_enrich
from src.global_threat_context import (
    get_global_threat_context,
    GlobalThreatContextError
)
from src.risk_context import (
    interpret_global_context,
    determine_ioc_risk,
    generate_recommendation
)



def get_safe_global_context():

    try:
        return get_global_threat_context()

    except GlobalThreatContextError as error:

        return {
            "source": "ICHI",
            "status": "error",
            "error": str(error)
        }


def enrich_alert(alert_text):
    if not alert_text or not isinstance(alert_text, str):
        alert_text = ""

    iocs = extract_iocs(alert_text)
    iocs = normalize_iocs(iocs)

    results = []

    for ip in iocs["ips"]:
        results.append(safe_enrich(ip, "ipv4"))

    for domain in iocs["domains"]:
        results.append(safe_enrich(domain, "domain"))

    for url in iocs["urls"]:
        results.append(safe_enrich(url, "url"))

    for hash_type, hashes in iocs["hashes"].items():
        for file_hash in hashes:
            results.append(
                safe_enrich(file_hash, hash_type)
            )

    global_context = get_safe_global_context()

    context_interpretation = interpret_global_context(
        global_context
    )

    enriched_results = []

    for result in results:
        ioc_analysis = determine_ioc_risk(result)

        recommendation = generate_recommendation(
            ioc_analysis["ioc_risk"],
            context_interpretation["urgency_modifier"]
        )

        enriched_results.append({
            **result,
            "ioc_risk": ioc_analysis["ioc_risk"],
            "confidence": ioc_analysis["confidence"],
            "risk_reasons": ioc_analysis["reasons"],
            "global_threat_level": global_context.get("band"),
            "global_threat_score": global_context.get("score"),
            "urgency_modifier": (
                context_interpretation["urgency_modifier"]
            ),
            "soc_recommendation": recommendation
        })

    # IMPORTANT:
    # This must be outside the IOC loops.
    analyst_assessment = build_analyst_assessment(
        enriched_results,
        context_interpretation["urgency_modifier"],
    )

    return {
        "ioc_count": len(enriched_results),
        "unique_ioc_count": len(enriched_results),
        "global_threat_context": global_context,
        "context_interpretation": context_interpretation,
        "analyst_assessment": analyst_assessment,
        "results": enriched_results,
    }
