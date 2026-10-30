import csv
import json
from pathlib import Path


REPORTS_DIR = Path("reports")


def save_json_report(
    enrichment_results,
    filename="enrichment_results.json"
):
    REPORTS_DIR.mkdir(exist_ok=True)

    output_path = REPORTS_DIR / filename

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(
            enrichment_results,
            file,
            indent=4
        )

    return output_path


def save_csv_report(
    enrichment_results,
    filename="enrichment_results.csv"
):
    """
    Save IOC-level threat intelligence results.

    MITRE ATT&CK data is intentionally excluded because
    MITRE techniques describe alert behavior rather than
    individual IOC reputation.
    """

    REPORTS_DIR.mkdir(exist_ok=True)

    output_path = REPORTS_DIR / filename
    results = enrichment_results.get("results", [])

    fieldnames = [
        "indicator",
        "indicator_type",
        "source",
        "pulse_count",
        "reputation",
        "status",
        "ioc_risk",
        "confidence",
        "global_threat_level",
        "global_threat_score",
        "urgency_modifier",
        "soc_recommendation",
    ]

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for result in results:
            writer.writerow({
                "indicator": result.get(
                    "indicator"
                ),
                "indicator_type": result.get(
                    "indicator_type"
                ),
                "source": result.get(
                    "source"
                ),
                "pulse_count": result.get(
                    "pulse_count"
                ),
                "reputation": result.get(
                    "reputation"
                ),
                "status": result.get(
                    "status"
                ),
                "ioc_risk": result.get(
                    "ioc_risk"
                ),
                "confidence": result.get(
                    "confidence"
                ),
                "global_threat_level": result.get(
                    "global_threat_level"
                ),
                "global_threat_score": result.get(
                    "global_threat_score"
                ),
                "urgency_modifier": result.get(
                    "urgency_modifier"
                ),
                "soc_recommendation": result.get(
                    "soc_recommendation"
                ),
            })

    return output_path


def save_mitre_csv_report(
    enrichment_results,
    filename="mitre_attack.csv"
):
    """
    Save alert-level MITRE ATT&CK analysis.

    MITRE techniques represent behavioral evidence
    identified from the alert.
    """

    REPORTS_DIR.mkdir(exist_ok=True)

    output_path = REPORTS_DIR / filename

    mitre_techniques = enrichment_results.get(
        "mitre_attack",
        []
    )

    fieldnames = [
        "technique_id",
        "name",
        "tactics",
        "matched_keywords",
        "description",
    ]

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for technique in mitre_techniques:
            writer.writerow({
                "technique_id": technique.get(
                    "technique_id"
                ),
                "name": technique.get(
                    "name"
                ),
                "tactics": "; ".join(
                    technique.get(
                        "tactics",
                        []
                    )
                ),
                "matched_keywords": "; ".join(
                    technique.get(
                        "matched_keywords",
                        []
                    )
                ),
                "description": technique.get(
                    "description",
                    ""
                ),
            })

    return output_path


def generate_text_report(
    enrichment_results,
    filename="enrichment_report.txt"
):
    """
    Generate a concise SOC analyst report.

    Full MITRE descriptions remain available in the
    JSON and MITRE CSV reports.
    """

    REPORTS_DIR.mkdir(exist_ok=True)

    output_path = REPORTS_DIR / filename

    global_context = enrichment_results.get(
        "global_threat_context",
        {}
    )

    context_interpretation = enrichment_results.get(
        "context_interpretation",
        {}
    )

    analyst_assessment = enrichment_results.get(
        "analyst_assessment",
        {}
    )

    mitre_techniques = enrichment_results.get(
        "mitre_attack",
        []
    )

    results = enrichment_results.get(
        "results",
        []
    )

    lines = [
        "=" * 70,
        "THREAT INTELLIGENCE ENRICHMENT REPORT",
        "=" * 70,
        "",
        f"IOC Count: "
        f"{enrichment_results.get('ioc_count', 0)}",
        f"Unique IOC Count: "
        f"{enrichment_results.get('unique_ioc_count', 0)}",
        "",
        "SOC ANALYST ASSESSMENT",
        "-" * 70,
        f"Overall Risk: "
        f"{analyst_assessment.get('overall_risk', 'UNKNOWN')}",
        f"Confidence: "
        f"{analyst_assessment.get('overall_confidence', 'LOW')}",
        f"Recommended Action: "
        f"{analyst_assessment.get('recommended_action', 'REVIEW')}",
        f"High-Risk IOCs: "
        f"{analyst_assessment.get('high_risk_iocs', 0)}",
        f"Medium-Risk IOCs: "
        f"{analyst_assessment.get('medium_risk_iocs', 0)}",
        f"Low-Risk IOCs: "
        f"{analyst_assessment.get('low_risk_iocs', 0)}",
        f"Unknown-Risk IOCs: "
        f"{analyst_assessment.get('unknown_risk_iocs', 0)}",
        "",
        "Analyst Summary:",
        analyst_assessment.get(
            "analyst_summary",
            "No analyst summary available."
        ),
        "",
        "GLOBAL THREAT CONTEXT",
        "-" * 70,
        f"Source: "
        f"{global_context.get('source', 'Unknown')}",
        f"Threat Score: "
        f"{global_context.get('score', 'Unknown')}",
        f"Threat Level: "
        f"{global_context.get('band', 'Unknown')}",
        f"Urgency Modifier: "
        f"{context_interpretation.get('urgency_modifier', 'Unknown')}",
        f"Context Status: "
        f"{global_context.get('status', 'Unknown')}",
        "",
        "MITRE ATT&CK ANALYSIS",
        "-" * 70,
        f"Techniques Identified: {len(mitre_techniques)}",
    ]

    if not mitre_techniques:
        lines.append(
            "No MITRE ATT&CK techniques identified."
        )

    else:
        for index, technique in enumerate(
            mitre_techniques,
            start=1
        ):
            lines.extend([
                "",
                f"[{index}] "
                f"{technique.get('technique_id', 'Unknown')} "
                f"- "
                f"{technique.get('name', 'Unknown')}",
                f"Tactics: "
                f"{', '.join(technique.get('tactics', []))}",
                f"Evidence: "
                f"{', '.join(technique.get('matched_keywords', []))}",
            ])

    lines.extend([
        "",
        "ENRICHED INDICATORS",
        "-" * 70,
    ])

    if not results:
        lines.append(
            "No indicators were enriched."
        )

    for index, result in enumerate(
        results,
        start=1
    ):
        lines.extend([
            "",
            f"[{index}] "
            f"{result.get('indicator', 'Unknown')}",
            f"Type: "
            f"{result.get('indicator_type', 'Unknown')}",
            f"IOC Risk: "
            f"{result.get('ioc_risk', 'Unknown')}",
            f"Confidence: "
            f"{result.get('confidence', 'Unknown')}",
            f"Pulse Count: "
            f"{result.get('pulse_count', 0)}",
            f"Reputation: "
            f"{result.get('reputation', 0)}",
            f"Global Threat Level: "
            f"{result.get('global_threat_level', 'Unknown')}",
            f"Global Threat Score: "
            f"{result.get('global_threat_score', 'Unknown')}",
            f"Urgency Modifier: "
            f"{result.get('urgency_modifier', 'Unknown')}",
            f"Recommendation: "
            f"{result.get('soc_recommendation', 'REVIEW')}",
        ])

        reasons = result.get(
            "risk_reasons",
            []
        )

        if reasons:
            lines.append(
                "Risk Reasons:"
            )

            for reason in reasons:
                lines.append(
                    f"  - {reason}"
                )

    lines.extend([
        "",
        "=" * 70,
        "END OF REPORT",
        "=" * 70,
    ])

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(
            "\n".join(lines)
        )

    return output_path


def generate_all_reports(
    enrichment_results
):
    return {
        "json": save_json_report(
            enrichment_results
        ),
        "csv": save_csv_report(
            enrichment_results
        ),
        "mitre_csv": save_mitre_csv_report(
            enrichment_results
        ),
        "text": generate_text_report(
            enrichment_results
        ),
    }
