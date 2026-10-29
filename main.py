from src.enrichment import enrich_alert
from src.generate_report import generate_all_reports


def main():
    alert = """
    Suspicious login activity detected from 8.8.8.8.
    The user also connected to malicious-example.com.
    """

    results = enrich_alert(alert)

    print("=" * 60)
    print("THREAT INTELLIGENCE ENRICHMENT ENGINE")
    print("=" * 60)
    print()

    print(f"IOC Count: {results['ioc_count']}")
    print()

    assessment = results["analyst_assessment"]

    print("SOC Analyst Assessment:")
    print(f"  Overall Risk: {assessment['overall_risk']}")
    print(f"  Confidence: {assessment['overall_confidence']}")
    print(f"  Recommended Action: {assessment['recommended_action']}")
    print(f"  High-Risk IOCs: {assessment['high_risk_iocs']}")
    print(f"  Medium-Risk IOCs: {assessment['medium_risk_iocs']}")
    print(f"  Low-Risk IOCs: {assessment['low_risk_iocs']}")
    print(f"  Unknown-Risk IOCs: {assessment['unknown_risk_iocs']}")
    print(f"  Summary: {assessment['analyst_summary']}")
    print()

    # Generate reports
    report_paths = generate_all_reports(results)

    print("Reports Generated:")
    for report_type, path in report_paths.items():
        print(f"  {report_type.upper()}: {path}")


if __name__ == "__main__":
    main()