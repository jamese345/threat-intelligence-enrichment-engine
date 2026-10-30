from src.enrichment import enrich_alert
from src.generate_report import generate_all_reports


def main():
    alert = """
        Multiple failed login attempts detected against the admin account.
        The attacker appears to be using a compromised account.
        PowerShell command execution was also detected after authentication.
        Possible credential dumping activity targeting LSASS was observed.
        The attacker performed account discovery to enumerate users.
        The source IP was 185.10.10.25 and the suspicious domain was malicious-example.com.
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