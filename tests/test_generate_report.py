import json
import shutil
import unittest
from pathlib import Path

from src.generate_report import (
    save_json_report,
    save_csv_report,
    generate_text_report,
    generate_all_reports,
)


class TestGenerateReport(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path("test_reports")
        self.test_dir.mkdir(exist_ok=True)

        self.sample_results = {
            "ioc_count": 1,
            "global_threat_context": {
                "source": "ICHI",
                "score": 75,
                "band": "HIGH",
                "status": "success",
            },
            "context_interpretation": {
                "context_available": True,
                "urgency_modifier": "HIGH",
            },
            "results": [
                {
                    "indicator": "8.8.8.8",
                    "indicator_type": "ipv4",
                    "source": "AlienVault OTX",
                    "pulse_count": 15,
                    "reputation": 1,
                    "status": "success",
                    "ioc_risk": "HIGH",
                    "confidence": "HIGH",
                    "global_threat_level": "HIGH",
                    "global_threat_score": 75,
                    "urgency_modifier": "HIGH",
                    "soc_recommendation": "ESCALATE",
                    "risk_reasons": [
                        "Indicator appears in many "
                        "threat-intelligence pulses."
                    ],
                }
            ],
        }

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

        reports_dir = Path("reports")

        for filename in [
            "enrichment_results.json",
            "enrichment_results.csv",
            "enrichment_report.txt",
        ]:
            path = reports_dir / filename
            if path.exists():
                path.unlink()

    def test_save_json_report(self):
        path = save_json_report(self.sample_results)

        self.assertTrue(path.exists())

        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        self.assertEqual(data["ioc_count"], 1)
        self.assertEqual(
            data["results"][0]["ioc_risk"],
            "HIGH"
        )

    def test_save_csv_report(self):
        path = save_csv_report(self.sample_results)

        self.assertTrue(path.exists())

        content = path.read_text(encoding="utf-8")

        self.assertIn("indicator", content)
        self.assertIn("ioc_risk", content)
        self.assertIn("ESCALATE", content)

    def test_generate_text_report(self):
        path = generate_text_report(self.sample_results)

        self.assertTrue(path.exists())

        content = path.read_text(encoding="utf-8")

        self.assertIn(
            "THREAT INTELLIGENCE ENRICHMENT REPORT",
            content
        )
        self.assertIn("8.8.8.8", content)
        self.assertIn("HIGH", content)
        self.assertIn("ESCALATE", content)

    def test_generate_all_reports(self):
        reports = generate_all_reports(self.sample_results)

        self.assertIn("json", reports)
        self.assertIn("csv", reports)
        self.assertIn("text", reports)

        for path in reports.values():
            self.assertTrue(path.exists())

    def test_empty_report(self):
        empty_results = {
            "ioc_count": 0,
            "unique_ioc_count": 0,
            "global_threat_context": {
                "source": "ICHI",
                "status": "success",
                "score": 50,
                "band": "ELEVATED",
            },
            "context_interpretation": {
                "urgency_modifier": "MODERATE",
            },
            "analyst_assessment": {
                "overall_risk": "UNKNOWN",
                "overall_confidence": "LOW",
                "recommended_action": "REVIEW",
                "high_risk_iocs": 0,
                "medium_risk_iocs": 0,
                "low_risk_iocs": 0,
                "unknown_risk_iocs": 0,
                "analyst_summary": (
                    "No indicators were available for analysis."
                ),
            },
            "results": [],
        }

        path = generate_text_report(empty_results)

        self.assertTrue(path.exists())

        content = path.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "No indicators were enriched.",
            content
        )


if __name__ == "__main__":
    unittest.main()