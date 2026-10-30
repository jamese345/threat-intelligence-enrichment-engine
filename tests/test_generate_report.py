import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.generate_report import (
    save_json_report,
    save_csv_report,
    save_mitre_csv_report,
    generate_text_report,
    generate_all_reports,
)


class TestGenerateReport(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.enrichment_results = {
            "ioc_count": 2,
            "unique_ioc_count": 2,
            "global_threat_context": {
                "source": "ICHI",
                "score": 68.75,
                "band": "ELEVATED",
                "status": "success",
            },
            "context_interpretation": {
                "urgency_modifier": "MODERATE",
            },
            "analyst_assessment": {
                "overall_risk": "MEDIUM",
                "overall_confidence": "MEDIUM",
                "recommended_action": "MONITOR",
                "high_risk_iocs": 0,
                "medium_risk_iocs": 1,
                "low_risk_iocs": 0,
                "unknown_risk_iocs": 1,
                "analyst_summary": (
                    "Alert assessed as MEDIUM risk."
                ),
            },
            "mitre_attack": [
                {
                    "technique_id": "T1110",
                    "name": "Brute Force",
                    "tactics": [
                        "credential-access"
                    ],
                    "matched_keywords": [
                        "brute force",
                        "failed login",
                    ],
                    "description": (
                        "Adversaries may use brute force "
                        "techniques to gain access to accounts."
                    ),
                }
            ],
            "results": [
                {
                    "indicator": "8.8.8.8",
                    "indicator_type": "ipv4",
                    "source": "OTX",
                    "pulse_count": 0,
                    "reputation": 0,
                    "status": "unknown",
                    "ioc_risk": "UNKNOWN",
                    "confidence": "LOW",
                    "global_threat_level": "ELEVATED",
                    "global_threat_score": 68.75,
                    "urgency_modifier": "MODERATE",
                    "soc_recommendation": "REVIEW",
                    "risk_reasons": [
                        "No strong malicious evidence found."
                    ],
                },
                {
                    "indicator": "malicious-example.com",
                    "indicator_type": "domain",
                    "source": "OTX",
                    "pulse_count": 20,
                    "reputation": 0,
                    "status": "unknown",
                    "ioc_risk": "MEDIUM",
                    "confidence": "MEDIUM",
                    "global_threat_level": "ELEVATED",
                    "global_threat_score": 68.75,
                    "urgency_modifier": "MODERATE",
                    "soc_recommendation": "MONITOR",
                    "risk_reasons": [
                        "Indicator appears in many "
                        "threat-intelligence pulses."
                    ],
                },
            ],
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_json_report(self):
        with patch(
            "src.generate_report.REPORTS_DIR",
            Path(self.temp_dir.name)
        ):
            output_path = save_json_report(
                self.enrichment_results
            )

        self.assertTrue(output_path.exists())

        with open(
            output_path,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        self.assertEqual(
            data["ioc_count"],
            2
        )

        self.assertEqual(
            data["mitre_attack"][0]["technique_id"],
            "T1110"
        )

    def test_save_csv_report(self):
        with patch(
            "src.generate_report.REPORTS_DIR",
            Path(self.temp_dir.name)
        ):
            output_path = save_csv_report(
                self.enrichment_results
            )

        self.assertTrue(output_path.exists())

        with open(
            output_path,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:
            rows = list(
                csv.DictReader(file)
            )

        self.assertEqual(
            len(rows),
            2
        )

        self.assertEqual(
            rows[0]["indicator"],
            "8.8.8.8"
        )

        self.assertEqual(
            rows[1]["indicator"],
            "malicious-example.com"
        )

        self.assertEqual(
            rows[1]["ioc_risk"],
            "MEDIUM"
        )

        # MITRE data should NOT be repeated
        # across IOC-level rows.
        self.assertNotIn(
            "mitre_techniques",
            rows[0]
        )

        self.assertNotIn(
            "mitre_tactics",
            rows[0]
        )

        self.assertNotIn(
            "mitre_keywords",
            rows[0]
        )

    def test_save_mitre_csv_report(self):
        with patch(
            "src.generate_report.REPORTS_DIR",
            Path(self.temp_dir.name)
        ):
            output_path = save_mitre_csv_report(
                self.enrichment_results
            )

        self.assertTrue(output_path.exists())

        with open(
            output_path,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:
            rows = list(
                csv.DictReader(file)
            )

        self.assertEqual(
            len(rows),
            1
        )

        self.assertEqual(
            rows[0]["technique_id"],
            "T1110"
        )

        self.assertEqual(
            rows[0]["name"],
            "Brute Force"
        )

        self.assertEqual(
            rows[0]["tactics"],
            "credential-access"
        )

        self.assertEqual(
            rows[0]["matched_keywords"],
            "brute force; failed login"
        )

        self.assertIn(
            "brute force",
            rows[0]["description"]
        )

    def test_generate_text_report(self):
        with patch(
            "src.generate_report.REPORTS_DIR",
            Path(self.temp_dir.name)
        ):
            output_path = generate_text_report(
                self.enrichment_results
            )

        self.assertTrue(output_path.exists())

        content = output_path.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "THREAT INTELLIGENCE ENRICHMENT REPORT",
            content
        )

        self.assertIn(
            "Overall Risk: MEDIUM",
            content
        )

        self.assertIn(
            "Techniques Identified: 1",
            content
        )

        self.assertIn(
            "T1110 - Brute Force",
            content
        )

        self.assertIn(
            "Tactics: credential-access",
            content
        )

        self.assertIn(
            "Evidence: brute force, failed login",
            content
        )

        self.assertNotIn(
            "Description:",
            content
        )

        self.assertIn(
            "8.8.8.8",
            content
        )

        self.assertIn(
            "malicious-example.com",
            content
        )

    def test_generate_text_report_without_mitre(self):
        data = dict(
            self.enrichment_results
        )

        data["mitre_attack"] = []

        with patch(
            "src.generate_report.REPORTS_DIR",
            Path(self.temp_dir.name)
        ):
            output_path = generate_text_report(
                data
            )

        content = output_path.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "Techniques Identified: 0",
            content
        )

        self.assertIn(
            "No MITRE ATT&CK techniques identified.",
            content
        )

    def test_generate_all_reports(self):
        with patch(
            "src.generate_report.REPORTS_DIR",
            Path(self.temp_dir.name)
        ):
            report_paths = generate_all_reports(
                self.enrichment_results
            )

        self.assertEqual(
            set(report_paths.keys()),
            {
                "json",
                "csv",
                "mitre_csv",
                "text",
            }
        )

        for path in report_paths.values():
            self.assertTrue(
                path.exists()
            )


if __name__ == "__main__":
    unittest.main()