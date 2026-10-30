import unittest

from src.analyst_workflow import (
    calculate_risk_summary,
    calculate_overall_confidence,
    determine_analyst_action,
    generate_analyst_summary,
    summarize_mitre_techniques,
    build_analyst_assessment,
)


class TestAnalystWorkflow(unittest.TestCase):

    def test_risk_summary(self):
        results = [
            {"ioc_risk": "HIGH"},
            {"ioc_risk": "MEDIUM"},
            {"ioc_risk": "LOW"},
            {"ioc_risk": "HIGH"},
        ]

        summary = calculate_risk_summary(results)

        self.assertEqual(
            summary["overall_risk"],
            "HIGH"
        )

        self.assertEqual(
            summary["high_risk_iocs"],
            2
        )

        self.assertEqual(
            summary["medium_risk_iocs"],
            1
        )

        self.assertEqual(
            summary["low_risk_iocs"],
            1
        )

    def test_empty_risk_summary(self):
        summary = calculate_risk_summary([])

        self.assertEqual(
            summary["overall_risk"],
            "UNKNOWN"
        )

    def test_high_confidence(self):
        results = [
            {"confidence": "HIGH"},
            {"confidence": "HIGH"},
            {"confidence": "MEDIUM"},
        ]

        confidence = calculate_overall_confidence(results)

        self.assertEqual(confidence, "HIGH")

    def test_low_confidence(self):
        results = [
            {"confidence": "LOW"},
            {"confidence": "LOW"},
        ]

        confidence = calculate_overall_confidence(results)

        self.assertEqual(confidence, "LOW")

    def test_high_risk_action(self):
        action = determine_analyst_action(
            "HIGH",
            "LOW"
        )

        self.assertEqual(action, "ESCALATE")

    def test_medium_risk_high_global_context(self):
        action = determine_analyst_action(
            "MEDIUM",
            "HIGH"
        )

        self.assertEqual(action, "INVESTIGATE")

    def test_low_risk_normal_context(self):
        action = determine_analyst_action(
            "LOW",
            "LOW"
        )

        self.assertEqual(action, "MONITOR")

    def test_unknown_risk(self):
        action = determine_analyst_action(
            "UNKNOWN",
            "HIGH"
        )

        self.assertEqual(action, "REVIEW")

    def test_generate_summary(self):
        risk_summary = {
            "high_risk_iocs": 1,
            "medium_risk_iocs": 2,
            "low_risk_iocs": 1,
            "unknown_risk_iocs": 0,
        }

        summary = generate_analyst_summary(
            "HIGH",
            "HIGH",
            "ESCALATE",
            risk_summary,
        )

        self.assertIn("HIGH risk", summary)
        self.assertIn("ESCALATE", summary)

    def test_mitre_summary_empty(self):
        assessment = build_analyst_assessment(
            [],
            "LOW",
            [],
        )

        self.assertEqual(
            assessment["mitre_attack"]["technique_count"],
            0
        )

        self.assertEqual(
            assessment["mitre_attack"]["techniques"],
            []
        )

    def test_mitre_summary_single_technique(self):
        results = [
            {
                "ioc_risk": "MEDIUM",
                "confidence": "MEDIUM",
            }
        ]

        mitre_techniques = [
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "tactics": ["credential-access"],
                "matched_keywords": [
                    "brute force",
                    "failed login",
                ],
            }
        ]

        assessment = build_analyst_assessment(
            results,
            "MODERATE",
            mitre_techniques,
        )

        mitre = assessment["mitre_attack"]

        self.assertEqual(
            mitre["technique_count"],
            1
        )

        self.assertEqual(
            mitre["techniques"][0]["technique_id"],
            "T1110"
        )

        self.assertEqual(
            mitre["techniques"][0]["name"],
            "Brute Force"
        )

    def test_mitre_summary_multiple_techniques(self):
        results = [
            {
                "ioc_risk": "HIGH",
                "confidence": "HIGH",
            }
        ]

        mitre_techniques = [
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "tactics": ["credential-access"],
                "matched_keywords": [
                    "brute force",
                ],
            },
            {
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactics": ["execution"],
                "matched_keywords": [
                    "powershell",
                ],
            },
        ]

        assessment = build_analyst_assessment(
            results,
            "HIGH",
            mitre_techniques,
        )

        mitre = assessment["mitre_attack"]

        self.assertEqual(
            mitre["technique_count"],
            2
        )

        technique_ids = [
            technique["technique_id"]
            for technique in mitre["techniques"]
        ]

        self.assertIn(
            "T1110",
            technique_ids
        )

        self.assertIn(
            "T1059",
            technique_ids
        )

    def test_mitre_evidence_preserved(self):
        results = [
            {
                "ioc_risk": "MEDIUM",
                "confidence": "MEDIUM",
            }
        ]

        mitre_techniques = [
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "tactics": ["credential-access"],
                "matched_keywords": [
                    "brute force",
                    "failed login",
                ],
            }
        ]

        assessment = build_analyst_assessment(
            results,
            "MODERATE",
            mitre_techniques,
        )

        technique = assessment[
            "mitre_attack"
        ]["techniques"][0]

        self.assertEqual(
            technique["matched_keywords"],
            [
                "brute force",
                "failed login",
            ]
        )

        self.assertEqual(
            technique["tactics"],
            ["credential-access"]
        )

    def test_complete_assessment(self):
        results = [
            {
                "ioc_risk": "HIGH",
                "confidence": "HIGH",
            },
            {
                "ioc_risk": "MEDIUM",
                "confidence": "MEDIUM",
            },
        ]

        assessment = build_analyst_assessment(
            results,
            "HIGH",
        )

        self.assertEqual(
            assessment["overall_risk"],
            "HIGH"
        )

        self.assertEqual(
            assessment["recommended_action"],
            "ESCALATE"
        )

        self.assertIn(
            "analyst_summary",
            assessment
        )

    def test_mitre_description_is_preserved(self):
        mitre_techniques = [
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts.",
                "tactics": ["credential-access"],
                "matched_keywords": ["brute force"],
            }
        ]

        result = summarize_mitre_techniques(mitre_techniques)

        self.assertEqual(result["technique_count"], 1)
        self.assertEqual(
            result["techniques"][0]["description"],
            "Adversaries may use brute force techniques to gain access to accounts."
        )


if __name__ == "__main__":
    unittest.main()