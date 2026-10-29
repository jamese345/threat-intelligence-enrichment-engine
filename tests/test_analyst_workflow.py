import unittest

from src.analyst_workflow import (
    calculate_risk_summary,
    calculate_overall_confidence,
    determine_analyst_action,
    generate_analyst_summary,
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


if __name__ == "__main__":
    unittest.main()