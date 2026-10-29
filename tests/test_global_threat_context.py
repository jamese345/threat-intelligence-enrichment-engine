import unittest

from src.risk_context import (
    interpret_global_context,
    determine_ioc_risk,
    generate_recommendation
)


class TestGlobalThreatContext(unittest.TestCase):

    def test_high_threat_context(self):

        context = {
            "status": "success",
            "band": "HIGH",
            "score": 75
        }

        result = interpret_global_context(
            context
        )

        self.assertTrue(
            result["context_available"]
        )

        self.assertEqual(
            result["urgency_modifier"],
            "HIGH"
        )

    def test_critical_threat_context(self):

        context = {
            "status": "success",
            "band": "CRITICAL",
            "score": 90
        }

        result = interpret_global_context(
            context
        )

        self.assertEqual(
            result["urgency_modifier"],
            "VERY_HIGH"
        )

    def test_elevated_threat_context(self):

        context = {
            "status": "success",
            "band": "ELEVATED",
            "score": 65
        }

        result = interpret_global_context(
            context
        )

        self.assertEqual(
            result["urgency_modifier"],
            "MODERATE"
        )

    def test_unavailable_context(self):

        context = {
            "status": "error",
            "error": "ICHI unavailable"
        }

        result = interpret_global_context(
            context
        )

        self.assertFalse(
            result["context_available"]
        )

        self.assertEqual(
            result["urgency_modifier"],
            "UNKNOWN"
        )

    def test_high_ioc_risk(self):

        result = determine_ioc_risk({
            "status": "success",
            "pulse_count": 15,
            "reputation": 1
        })

        self.assertEqual(
            result["ioc_risk"],
            "HIGH"
        )

        self.assertEqual(
            result["confidence"],
            "HIGH"
        )

    def test_medium_ioc_risk(self):

        result = determine_ioc_risk({
            "status": "success",
            "pulse_count": 5,
            "reputation": 0
        })

        self.assertEqual(
            result["ioc_risk"],
            "MEDIUM"
        )

    def test_unknown_ioc_risk(self):

        result = determine_ioc_risk({
            "status": "success",
            "pulse_count": 0,
            "reputation": 0
        })

        self.assertEqual(
            result["ioc_risk"],
            "UNKNOWN"
        )

    def test_high_risk_high_global_threat(self):

        recommendation = generate_recommendation(
            "HIGH",
            "HIGH"
        )

        self.assertEqual(
            recommendation,
            "ESCALATE"
        )

    def test_medium_risk_high_global_threat(self):

        recommendation = generate_recommendation(
            "MEDIUM",
            "HIGH"
        )

        self.assertEqual(
            recommendation,
            "INVESTIGATE"
        )

    def test_unknown_risk_high_global_threat(self):

        recommendation = generate_recommendation(
            "UNKNOWN",
            "HIGH"
        )

        self.assertEqual(
            recommendation,
            "REVIEW"
        )


if __name__ == "__main__":
    unittest.main()