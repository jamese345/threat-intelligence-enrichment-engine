import unittest
from unittest.mock import patch

from src.enrichment import enrich_alert


class TestEndToEnd(unittest.TestCase):

    @patch("src.enrichment.get_safe_global_context")
    @patch("src.enrichment.safe_enrich")
    def test_complete_pipeline(
        self,
        mock_enrich,
        mock_global_context,
    ):
        mock_global_context.return_value = {
            "source": "ICHI",
            "score": 75,
            "band": "HIGH",
            "status": "success",
        }

        mock_enrich.return_value = {
            "indicator": "8.8.8.8",
            "indicator_type": "ipv4",
            "source": "AlienVault OTX",
            "pulse_count": 15,
            "reputation": 1,
            "status": "success",
        }

        alert = """
        Suspicious connection from 8.8.8.8.
        Repeated connection from 8.8.8.8.
        """

        result = enrich_alert(alert)

        self.assertEqual(
            result["ioc_count"],
            1
        )

        self.assertEqual(
            result["analyst_assessment"]["overall_risk"],
            "HIGH"
        )

        self.assertEqual(
            result["analyst_assessment"]["recommended_action"],
            "ESCALATE"
        )


if __name__ == "__main__":
    unittest.main()