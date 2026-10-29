import unittest
from unittest.mock import patch
from src.global_threat_context import GlobalThreatContextError
from src.enrichment import enrich_alert, get_safe_global_context


class TestEnrichment(unittest.TestCase):

    @patch(
        "src.enrichment.safe_enrich"
    )
    def test_enrich_alert(self, mock_enrich):

        mock_enrich.side_effect = (
            lambda indicator, indicator_type: {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "status": "success"
            }
        )

        alert = """
        Connection from 8.8.8.8
        to malicious-example.com

        URL:
        https://malicious-example.com/login
        """

        result = enrich_alert(alert)

        self.assertGreater(
            result["ioc_count"],
            0
        )

        self.assertEqual(
            result["ioc_count"],
            len(result["results"])
        )

    def test_duplicate_iocs_are_deduplicated(self):
        alert = """
        Connection from 8.8.8.8
        Connection from 8.8.8.8
        Connection from 8.8.8.8
        """

        with patch("src.enrichment.safe_enrich") as mock_enrich:
            mock_enrich.return_value = {
                "indicator": "8.8.8.8",
                "indicator_type": "ipv4",
                "status": "success",
            }

            result = enrich_alert(alert)

            self.assertEqual(result["ioc_count"], 1)
            mock_enrich.assert_called_once_with(
                "8.8.8.8",
                "ipv4"
            )
    @patch("src.enrichment.get_safe_global_context")
    def test_empty_alert(self, mock_global_context):
        mock_global_context.return_value = {
            "source": "ICHI",
            "status": "success",
            "score": 50,
            "band": "ELEVATED",
        }

        result = enrich_alert("")

        self.assertEqual(
            result["ioc_count"],
            0
        )

        self.assertEqual(
            result["results"],
            []
        )


    @patch("src.enrichment.get_safe_global_context")
    def test_none_alert(self, mock_global_context):
        mock_global_context.return_value = {
            "source": "ICHI",
            "status": "success",
            "score": 50,
            "band": "ELEVATED",
        }

        result = enrich_alert(None)

        self.assertEqual(
            result["ioc_count"],
            0
        )

    @patch("src.enrichment.get_global_threat_context")
    def test_global_context_failure(self, mock_context):
        mock_context.side_effect = GlobalThreatContextError(
            "ICHI unavailable"
        )

        result = get_safe_global_context()

        self.assertEqual(
            result["status"],
            "error"
        )

        self.assertIn(
            "ICHI unavailable",
            result["error"]
        )


if __name__ == "__main__":
    unittest.main()