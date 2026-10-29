import unittest
import requests
from unittest.mock import MagicMock, patch

from src.threat_intelligence import (
    make_request,
    normalize_result,
    safe_enrich,
    ThreatIntelligenceError,
)


class TestThreatIntelligence(unittest.TestCase):

    def test_normalize_result(self):
        data = {
            "reputation": 1,
            "pulse_info": {
                "count": 5
            }
        }

        result = normalize_result(
            "8.8.8.8",
            "ipv4",
            data
        )

        self.assertEqual(
            result["indicator"],
            "8.8.8.8"
        )

        self.assertEqual(
            result["indicator_type"],
            "ipv4"
        )

        self.assertEqual(
            result["pulse_count"],
            5
        )

        self.assertEqual(
            result["reputation"],
            1
        )

        self.assertEqual(
            result["source"],
            "AlienVault OTX"
        )

        self.assertEqual(
            result["status"],
            "success"
        )

    @patch(
        "src.threat_intelligence.enrich_ip"
    )
    def test_successful_enrichment(self, mock_enrich):

        mock_enrich.return_value = {
            "indicator": "8.8.8.8",
            "indicator_type": "ipv4",
            "source": "AlienVault OTX",
            "pulse_count": 3,
            "reputation": 1,
            "raw_data_available": True,
            "status": "success",
        }

        result = safe_enrich(
            "8.8.8.8",
            "ipv4"
        )

        self.assertEqual(
            result["indicator"],
            "8.8.8.8"
        )

        self.assertEqual(
            result["status"],
            "success"
        )

    @patch(
        "src.threat_intelligence.enrich_ip"
    )
    def test_api_failure(self, mock_enrich):

        mock_enrich.side_effect = ThreatIntelligenceError(
            "OTX request timed out."
        )

        result = safe_enrich(
            "8.8.8.8",
            "ipv4"
        )

        self.assertEqual(
            result["status"],
            "error"
        )

        self.assertIn(
            "timed out",
            result["error"]
        )

    @patch("src.threat_intelligence.requests.get")
    def test_invalid_json_response(self, mock_get):
        mock_response = MagicMock()

        mock_response.raise_for_status.return_value = None

        mock_response.json.side_effect = ValueError(
            "Invalid JSON"
        )

        mock_get.return_value = mock_response

        with self.assertRaises(ThreatIntelligenceError):
            make_request("indicators/IPv4/8.8.8.8/general")


    @patch("src.threat_intelligence.requests.get")
    def test_unexpected_response_format(self, mock_get):
        mock_response = MagicMock()

        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = []

        mock_get.return_value = mock_response

        with self.assertRaises(ThreatIntelligenceError):
            make_request("indicators/IPv4/8.8.8.8/general")


    @patch("src.threat_intelligence.requests.get")
    def test_timeout_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout()

        with self.assertRaises(ThreatIntelligenceError):
            make_request("indicators/IPv4/8.8.8.8/general")

    def test_unsupported_indicator_type(self):
        result = safe_enrich(
            "example",
            "unsupported_type"
        )

        self.assertEqual(
            result["status"],
            "unsupported"
        )

        self.assertIn(
            "error",
            result
        )


if __name__ == "__main__":
    unittest.main()