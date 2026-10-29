import unittest

from src.normalize_iocs import (
    normalize_ip,
    normalize_domain,
    normalize_url,
    normalize_hash,
    normalize_iocs,
)


class TestNormalizeIOCs(unittest.TestCase):

    def test_normalize_ip(self):
        self.assertEqual(
            normalize_ip("  8.8.8.8  "),
            "8.8.8.8"
        )

    def test_normalize_domain(self):
        self.assertEqual(
            normalize_domain("WWW.Example.COM."),
            "example.com"
        )

    def test_normalize_url(self):
        self.assertEqual(
            normalize_url(
                "HTTPS://Example.COM/login/"
            ),
            "https://example.com/login"
        )

    def test_normalize_hash(self):
        self.assertEqual(
            normalize_hash(
                " ABCDEF1234567890ABCDEF1234567890 "
            ),
            "abcdef1234567890abcdef1234567890"
        )

    def test_deduplicate_iocs(self):
        iocs = {
            "ips": [
                "8.8.8.8",
                "8.8.8.8",
                " 8.8.8.8 ",
            ],
            "domains": [
                "Example.COM",
                "example.com",
                "www.example.com",
            ],
            "urls": [
                "https://Example.COM/login/",
                "https://example.com/login/",
            ],
            "hashes": {
                "md5": [
                    "ABCDEF1234567890ABCDEF1234567890",
                    "abcdef1234567890abcdef1234567890",
                ],
                "sha1": [],
                "sha256": [],
            },
        }

        result = normalize_iocs(iocs)

        self.assertEqual(
            result["ips"],
            ["8.8.8.8"]
        )

        self.assertEqual(
            result["domains"],
            ["example.com"]
        )

        self.assertEqual(
            result["urls"],
            ["https://example.com/login"]
        )

        self.assertEqual(
            result["hashes"]["md5"],
            ["abcdef1234567890abcdef1234567890"]
        )


if __name__ == "__main__":
    unittest.main()