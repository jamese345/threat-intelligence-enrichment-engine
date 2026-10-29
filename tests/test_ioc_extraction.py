import unittest

from src.extract_iocs import (
    extract_ips,
    extract_domains,
    extract_urls,
    extract_hashes,
    extract_iocs,
)


class TestIOCExtraction(unittest.TestCase):

    def setUp(self):
        self.text = """
        Connection from 185.199.108.153
        to 10.0.0.25.

        Suspicious domain:
        evil-example.com

        URL:
        https://malicious-example.com/login

        MD5:
        44d88612fea8a8f36de82e1278abb02f

        SHA1:
        0123456789abcdef0123456789abcdef01234567

        SHA256:
        0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        """

    def test_extract_ips(self):
        ips = extract_ips(self.text)

        self.assertIn("185.199.108.153", ips)
        self.assertIn("10.0.0.25", ips)

    def test_extract_domains(self):
        domains = extract_domains(self.text)

        self.assertIn("evil-example.com", domains)

    def test_extract_urls(self):
        urls = extract_urls(self.text)

        self.assertIn(
            "https://malicious-example.com/login",
            urls
        )

    def test_extract_hashes(self):
        hashes = extract_hashes(self.text)

        self.assertEqual(len(hashes["md5"]), 1)
        self.assertEqual(len(hashes["sha1"]), 1)
        self.assertEqual(len(hashes["sha256"]), 1)

    def test_extract_all_iocs(self):
        results = extract_iocs(self.text)

        self.assertIn("ips", results)
        self.assertIn("domains", results)
        self.assertIn("urls", results)
        self.assertIn("hashes", results)

    def test_invalid_ip_is_ignored(self):
        text = "Suspicious IP: 999.999.999.999"

        ips = extract_ips(text)

        self.assertEqual(ips, [])


if __name__ == "__main__":
    unittest.main()