import unittest
from pathlib import Path

from src.mitre_attack import MitreAttackMapper


class TestMitreAttack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        project_root = Path(__file__).resolve().parent.parent

        attack_data_path = (
            project_root
            / "data"
            / "enterprise-attack.json"
        )

        cls.mapper = MitreAttackMapper(
            str(attack_data_path)
        )

    # ---------------------------------------------------------
    # Technique metadata tests
    # ---------------------------------------------------------

    def test_get_brute_force_technique(self):
        result = self.mapper.get_technique("T1110")

        self.assertIsNotNone(result)
        self.assertEqual(
            result["technique_id"],
            "T1110"
        )
        self.assertEqual(
            result["name"],
            "Brute Force"
        )

    def test_brute_force_tactic(self):
        result = self.mapper.get_technique("T1110")

        self.assertIn(
            "credential-access",
            result["tactics"]
        )

    def test_get_valid_accounts_technique(self):
        result = self.mapper.get_technique("T1078")

        self.assertIsNotNone(result)
        self.assertEqual(
            result["technique_id"],
            "T1078"
        )
        self.assertEqual(
            result["name"],
            "Valid Accounts"
        )

    def test_valid_accounts_tactic(self):
        result = self.mapper.get_technique("T1078")

        expected_tactics = {
            "stealth",
            "persistence",
            "privilege-escalation",
            "initial-access",
        }

        self.assertEqual(
            set(result["tactics"]),
            expected_tactics
        )

    def test_get_command_execution_technique(self):
        result = self.mapper.get_technique("T1059")

        self.assertIsNotNone(result)
        self.assertEqual(
            result["technique_id"],
            "T1059"
        )
        self.assertEqual(
            result["name"],
            "Command and Scripting Interpreter"
        )

    def test_command_execution_tactic(self):
        result = self.mapper.get_technique("T1059")

        self.assertIn(
            "execution",
            result["tactics"]
        )

    # ---------------------------------------------------------
    # Technique enrichment tests
    # ---------------------------------------------------------

    def test_enrich_technique(self):
        result = self.mapper.enrich_technique(
            "T1110"
        )

        self.assertTrue(result["found"])
        self.assertEqual(
            result["name"],
            "Brute Force"
        )

    def test_unknown_technique(self):
        result = self.mapper.enrich_technique(
            "T9999"
        )

        self.assertFalse(result["found"])

    # ---------------------------------------------------------
    # Alert mapping tests
    # ---------------------------------------------------------

    def test_alert_brute_force_mapping(self):
        alert = (
            "Multiple failed login attempts "
            "detected against the admin account. "
            "Possible brute force attack."
        )

        results = self.mapper.map_alert_to_techniques(
            alert
        )

        technique_ids = [
            result["technique_id"]
            for result in results
        ]

        self.assertIn(
            "T1110",
            technique_ids
        )

    def test_alert_valid_accounts_mapping(self):
        alert = (
            "A compromised account was used "
            "to access the internal system."
        )

        results = self.mapper.map_alert_to_techniques(
            alert
        )

        technique_ids = [
            result["technique_id"]
            for result in results
        ]

        self.assertIn(
            "T1078",
            technique_ids
        )

    def test_alert_command_execution_mapping(self):
        alert = (
            "PowerShell command execution was "
            "detected on the endpoint."
        )

        results = self.mapper.map_alert_to_techniques(
            alert
        )

        technique_ids = [
            result["technique_id"]
            for result in results
        ]

        self.assertIn(
            "T1059",
            technique_ids
        )

    def test_alert_without_mitre_match(self):
        alert = (
            "Normal user activity detected "
            "during business hours."
        )

        results = self.mapper.map_alert_to_techniques(
            alert
        )

        self.assertEqual(
            results,
            []
        )

    def test_alert_account_discovery_mapping(self):
        alert = "The attacker performed account discovery to enumerate users."

        results = self.mapper.map_alert_to_techniques(alert)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["technique_id"], "T1087")
        self.assertIn("account discovery", results[0]["matched_keywords"])


    def test_alert_credential_dumping_mapping(self):
        alert = "Possible credential dumping activity targeting LSASS."

        results = self.mapper.map_alert_to_techniques(alert)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["technique_id"], "T1003")
        self.assertIn("credential dumping", results[0]["matched_keywords"])

    def test_alert_multiple_techniques_mapping(self):
        alert = """
        Multiple failed login attempts were detected.
        The attacker used a compromised account and executed
        PowerShell commands.
        """

        results = self.mapper.map_alert_to_techniques(alert)

        technique_ids = {
            result["technique_id"]
            for result in results
        }

        self.assertEqual(
            technique_ids,
            {"T1110", "T1078", "T1059"}
        )


if __name__ == "__main__":
    unittest.main()