from mitreattack.stix20 import MitreAttackData
from pathlib import Path

class MitreAttackMapper:
    """Query MITRE ATT&CK Enterprise techniques."""

    def __init__(self, attack_data_path):
        self.attack_data = MitreAttackData(attack_data_path)

    def get_technique(self, technique_id):
        """Return detailed MITRE ATT&CK technique information."""

        technique = self.attack_data.get_object_by_attack_id(
            technique_id,
            "attack-pattern"
        )

        if not technique:
            return None

        tactics = []

        for phase in getattr(technique, "kill_chain_phases", []):
            if phase.kill_chain_name == "mitre-attack":
                tactics.append(phase.phase_name)

        return {
            "technique_id": technique_id,
            "name": technique.name,
            "description": technique.description,
            "tactics": tactics,
        }
    def enrich_technique(self, technique_id):
        """Create a SOC-ready MITRE ATT&CK enrichment result."""

        technique = self.get_technique(technique_id)

        if not technique:
            return {
                "technique_id": technique_id,
                "found": False,
                "error": "MITRE ATT&CK technique not found.",
            }

        return {
            "technique_id": technique["technique_id"],
            "name": technique["name"],
            "tactics": technique["tactics"],
            "description": technique["description"],
            "found": True,
        }
    def map_alert_to_techniques(self, alert_text):
        """Map alert text to MITRE ATT&CK techniques."""

        if not alert_text or not isinstance(alert_text, str):
            return []

        text = alert_text.lower()

        technique_rules = {
            "T1110": [
                "brute force",
                "failed login",
                "failed logins",
                "password guessing",
                "credential stuffing",
                "password spraying",
            ],
            "T1078": [
                "valid account",
                "compromised account",
                "stolen credentials",
                "account takeover",
            ],
            "T1059": [
                "command shell",
                "powershell",
                "command execution",
                "cmd.exe",
                "script execution",
            ],
            "T1087": [
                "account discovery",
                "user discovery",
                "enumerate users",
                "enumerating users",
            ],
            "T1003": [
                "credential dumping",
                "password hash",
                "lsass",
                "sam database",
            ],
        }

        matched_techniques = []

        for technique_id, keywords in technique_rules.items():

            if any(keyword in text for keyword in keywords):

                technique = self.enrich_technique(
                    technique_id
                )

                if technique.get("found"):
                    technique["matched_keywords"] = [
                        keyword
                        for keyword in keywords
                        if keyword in text
                    ]

                    matched_techniques.append(
                        technique
                    )

        return matched_techniques


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    attack_data_path = (
        project_root / "data" / "enterprise-attack.json"
    )

    mapper = MitreAttackMapper(
        str(attack_data_path)
    )

    alert = """
    Multiple failed login attempts detected from
    185.10.10.25 against the admin account.
    Possible brute force attack.
    """

    results = mapper.map_alert_to_techniques(alert)

    print("\n=== MITRE ATT&CK ALERT MAPPING ===")

    for result in results:

        print(
            f"\nTechnique ID: "
            f"{result['technique_id']}"
        )

        print(
            f"Technique: "
            f"{result['name']}"
        )

        print(
            f"Tactics: "
            f"{', '.join(result['tactics'])}"
        )

        print(
            f"Matched keywords: "
            f"{', '.join(result['matched_keywords'])}"
        )