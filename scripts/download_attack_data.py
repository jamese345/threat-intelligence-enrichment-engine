from pathlib import Path
from urllib.request import urlopen


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_FILE = DATA_DIR / "enterprise-attack.json"

ATTACK_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def download_attack_data():
    DATA_DIR.mkdir(exist_ok=True)

    print("Downloading MITRE ATT&CK Enterprise dataset...")

    with urlopen(ATTACK_URL, timeout=60) as response:
        data = response.read()

    OUTPUT_FILE.write_bytes(data)

    size_mb = len(data) / (1024 * 1024)

    print(
        f"MITRE ATT&CK dataset downloaded successfully "
        f"({size_mb:.2f} MB)."
    )
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    download_attack_data()