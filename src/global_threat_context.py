import requests


ICHI_URL = "https://ichi.global/api/current-index"


class GlobalThreatContextError(Exception):
    """Raised when the global threat context cannot be retrieved."""


def get_global_threat_context():
    try:
        response = requests.get(
            ICHI_URL,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        current = data.get("current", {})

        return {
            "source": "ICHI",
            "score": current.get("score"),
            "rounded_score": current.get("rounded"),
            "band": current.get("band"),
            "evaluation_id": current.get(
                "evaluation_id"
            ),
            "epoch": current.get("epoch"),
            "served_at": data.get("served_at"),
            "headline_state": data.get(
                "headline_state"
            ),
            "headline_reason": data.get(
                "headline_reason"
            ),
            "status": "success"
        }

    except requests.exceptions.Timeout as exc:
        raise GlobalThreatContextError(
            "ICHI request timed out."
        ) from exc

    except requests.exceptions.RequestException as exc:
        raise GlobalThreatContextError(
            f"ICHI request failed: {exc}"
        ) from exc

    except ValueError as exc:
        raise GlobalThreatContextError(
            "ICHI returned invalid JSON."
        ) from exc