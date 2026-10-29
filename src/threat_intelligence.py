import os

import requests
from dotenv import load_dotenv


load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


class ThreatIntelligenceError(Exception):
    """Raised when a threat intelligence request fails."""


def get_headers():
    if not OTX_API_KEY:
        raise ThreatIntelligenceError(
            "OTX_API_KEY is not configured."
        )

    return {
        "X-OTX-API-KEY": OTX_API_KEY
    }

def make_request(endpoint):
    headers = get_headers()

    try:
        response = requests.get(
            f"{OTX_BASE_URL}/{endpoint}",
            headers=headers,
            timeout=10,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            raise ThreatIntelligenceError(
                "Unexpected API response format."
            )

        return data

    except requests.exceptions.Timeout as error:
        raise ThreatIntelligenceError(
            "Threat intelligence request timed out."
        ) from error

    except requests.exceptions.RequestException as error:
        raise ThreatIntelligenceError(
            f"Threat intelligence request failed: {error}"
        ) from error

    except ValueError as error:
        raise ThreatIntelligenceError(
            "Threat intelligence API returned invalid JSON."
        ) from error


def lookup_ip(ip):
    return make_request(
        f"indicators/IPv4/{ip}/general"
    )


def lookup_domain(domain):
    return make_request(
        f"indicators/domain/{domain}/general"
    )


def lookup_url(url):
    return make_request(
        f"indicators/url/{url}/general"
    )


def lookup_hash(file_hash):
    return make_request(
        f"indicators/file/{file_hash}/general"
    )


def normalize_result(
    indicator,
    indicator_type,
    data
):
    pulse_info = data.get(
        "pulse_info",
        {}
    )

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "source": "AlienVault OTX",
        "pulse_count": pulse_info.get(
            "count",
            0
        ),
        "reputation": data.get(
            "reputation",
            0
        ),
        "raw_data_available": bool(data),
        "status": "success"
    }


def enrich_ip(ip):
    data = lookup_ip(ip)

    return normalize_result(
        ip,
        "ipv4",
        data
    )


def enrich_domain(domain):
    data = lookup_domain(domain)

    return normalize_result(
        domain,
        "domain",
        data
    )


def enrich_url(url):
    data = lookup_url(url)

    return normalize_result(
        url,
        "url",
        data
    )


def enrich_hash(file_hash):
    data = lookup_hash(file_hash)

    hash_type = "hash"

    if len(file_hash) == 32:
        hash_type = "md5"

    elif len(file_hash) == 40:
        hash_type = "sha1"

    elif len(file_hash) == 64:
        hash_type = "sha256"

    return normalize_result(
        file_hash,
        hash_type,
        data
    )

def safe_enrich(indicator, indicator_type):
    try:
        if indicator_type == "ipv4":
            return enrich_ip(indicator)

        if indicator_type == "domain":
            return enrich_domain(indicator)

        if indicator_type == "url":
            return enrich_url(indicator)

        if indicator_type in {"md5", "sha1", "sha256"}:
            return enrich_hash(indicator)

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "status": "unsupported",
            "error": "Unsupported indicator type.",
        }

    except ThreatIntelligenceError as error:
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "status": "error",
            "error": str(error),
        }

