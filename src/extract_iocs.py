import re
import ipaddress


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


def extract_ips(text):
    candidates = IP_PATTERN.findall(text)

    valid_ips = []

    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            continue

    return list(dict.fromkeys(valid_ips))

def extract_domains(text):
    return list(dict.fromkeys(DOMAIN_PATTERN.findall(text)))


def extract_urls(text):
    return list(dict.fromkeys(URL_PATTERN.findall(text)))


def extract_hashes(text):
    return {
        "md5": list(dict.fromkeys(MD5_PATTERN.findall(text))),
        "sha1": list(dict.fromkeys(SHA1_PATTERN.findall(text))),
        "sha256": list(dict.fromkeys(SHA256_PATTERN.findall(text))),
    }


def extract_iocs(text):
    return {
        "ips": extract_ips(text),
        "domains": extract_domains(text),
        "urls": extract_urls(text),
        "hashes": extract_hashes(text),
    }