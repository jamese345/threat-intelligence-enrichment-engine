from urllib.parse import urlparse


def normalize_ip(ip):
    """Normalize an IPv4 address."""
    return ip.strip()


def normalize_domain(domain):
    """Normalize a domain name."""
    domain = domain.strip().lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain.rstrip(".")


def normalize_url(url):
    """Normalize a URL while preserving its path."""
    url = url.strip()

    parsed = urlparse(url)

    if not parsed.scheme:
        return url.lower().rstrip("/")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    normalized = f"{scheme}://{netloc}{path}"

    if parsed.query:
        normalized += f"?{parsed.query}"

    return normalized


def normalize_hash(file_hash):
    """Normalize a file hash."""
    return file_hash.strip().lower()


def normalize_iocs(iocs):
    """
    Normalize and deduplicate extracted IOCs.
    """

    normalized = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    }

    normalized["ips"] = sorted({
        normalize_ip(ip)
        for ip in iocs.get("ips", [])
    })

    normalized["domains"] = sorted({
        normalize_domain(domain)
        for domain in iocs.get("domains", [])
    })

    normalized["urls"] = sorted({
        normalize_url(url)
        for url in iocs.get("urls", [])
    })

    for hash_type in normalized["hashes"]:
        normalized["hashes"][hash_type] = sorted({
            normalize_hash(file_hash)
            for file_hash in iocs.get(
                "hashes", {}
            ).get(hash_type, [])
        })

    return normalized