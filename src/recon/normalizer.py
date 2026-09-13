"""Asset Normalization and Deduplication Engine (Doc 17).

Normalizes domains, subdomains, IPs, URLs, and endpoints into consistent canonical
formats to eliminate duplicates before ingestion into the Target Model.
"""

import ipaddress
import re
from typing import List, Optional, Set
from urllib.parse import urlparse, urlunparse


class AssetNormalizer:
    """Canonicalizes and deduplicates security targets and discovered assets."""

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain / FQDN: lowercased, stripped of protocols and trailing dots."""
        if not domain:
            return ""
        clean = domain.strip().lower()
        if "://" in clean:
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
        # Remove path or port if present
        if "/" in clean:
            clean = clean.split("/", 1)[0]
        if ":" in clean:
            clean = clean.split(":", 1)[0]
        return clean.strip(".")

    @staticmethod
    def normalize_ip(ip_str: str) -> Optional[str]:
        """Normalize an IPv4 or IPv6 address."""
        if not ip_str:
            return None
        clean = ip_str.strip()
        if "://" in clean:
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
        if ":" in clean and not ("[" in clean or clean.count(":") > 1):
            clean = clean.split(":", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(clean)
            return str(ip_obj)
        except ValueError:
            return None

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize an HTTP/HTTPS URL:
        - Lowercases scheme and host
        - Strips default ports (:80, :443)
        - Removes fragments (#section)
        - Ensures canonical root path
        """
        if not url:
            return ""
        raw = url.strip()
        if not raw.startswith(("http://", "https://")):
            raw = f"https://{raw}"

        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Strip default ports
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        elif netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]

        path = parsed.path or "/"
        # Deduplicate consecutive slashes
        path = re.sub(r"/+", "/", path)

        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))

    @staticmethod
    def normalize_endpoint_path(path: str) -> str:
        """Normalize an endpoint path."""
        if not path:
            return "/"
        clean = path.strip()
        if not clean.startswith("/"):
            clean = "/" + clean
        clean = re.sub(r"/+", "/", clean)
        # Strip trailing slash unless it's just '/'
        if len(clean) > 1 and clean.endswith("/"):
            clean = clean[:-1]
        return clean

    @classmethod
    def deduplicate(cls, items: List[str]) -> List[str]:
        """Deduplicate string items while preserving order."""
        seen: Set[str] = set()
        unique: List[str] = []
        for item in items:
            normalized = item.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
        return unique
