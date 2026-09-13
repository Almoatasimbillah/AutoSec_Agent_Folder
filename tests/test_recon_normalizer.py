"""Unit tests for Asset Normalizer & Deduplicator (Doc 17)."""

import pytest
from src.recon.normalizer import AssetNormalizer


def test_domain_normalization():
    assert AssetNormalizer.normalize_domain("API.Example.COM.") == "api.example.com"
    assert AssetNormalizer.normalize_domain("https://dev.portal.target.com/v1/api") == "dev.portal.target.com"
    assert AssetNormalizer.normalize_domain("sub.target.com:8443") == "sub.target.com"


def test_url_normalization():
    # Strips default port 443 on https
    assert AssetNormalizer.normalize_url("https://api.example.com:443/login/") == "https://api.example.com/login/"
    # Strips default port 80 on http
    assert AssetNormalizer.normalize_url("http://example.com:80/") == "http://example.com/"
    # Removes fragments
    assert AssetNormalizer.normalize_url("https://example.com/page#section") == "https://example.com/page"
    # Deduplicates slashes in path
    assert AssetNormalizer.normalize_url("https://example.com//api///users") == "https://example.com/api/users"


def test_ip_normalization():
    assert AssetNormalizer.normalize_ip("192.168.1.1") == "192.168.1.1"
    assert AssetNormalizer.normalize_ip("10.0.0.1:8080") == "10.0.0.1"
    assert AssetNormalizer.normalize_ip("invalid_ip") is None


def test_deduplication():
    items = ["api.example.com", "dev.example.com", "api.example.com", "test.example.com"]
    deduped = AssetNormalizer.deduplicate(items)
    assert deduped == ["api.example.com", "dev.example.com", "test.example.com"]
