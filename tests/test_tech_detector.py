"""Unit tests for Technology Fingerprinting Engine (Doc 06 & Doc 17)."""

import pytest
from src.recon.tech_detector import TechnologyDetector


def test_server_header_detection():
    headers = {"Server": "cloudflare", "Content-Type": "text/html"}
    techs = TechnologyDetector.detect_from_response(headers=headers)
    assert "Cloudflare" in techs


def test_framework_detection_from_headers_and_cookies():
    headers = {"Server": "nginx/1.18.0", "X-Powered-By": "Express"}
    cookies = {"connect.sid": "s%3A123456"}
    techs = TechnologyDetector.detect_from_response(headers=headers, cookies=cookies)
    assert "Nginx" in techs
    assert "Express.js" in techs


def test_django_detection_from_cookies():
    headers = {"Server": "gunicorn"}
    cookies = {"csrftoken": "abcd1234efgh"}
    techs = TechnologyDetector.detect_from_response(headers=headers, cookies=cookies)
    assert "Gunicorn" in techs
    assert "Django" in techs


def test_body_heuristic_detection():
    body = "<html><head><script src='/wp-content/themes/theme.js'></script></head><body>Hello</body></html>"
    techs = TechnologyDetector.detect_from_response(headers={}, body=body)
    assert "WordPress" in techs
