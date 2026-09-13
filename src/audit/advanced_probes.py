"""Advanced API Security Auditing Engine (Doc 07, Doc 15, Doc 18).

Implements non-destructive auditing modules covering:
1. IDOR / BOLA (Broken Object Level Authorization) across predictable numerical endpoints.
2. JavaScript Client Bundle Secret & Hidden Endpoint Harvester.
3. Mass Assignment Parameter Reflection Auditing.
"""

import re
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin
import httpx
from pydantic import BaseModel

from ..models.entities import Finding
from ..models.enums import FindingSeverity


class AdvancedAuditResult(BaseModel):
    idor_findings: List[Finding] = []
    discovered_secrets: List[Dict[str, str]] = []
    hidden_endpoints: List[str] = []
    mass_assignment_findings: List[Finding] = []


class AdvancedApiAuditor:
    """Automated, safe, non-destructive auditor for modern API vulnerabilities."""

    def __init__(self, researcher_tag: str = "almoatasem_bellah"):
        self.researcher_tag = researcher_tag
        self.default_headers = {
            "User-Agent": "AutonomousSecurityAuditor/1.0",
            "X-Security-Research": researcher_tag,
            "Accept": "application/json, text/plain, */*"
        }

    async def audit_idor_bola(self, base_url: str) -> List[Finding]:
        """Probe common REST API patterns for object enumeration without authentication."""
        findings = []
        candidates = [
            ("/api/Users/1", "User Record IDOR Probe"),
            ("/api/Feedbacks/1", "Customer Feedback Object Exposure"),
            ("/api/Challenges/1", "Challenge Metadata Exposure"),
            ("/rest/basket/1", "User Shopping Basket IDOR Probe")
        ]

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            for endpoint_path, desc in candidates:
                target_url = urljoin(base_url, endpoint_path)
                try:
                    resp = await client.get(target_url, headers=self.default_headers)
                    # If endpoint responds 200 OK and contains structured record data
                    if resp.status_code == 200 and ("application/json" in resp.headers.get("content-type", "") or resp.text.startswith("{") or resp.text.startswith("[")):
                        # Verify it has data
                        if len(resp.text) > 30 and ("id" in resp.text.lower() or "data" in resp.text.lower() or "status" in resp.text.lower()):
                            findings.append(Finding(
                                engagement_id="active",
                                title=f"BOLA / Insecure Direct Object Reference on {endpoint_path}",
                                severity=FindingSeverity.HIGH,
                                affected_asset=target_url,
                                reproduction_steps=(
                                    f"1. Send an unauthenticated GET request to {target_url}.\n"
                                    f"2. Header injected: X-Security-Research: {self.researcher_tag}\n"
                                    f"3. Target server returns HTTP 200 OK containing serialized object data without authorization checks."
                                ),
                                remediation_advice=(
                                    "Implement strict server-side authorization checks verifying that the requesting session "
                                    "owns or has explicit role permission to access the requested resource ID."
                                )
                            ))
                except Exception:
                    continue

        return findings

    async def harvest_js_secrets(self, base_url: str) -> Dict[str, Any]:
        """Harvest scripts from target homepage and extract leaked tokens & hidden endpoints."""
        discovered_secrets = []
        hidden_endpoints = set()

        script_urls = set()
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            # 1. Fetch home HTML to locate script files
            try:
                html_resp = await client.get(base_url, headers=self.default_headers)
                if html_resp.status_code == 200:
                    # Extract script tags
                    matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_resp.text, re.IGNORECASE)
                    for m in matches:
                        if not m.startswith("http"):
                            full_js_url = urljoin(base_url, m)
                        else:
                            full_js_url = m
                        # Only target same-origin scripts
                        if any(domain in full_js_url for domain in ["owasp-juice.shop", "localhost", "127.0.0.1"]):
                            script_urls.add(full_js_url)
            except Exception:
                pass

            # Fallback to common single-page app bundles if none extracted
            if not script_urls:
                for bundle in ["main.js", "runtime.js", "polyfills.js", "vendor.js"]:
                    script_urls.add(urljoin(base_url, bundle))

            # 2. Inspect script content
            secret_patterns = [
                ("AWS API Key", r'AKIA[0-9A-Z]{16}'),
                ("Google API Key", r'AIza[0-9A-Za-z\-_]{35}'),
                ("JWT Token", r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
                ("Hardcoded Password", r'(?:password|passwd|secret)\s*[:=]\s*["\']([^"\']{6,})["\']'),
                ("Authorization Bearer", r'Bearer\s+[a-zA-Z0-9\._\-]{20,}')
            ]
            endpoint_pattern = r'["\'](/(?:api|rest|admin|ftp|metrics)/[a-zA-Z0-9_\-/]+)["\']'

            for s_url in list(script_urls)[:4]:  # limit to first 4 bundles to prevent rate issues
                try:
                    js_resp = await client.get(s_url, headers=self.default_headers)
                    if js_resp.status_code == 200 and len(js_resp.text) > 50:
                        content = js_resp.text
                        # Find endpoints
                        for ep in re.findall(endpoint_pattern, content):
                            hidden_endpoints.add(ep)

                        # Find secrets
                        for sec_name, sec_regex in secret_patterns:
                            for match in re.finditer(sec_regex, content):
                                discovered_secrets.append({
                                    "type": sec_name,
                                    "match": match.group(0)[:60],
                                    "source_script": s_url
                                })
                except Exception:
                    continue

        return {
            "secrets": discovered_secrets,
            "hidden_endpoints": sorted(list(hidden_endpoints))
        }

    async def audit_mass_assignment(self, base_url: str) -> List[Finding]:
        """Test user profile or registration endpoints against unauthorized role elevation."""
        findings = []
        target_url = urljoin(base_url, "/api/Users")
        probe_payload = {
            "email": "audit_probe_test@security-research.local",
            "password": "ProbePassword123!",
            "role": "admin",
            "isAdmin": True
        }

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            try:
                resp = await client.post(
                    target_url,
                    json=probe_payload,
                    headers=self.default_headers
                )
                # If accepted with 200 or 201 and echoes back the role or admin flag
                if resp.status_code in [200, 201] and ("\"role\"" in resp.text or "\"isAdmin\"" in resp.text):
                    findings.append(Finding(
                        engagement_id="active",
                        title="Mass Assignment Vulnerability on User Registration",
                        severity=FindingSeverity.HIGH,
                        affected_asset=target_url,
                        reproduction_steps=(
                            f"1. Send a POST request to {target_url} with JSON payload containing 'role': 'admin' and 'isAdmin': true.\n"
                            f"2. Header injected: X-Security-Research: {self.researcher_tag}\n"
                            f"3. Server processed the object and preserved elevated privilege fields in the created entity."
                        ),
                        remediation_advice=(
                            "Use strict Data Transfer Objects (DTOs) and request schemas that allowlist only expected fields "
                            "(e.g., email, password) and disallow binding privileged attributes like 'role' or 'isAdmin'."
                        )
                    ))
            except Exception:
                pass

        return findings
