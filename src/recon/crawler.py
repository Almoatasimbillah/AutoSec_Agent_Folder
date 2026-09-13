"""Smart SPA Crawler & Route Miner (Doc 03, Doc 17).

Extracts client-side SPA routes, REST API paths, form actions, and input parameters
from HTML and modern JavaScript bundles (Angular, React, Vue, Webpack).
"""

import re
from typing import List, Dict, Set, Optional, Any
from urllib.parse import urljoin, urlparse
import httpx
from pydantic import BaseModel, Field

from ..policy.action_gate import ActionGate
from ..models.enums import RiskLevel, ActionStatus
from ..knowledge.target_model import TargetModelManager


class CrawledEndpoint(BaseModel):
    """Discovered route or API endpoint."""
    url: str
    path: str
    method: str = "GET"
    route_type: str = "REST_API"  # 'SPA_CLIENT_ROUTE', 'REST_API', 'HTML_LINK', 'FORM_ACTION'
    source: str = "html_crawler"
    parameters: List[str] = Field(default_factory=list)
    confidence: str = "HIGH"


class CrawlResult(BaseModel):
    """Aggregate result from crawling an application asset."""
    base_url: str
    discovered_endpoints: List[CrawledEndpoint] = []
    scanned_scripts: List[str] = []
    forms_count: int = 0
    client_routes_count: int = 0
    api_endpoints_count: int = 0


class SPACrawler:
    """Non-destructive, scope-enforced SPA route and endpoint crawler."""

    # Regex patterns for modern frontend routing and API calls
    ANGULAR_ROUTE_REGEX = re.compile(r'''path:\s*['"]([^'"]+)['"]''', re.IGNORECASE)
    REACT_ROUTE_REGEX = re.compile(r'''<Route[^>]+path=['"]([^'"]+)['"]''', re.IGNORECASE)
    REST_API_REGEX = re.compile(r'''['"](/(?:api|rest|v[0-9]|graphql|auth|admin|oauth|ftp)/[a-zA-Z0-9_/?&=%-]+)['"]''', re.IGNORECASE)
    QUERY_PARAM_REGEX = re.compile(r'''[?&]([a-zA-Z0-9_-]+)=''', re.IGNORECASE)
    HTML_LINK_REGEX = re.compile(r'''<a[^>]+href=['"]([^'"#]+)['"]''', re.IGNORECASE)
    HTML_FORM_REGEX = re.compile(r'''<form[^>]*action=['"]([^'"]*)['"][^>]*method=['"]?([a-zA-Z]+)?['"]?[^>]*>''', re.IGNORECASE)
    HTML_INPUT_REGEX = re.compile(r'''<input[^>]+name=['"]([^'"]+)['"]''', re.IGNORECASE)
    SCRIPT_SRC_REGEX = re.compile(r'''<script[^>]+src=['"]([^'"]+)['"]''', re.IGNORECASE)

    def __init__(self, action_gate: ActionGate, target_model: Optional[TargetModelManager] = None):
        self.action_gate = action_gate
        self.target_model = target_model
        self.default_headers = {
            "User-Agent": "AutonomousSecurityAuditor/1.0 (Crawler)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

    async def crawl_target(
        self,
        base_url: str,
        max_scripts_to_scan: int = 15,
        timeout_seconds: float = 8.0
    ) -> CrawlResult:
        """Perform full scope-checked crawl of target homepage and frontend scripts."""
        base_url = base_url.rstrip("/")
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc.lower()

        result = CrawlResult(base_url=base_url)
        seen_paths: Set[str] = set()

        # 1. Action Gate check for root URL
        gate_res = self.action_gate.validate_action(
            target=base_url,
            action_name="CRAWL_FETCH_PAGE",
            risk_level=RiskLevel.LOW,
            requires_authorization=False,
            has_valid_authorization=True
        )
        if not gate_res.passed:
            return result

        # Fetch homepage
        html_content = ""
        script_urls: Set[str] = set()

        async with httpx.AsyncClient(verify=False, timeout=timeout_seconds, follow_redirects=True) as client:
            try:
                resp = await client.get(base_url, headers=self.default_headers)
                if resp.status_code == 200:
                    html_content = resp.text
            except Exception:
                return result

            # Parse HTML links
            for m in self.HTML_LINK_REGEX.findall(html_content):
                norm_url = urljoin(base_url, m)
                parsed_link = urlparse(norm_url)
                if parsed_link.netloc.lower() == base_domain and parsed_link.path not in seen_paths:
                    seen_paths.add(parsed_link.path)
                    result.discovered_endpoints.append(CrawledEndpoint(
                        url=norm_url,
                        path=parsed_link.path,
                        method="GET",
                        route_type="HTML_LINK",
                        source="html_anchor"
                    ))

            # Parse Forms and Input fields
            for action, method in self.HTML_FORM_REGEX.findall(html_content):
                form_action = action or parsed_base.path or "/"
                full_action_url = urljoin(base_url, form_action)
                p_action = urlparse(full_action_url)
                
                inputs = self.HTML_INPUT_REGEX.findall(html_content)
                result.forms_count += 1
                if p_action.path not in seen_paths:
                    seen_paths.add(p_action.path)
                    result.discovered_endpoints.append(CrawledEndpoint(
                        url=full_action_url,
                        path=p_action.path,
                        method=(method or "POST").upper(),
                        route_type="FORM_ACTION",
                        source="html_form",
                        parameters=list(set(inputs))
                    ))

            # Extract Script bundles
            for s in self.SCRIPT_SRC_REGEX.findall(html_content):
                full_script_url = urljoin(base_url, s)
                p_script = urlparse(full_script_url)
                if p_script.netloc.lower() == base_domain or not p_script.netloc:
                    script_urls.add(full_script_url)

            # Fallback to common frontend single-page app bundles if none extracted
            if not script_urls:
                for fallback in ["main.js", "vendor.js", "runtime.js", "polyfills.js", "app.js"]:
                    script_urls.add(f"{base_url}/{fallback}")

            # 2. Inspect Scripts for SPA client routes and REST API paths
            scanned_count = 0
            for script_url in script_urls:
                if scanned_count >= max_scripts_to_scan:
                    break

                gate_script = self.action_gate.validate_action(
                    target=script_url,
                    action_name="CRAWL_FETCH_SCRIPT",
                    risk_level=RiskLevel.LOW,
                    requires_authorization=False,
                    has_valid_authorization=True
                )
                if not gate_script.passed:
                    continue

                try:
                    js_resp = await client.get(script_url, headers=self.default_headers)
                    if js_resp.status_code == 200 and len(js_resp.text) > 50:
                        scanned_count += 1
                        result.scanned_scripts.append(script_url)
                        js_text = js_resp.text

                        # Angular Routes
                        for r in self.ANGULAR_ROUTE_REGEX.findall(js_text):
                            clean_r = r.strip()
                            if clean_r and clean_r not in {"**", "", ":id"} and len(clean_r) < 60:
                                route_path = f"/{clean_r.lstrip('/')}"
                                if route_path not in seen_paths:
                                    seen_paths.add(route_path)
                                    result.client_routes_count += 1
                                    result.discovered_endpoints.append(CrawledEndpoint(
                                        url=f"{base_url}#{route_path}",
                                        path=route_path,
                                        method="GET",
                                        route_type="SPA_CLIENT_ROUTE",
                                        source=f"angular_routing ({script_url.split('/')[-1]})"
                                    ))

                        # REST APIs
                        for api_route in self.REST_API_REGEX.findall(js_text):
                            clean_api = api_route.strip()
                            raw_path = clean_api.split("?")[0]
                            if raw_path not in seen_paths and len(raw_path) < 80:
                                seen_paths.add(raw_path)
                                result.api_endpoints_count += 1
                                
                                # Extract query params if embedded
                                params = self.QUERY_PARAM_REGEX.findall(clean_api)
                                result.discovered_endpoints.append(CrawledEndpoint(
                                    url=f"{base_url}{clean_api}",
                                    path=raw_path,
                                    method="GET",
                                    route_type="REST_API",
                                    source=f"js_bundle ({script_url.split('/')[-1]})",
                                    parameters=params
                                ))
                except Exception:
                    continue

        # Ingest endpoints into TargetModelManager if available
        if self.target_model:
            apps = self.target_model.get_applications()
            app_id = apps[0].id if apps else None
            if app_id:
                for ep in result.discovered_endpoints:
                    try:
                        self.target_model.add_endpoint(
                            application_id=app_id,
                            method=ep.method,
                            path=ep.path
                        )
                    except Exception:
                        pass

        return result
