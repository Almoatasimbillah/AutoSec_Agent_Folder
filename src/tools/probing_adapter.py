"""HTTP/Service Probing Tool Adapter (Doc 04, Doc 17).

Tests live status, TLS certificates, redirects, and extracts technologies for targets.
"""

import time
import httpx
from typing import Optional, List, Dict, Any
from .base import BaseToolAdapter, ToolContract, ToolCapability, ToolExecutionRequest, ToolExecutionResult
from ..recon.tech_detector import TechnologyDetector
from ..models.enums import RiskLevel


class HttpProbingAdapter(BaseToolAdapter):
    """High-performance async HTTP/HTTPS probing engine."""

    def __init__(self, proxy_url: Optional[str] = None):
        self.proxy_url = proxy_url

    def get_contract(self) -> ToolContract:
        return ToolContract(
            name="native_http_prober",
            version="1.0.0",
            capability=ToolCapability.HTTP_PROBING,
            risk_level=RiskLevel.LOW,
            timeout_seconds=15,
            requires_network=True,
            supported_os=["windows", "linux", "darwin"]
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        start_time = time.time()
        target = request.target.strip()
        
        # Test candidate schemes
        urls_to_test = []
        if target.startswith(("http://", "https://")):
            urls_to_test.append(target)
        else:
            urls_to_test.extend([f"https://{target}", f"http://{target}"])

        headers = request.parameters.get("headers", {})
        if request.injected_headers:
            headers.update(request.injected_headers)

        observations: List[Dict[str, Any]] = []
        live_endpoint: Optional[str] = None
        raw_outputs: List[str] = []

        async with httpx.AsyncClient(
            proxy=self.proxy_url,
            verify=False,
            timeout=8.0,
            follow_redirects=True
        ) as client:
            for url in urls_to_test:
                try:
                    t0 = time.time()
                    resp = await client.get(url, headers=headers)
                    duration_ms = int((time.time() - t0) * 1000)

                    # Extract technologies
                    technologies = TechnologyDetector.detect_from_response(
                        headers=dict(resp.headers),
                        cookies=dict(resp.cookies),
                        body=resp.text[:10000]
                    )

                    obs = {
                        "url": str(resp.url),
                        "original_url": url,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "server": resp.headers.get("server", ""),
                        "technologies": technologies,
                        "response_time_ms": duration_ms,
                        "is_live": True
                    }
                    observations.append(obs)
                    live_endpoint = str(resp.url)
                    raw_outputs.append(f"Probe {url} -> {resp.status_code} ({duration_ms}ms) | Tech: {technologies}")
                    # If HTTPS works, we prefer it
                    if url.startswith("https://") and resp.status_code < 500:
                        break

                except Exception as ex:
                    observations.append({
                        "original_url": url,
                        "is_live": False,
                        "error": str(ex)
                    })

        total_duration = time.time() - start_time
        success = any(obs.get("is_live") for obs in observations)

        return ToolExecutionResult(
            success=success,
            tool_name="native_http_prober",
            target=target,
            observations=observations,
            raw_output="\n".join(raw_outputs) if raw_outputs else "Host unreachable or timed out.",
            execution_time_seconds=total_duration,
            evidence_artifacts=[{
                "probe_results": observations,
                "preferred_endpoint": live_endpoint
            }]
        )

    def health_check(self) -> bool:
        return True
