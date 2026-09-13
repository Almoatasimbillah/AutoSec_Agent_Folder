"""HTTP Engine Tool Adapter (Doc 04 & Doc 18).

Executes precise HTTP requests, captures response metadata, timing, and supports
header injection from the Policy Engine.
"""

import time
import httpx
from typing import Optional
from .base import BaseToolAdapter, ToolContract, ToolCapability, ToolExecutionRequest, ToolExecutionResult
from ..models.enums import RiskLevel


class HttpToolAdapter(BaseToolAdapter):
    """Native Async HTTP Engine built on httpx."""

    def __init__(self, proxy_url: Optional[str] = None):
        self.proxy_url = proxy_url

    def get_contract(self) -> ToolContract:
        return ToolContract(
            name="native_http_engine",
            version="1.0.0",
            capability=ToolCapability.HTTP_REQUEST,
            risk_level=RiskLevel.LOW,
            timeout_seconds=20,
            requires_network=True,
            supported_os=["windows", "linux", "darwin"]
        )

    async def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        start_time = time.time()
        method = request.parameters.get("method", "GET").upper()
        headers = request.parameters.get("headers", {})
        
        # Merge injected headers from policy
        if request.injected_headers:
            headers.update(request.injected_headers)

        params = request.parameters.get("query_params", {})
        data = request.parameters.get("data")
        timeout = request.timeout_seconds or 15.0

        try:
            async with httpx.AsyncClient(
                proxy=self.proxy_url,
                verify=False,
                timeout=timeout,
                follow_redirects=False
            ) as client:
                response = await client.request(
                    method=method,
                    url=request.target,
                    headers=headers,
                    params=params,
                    content=data
                )
                duration = time.time() - start_time

                observation = {
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "content_type": response.headers.get("content-type", ""),
                    "headers": dict(response.headers),
                    "elapsed_ms": int(duration * 1000)
                }

                return ToolExecutionResult(
                    success=True,
                    tool_name="native_http_engine",
                    target=request.target,
                    observations=[observation],
                    raw_output=response.text[:5000],  # preview
                    execution_time_seconds=duration,
                    evidence_artifacts=[{
                        "type": "http_traffic",
                        "request": f"{method} {request.target}",
                        "response_status": response.status_code,
                        "response_headers": dict(response.headers)
                    }]
                )

        except Exception as ex:
            duration = time.time() - start_time
            return ToolExecutionResult(
                success=False,
                tool_name="native_http_engine",
                target=request.target,
                error_message=str(ex),
                execution_time_seconds=duration
            )

    def health_check(self) -> bool:
        return True
