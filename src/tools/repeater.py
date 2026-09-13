"""Interactive Request Repeater Tool (Doc 06, Doc 10).

Provides a Burp Suite-style repeater mechanism that validates target scope
via the deterministic Action Gate, injects mandatory researcher headers,
executes async HTTP requests, and returns response metrics.
"""

import time
from typing import Dict, Any, Optional
from pydantic import BaseModel
import httpx

from ..policy.action_gate import ActionGate, GateCheckResult
from ..models.enums import RiskLevel, ActionStatus


class RepeaterResponse(BaseModel):
    status_code: int
    headers: Dict[str, str]
    body: str
    latency_ms: float
    is_in_scope: bool
    gate_decision: str
    rejection_reason: Optional[str] = None


class InteractiveRepeater:
    """Dispatches targeted manual requests through the policy & scope gate."""

    def __init__(self, action_gate: ActionGate):
        self.action_gate = action_gate

    async def send_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        timeout_seconds: float = 10.0
    ) -> RepeaterResponse:
        """Send an HTTP request after evaluating ActionGate permissions."""
        method_upper = method.upper()
        custom_headers = dict(headers or {})

        # 1. Action Gate Verification
        gate_verdict: GateCheckResult = self.action_gate.validate_action(
            target=url,
            action_name="REPEATER_HTTP_REQUEST",
            risk_level=RiskLevel.LOW,
            requires_authorization=False,
            has_valid_authorization=True
        )

        if not gate_verdict.passed:
            return RepeaterResponse(
                status_code=403,
                headers={"X-Action-Gate-Status": "REJECTED"},
                body=f"Action Gate Denied: {gate_verdict.rejection_reason}",
                latency_ms=0.0,
                is_in_scope=False,
                gate_decision=gate_verdict.status.value,
                rejection_reason=gate_verdict.rejection_reason
            )

        # 2. Inject policy headers
        final_headers = dict(custom_headers)
        if gate_verdict.injected_headers:
            final_headers.update(gate_verdict.injected_headers)

        # 3. Execute request safely
        start_time = time.time()
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout_seconds, follow_redirects=False) as client:
                resp = await client.request(
                    method=method_upper,
                    url=url,
                    headers=final_headers,
                    content=body.encode("utf-8") if body else None
                )
                latency = round((time.time() - start_time) * 1000, 2)
                
                # Truncate preview if body is huge
                body_text = resp.text
                if len(body_text) > 100000:
                    body_text = body_text[:100000] + "\n... [Output truncated at 100KB]"

                return RepeaterResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=body_text,
                    latency_ms=latency,
                    is_in_scope=True,
                    gate_decision=gate_verdict.status.value,
                    rejection_reason=None
                )
        except Exception as ex:
            latency = round((time.time() - start_time) * 1000, 2)
            return RepeaterResponse(
                status_code=502,
                headers={"X-Repeater-Error": "ExecutionFailed"},
                body=f"Network Error: {str(ex)}",
                latency_ms=latency,
                is_in_scope=True,
                gate_decision=ActionDecision.ALLOW.value,
                rejection_reason=str(ex)
            )
