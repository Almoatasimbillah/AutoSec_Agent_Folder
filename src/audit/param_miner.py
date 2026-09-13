"""Parameter & Response Anomaly Miner (Doc 07, Doc 15).

Performs non-destructive differential analysis on API endpoints to detect
hidden parameters, reflection contexts, and response length/status anomalies.
"""

from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import httpx
from pydantic import BaseModel, Field

from ..policy.action_gate import ActionGate
from ..models.enums import RiskLevel
from ..core.hypothesis_engine import HypothesisEngine


class ParamAnomalyResult(BaseModel):
    """Result of differential parameter probing."""
    endpoint_url: str
    parameter_name: str
    tested_value: str
    baseline_status: int
    probed_status: int
    baseline_length: int
    probed_length: int
    length_difference: int
    status_code_changed: bool
    is_reflected: bool
    reflection_context: Optional[str] = None
    anomaly_type: str = "NORMAL"
    anomaly_score: float = 0.0


class ParameterAnomalyMiner:
    """Safe, non-destructive parameter discovery and anomaly analyzer."""

    HIGH_SIGNAL_PARAMETERS = [
        "debug", "admin", "role", "redirect", "url", "callback", "test",
        "id", "view", "source", "file", "format", "token", "user",
        "api_key", "email", "secret", "lang", "next", "origin", "state"
    ]

    def __init__(
        self,
        action_gate: ActionGate,
        hypothesis_engine: Optional[HypothesisEngine] = None,
        researcher_tag: str = "almoatasem_bellah"
    ):
        self.action_gate = action_gate
        self.hypothesis_engine = hypothesis_engine
        self.researcher_tag = researcher_tag
        self.default_headers = {
            "User-Agent": "AutonomousSecurityAuditor/1.0 (ParamMiner)",
            "X-Security-Research": researcher_tag,
            "Accept": "*/*"
        }

    async def probe_endpoint(
        self,
        endpoint_url: str,
        parameters_to_test: Optional[List[str]] = None,
        max_params: int = 15,
        timeout_seconds: float = 6.0
    ) -> List[ParamAnomalyResult]:
        """Probe an endpoint for parameter responsiveness and reflection anomalies."""
        # Action Gate Scope Check
        gate_res = self.action_gate.validate_action(
            target=endpoint_url,
            action_name="PARAM_MINING_PROBE",
            risk_level=RiskLevel.LOW,
            requires_authorization=False,
            has_valid_authorization=True
        )
        if not gate_res.passed:
            return []

        params_list = (parameters_to_test or self.HIGH_SIGNAL_PARAMETERS)[:max_params]
        results: List[ParamAnomalyResult] = []

        async with httpx.AsyncClient(verify=False, timeout=timeout_seconds, follow_redirects=False) as client:
            # 1. Establish Baseline Response
            try:
                base_resp = await client.get(endpoint_url, headers=self.default_headers)
                baseline_status = base_resp.status_code
                baseline_length = len(base_resp.content)
                baseline_body = base_resp.text
            except Exception:
                return []

            # 2. Probe candidate parameters
            parsed = urlparse(endpoint_url)
            orig_qs = parse_qs(parsed.query)

            for param in params_list:
                canary = f"pcanary{param}99"
                test_qs = dict(orig_qs)
                test_qs[param] = [canary]

                probed_parts = list(parsed)
                probed_parts[4] = urlencode(test_qs, doseq=True)
                probed_url = urlunparse(probed_parts)

                try:
                    probe_resp = await client.get(probed_url, headers=self.default_headers)
                    probed_status = probe_resp.status_code
                    probed_length = len(probe_resp.content)
                    probed_body = probe_resp.text

                    len_diff = probed_length - baseline_length
                    status_changed = (probed_status != baseline_status)

                    # Reflection Analysis
                    is_reflected = canary in probed_body
                    reflection_ctx = None
                    if is_reflected:
                        if f"<script" in probed_body and canary in probed_body.split("<script")[1].split("</script>")[0] if "</script>" in probed_body else False:
                            reflection_ctx = "SCRIPT_BLOCK"
                        elif probed_body.strip().startswith("{") or probed_body.strip().startswith("["):
                            reflection_ctx = "JSON_RESPONSE"
                        elif f'="{canary}"' in probed_body or f"='{canary}'" in probed_body:
                            reflection_ctx = "HTML_ATTRIBUTE"
                        else:
                            reflection_ctx = "HTML_BODY"

                    # Anomaly Scoring & Classification
                    anomaly_score = 0.0
                    anomaly_type = "NORMAL"

                    if status_changed:
                        if probed_status in {500, 502, 503}:
                            anomaly_score += 6.5
                            anomaly_type = "STATUS_5XX_SERVER_ERROR"
                        elif baseline_status in {401, 403} and probed_status == 200:
                            anomaly_score += 9.0
                            anomaly_type = "ACCESS_CONTROL_BYPASS_ANOMALY"
                        else:
                            anomaly_score += 4.0
                            anomaly_type = "STATUS_CODE_DRIFT"

                    if is_reflected:
                        anomaly_score += 5.0
                        anomaly_type = f"INPUT_REFLECTION ({reflection_ctx})"

                    if abs(len_diff) > max(40, int(baseline_length * 0.15)):
                        anomaly_score += 3.5
                        if anomaly_type == "NORMAL":
                            anomaly_type = "LENGTH_DEVIATION_ANOMALY"

                    if anomaly_score >= 3.0:
                        anomaly = ParamAnomalyResult(
                            endpoint_url=endpoint_url,
                            parameter_name=param,
                            tested_value=canary,
                            baseline_status=baseline_status,
                            probed_status=probed_status,
                            baseline_length=baseline_length,
                            probed_length=probed_length,
                            length_difference=len_diff,
                            status_code_changed=status_changed,
                            is_reflected=is_reflected,
                            reflection_context=reflection_ctx,
                            anomaly_type=anomaly_type,
                            anomaly_score=min(10.0, anomaly_score)
                        )
                        results.append(anomaly)

                        # Enqueue in HypothesisEngine if present
                        if self.hypothesis_engine and anomaly_score >= 5.0:
                            self.hypothesis_engine.create_hypothesis(
                                statement=f"Parameter '{param}' at {endpoint_url} triggers {anomaly_type} (Score: {anomaly_score}).",
                                potential_impact=f"Parameter reflection or status alteration indicates dynamic server-side processing: {anomaly_type}",
                                related_asset_id=endpoint_url,
                                priority_score=anomaly_score
                            )
                except Exception:
                    continue

        return results
