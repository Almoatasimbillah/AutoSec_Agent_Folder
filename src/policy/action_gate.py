"""Action Gate — The Execution Firewall (Doc 05, Doc 16).

All proposed agent actions must pass this deterministic pipeline before tool execution.
The LLM has zero authority to bypass this gate.
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel

from .scope_engine import ScopeEngine, ScopeEvaluationResult
from .policy_engine import PolicyEngine, PolicyEvaluationResult
from ..models.enums import RiskLevel, ActionStatus


class GateCheckResult(BaseModel):
    """Unified verdict from the Pre-Execution Action Gate."""
    passed: bool
    status: ActionStatus
    rejection_reason: Optional[str] = None
    injected_headers: Dict[str, str] = {}
    details: Dict[str, Any] = {}


class ActionGate:
    """Deterministic validation pipeline for all agent actions."""

    def __init__(self, scope_engine: ScopeEngine, policy_engine: PolicyEngine):
        self.scope_engine = scope_engine
        self.policy_engine = policy_engine

    def validate_action(
        self,
        target: str,
        action_name: str,
        risk_level: RiskLevel = RiskLevel.LOW,
        requires_authorization: bool = False,
        has_valid_authorization: bool = True
    ) -> GateCheckResult:
        """Run the comprehensive gate pipeline."""

        # 1. Target presence check
        if not target or not target.strip():
            return GateCheckResult(
                passed=False,
                status=ActionStatus.REJECTED,
                rejection_reason="Action rejected: Target cannot be empty."
            )

        # 2. Risk check
        if risk_level == RiskLevel.BLOCKED or risk_level == RiskLevel.CRITICAL:
            return GateCheckResult(
                passed=False,
                status=ActionStatus.BLOCKED,
                rejection_reason=f"Action rejected: Risk level '{risk_level.value}' is blocked from autonomous execution."
            )

        # 3. Authorization check
        if requires_authorization and not has_valid_authorization:
            return GateCheckResult(
                passed=False,
                status=ActionStatus.BLOCKED,
                rejection_reason="Action rejected: Required authorization/credentials are missing."
            )

        # 4. Scope Check (Deterministic)
        scope_res: ScopeEvaluationResult = self.scope_engine.evaluate(target)
        if not scope_res.is_allowed:
            return GateCheckResult(
                passed=False,
                status=ActionStatus.REJECTED,
                rejection_reason=f"Scope violation: {scope_res.reason}",
                details={"scope_details": scope_res.model_dump()}
            )

        # 5. Policy & Forbidden Action Check
        policy_res: PolicyEvaluationResult = self.policy_engine.evaluate_action_compliance(action_name)
        if not policy_res.is_compliant:
            return GateCheckResult(
                passed=False,
                status=ActionStatus.REJECTED,
                rejection_reason=f"Policy violation: {policy_res.reason}",
                details={"policy_details": policy_res.model_dump()}
            )

        # Gate passed
        return GateCheckResult(
            passed=True,
            status=ActionStatus.APPROVED,
            injected_headers=policy_res.required_headers_to_inject,
            details={"scope_reason": scope_res.reason}
        )
