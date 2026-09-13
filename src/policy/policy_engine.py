"""Policy Engine (Doc 05).

Normalizes and validates high-level program constraints, forbidden actions,
rate limits, and required headers.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel
from ..models.entities import Policy


class PolicyEvaluationResult(BaseModel):
    is_compliant: bool
    reason: str
    required_headers_to_inject: Dict[str, str] = {}


class PolicyEngine:
    """Validates actions against program policy rules."""

    def __init__(self, policy: Optional[Policy] = None):
        self.policy = policy

    def set_policy(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate_action_compliance(self, action_name: str) -> PolicyEvaluationResult:
        """Check if an action is in the forbidden list."""
        if not self.policy:
            return PolicyEvaluationResult(
                is_compliant=True,
                reason="No explicit policy restrictions configured."
            )

        action_clean = action_name.strip().lower()
        for forbidden in self.policy.forbidden_actions:
            if forbidden.strip().lower() in action_clean or action_clean in forbidden.strip().lower():
                return PolicyEvaluationResult(
                    is_compliant=False,
                    reason=f"Action '{action_name}' is forbidden by program policy: {forbidden}"
                )

        return PolicyEvaluationResult(
            is_compliant=True,
            reason="Action conforms to engagement policy.",
            required_headers_to_inject=self.policy.required_headers or {}
        )
