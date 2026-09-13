"""Differential Access Control Auditor (Doc 07, Doc 15, Doc 18).

Conducts scientific differential analysis to verify authorization boundaries
between authorized user roles (e.g., User A vs User B vs Anonymous) on shared endpoints.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel
import httpx

from ..session.manager import SessionManager
from ..models.entities import Observation, Hypothesis
from ..models.enums import ConfidenceLevel, HypothesisStatus


class DifferentialComparisonResult(BaseModel):
    """Normalized output of a differential authorization test."""
    endpoint: str
    user_a_status: int
    user_b_status: Optional[int] = None
    anonymous_status: Optional[int] = None
    access_control_discrepancy_detected: bool
    summary: str
    suggested_hypothesis: Optional[str] = None


class DifferentialAuditor:
    """Compares HTTP responses across different authorized sessions to detect permission issues."""

    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager

    async def compare_endpoint_access(
        self,
        endpoint_url: str,
        user_a_name: str,
        user_b_name: Optional[str] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None
    ) -> DifferentialComparisonResult:
        """Execute request under User A, User B, and unauthenticated to evaluate authorization."""
        base_headers = headers or {}
        
        # 1. Fetch Session A
        session_a = self.session_manager.get_session_for_identity(user_a_name)
        cookies_a = session_a.cookies if session_a else {}

        # 2. Fetch Session B if provided
        cookies_b = {}
        if user_b_name:
            session_b = self.session_manager.get_session_for_identity(user_b_name)
            cookies_b = session_b.cookies if session_b else {}

        status_a: int = 0
        status_b: Optional[int] = None
        status_anon: Optional[int] = None
        content_len_a: int = 0
        content_len_b: int = 0

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=False) as client:
            # Request as User A (Baseline Owner)
            try:
                resp_a = await client.request(method, endpoint_url, headers=base_headers, cookies=cookies_a)
                status_a = resp_a.status_code
                content_len_a = len(resp_a.content)
            except Exception:
                status_a = 0

            # Request as User B (Cross-account)
            if user_b_name:
                try:
                    resp_b = await client.request(method, endpoint_url, headers=base_headers, cookies=cookies_b)
                    status_b = resp_b.status_code
                    content_len_b = len(resp_b.content)
                except Exception:
                    status_b = 0

            # Request as Anonymous
            try:
                resp_anon = await client.request(method, endpoint_url, headers=base_headers)
                status_anon = resp_anon.status_code
            except Exception:
                status_anon = 0

        # Evaluate differential behavior
        discrepancy = False
        suggested_hyp = None
        summary = f"Baseline User A: HTTP {status_a}."

        if status_a == 200:
            if status_b == 200:
                # Both users get 200 OK on an object endpoint
                discrepancy = True
                summary += f" User B unexpectedly returned HTTP 200 (length diff: {abs(content_len_a - content_len_b)})."
                suggested_hyp = f"Potential broken object-level authorization on {endpoint_url}: User B accessed resource belonging to User A."
            elif status_anon == 200:
                discrepancy = True
                summary += " Anonymous request unexpectedly returned HTTP 200."
                suggested_hyp = f"Potential missing authentication or public exposure on {endpoint_url}."
            else:
                summary += f" User B received HTTP {status_b}; Anonymous received HTTP {status_anon} (Access control enforced)."

        return DifferentialComparisonResult(
            endpoint=endpoint_url,
            user_a_status=status_a,
            user_b_status=status_b,
            anonymous_status=status_anon,
            access_control_discrepancy_detected=discrepancy,
            summary=summary,
            suggested_hypothesis=suggested_hyp
        )
