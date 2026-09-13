"""Hypothesis & Scientific Verification Engine (Doc 07, Doc 15, Doc 20).

Manages security hypotheses, prioritizes investigation queues, and coordinates
controlled verification and false-positive disproving.
"""

from typing import List, Optional, Dict, Any
from sqlmodel import select

from ..storage.database import DatabaseManager
from ..models.entities import Hypothesis, Observation, Finding
from ..models.enums import HypothesisStatus, ConfidenceLevel, FindingSeverity


class HypothesisEngine:
    """Manages the lifecycle of hypotheses from candidate to verified finding."""

    def __init__(self, db_manager: DatabaseManager, engagement_id: str):
        self.db_manager = db_manager
        self.engagement_id = engagement_id

    def create_hypothesis(
        self,
        statement: str,
        potential_impact: str,
        related_asset_id: Optional[str] = None,
        priority_score: float = 5.0,
        initial_evidence_refs: Optional[List[str]] = None
    ) -> Hypothesis:
        """Register a new candidate hypothesis."""
        with self.db_manager.get_session(self.engagement_id) as session:
            hyp = Hypothesis(
                engagement_id=self.engagement_id,
                statement=statement,
                status=HypothesisStatus.CANDIDATE,
                confidence=ConfidenceLevel.MEDIUM,
                potential_impact=potential_impact,
                priority_score=priority_score,
                related_asset_id=related_asset_id,
                evidence_refs=initial_evidence_refs or []
            )
            session.add(hyp)
            session.commit()
            session.refresh(hyp)
            return hyp

    def create_hypothesis_from_scenario(
        self,
        scenario: Any,
        target_asset: Optional[str] = None,
        priority_score: float = 7.0
    ) -> Hypothesis:
        """Create a candidate hypothesis directly derived from a security writeup scenario."""
        statement = f"[{scenario.id}] {scenario.hypothesis_statement}"
        potential_impact = f"{scenario.summary} (Reference: {scenario.reference})"
        return self.create_hypothesis(
            statement=statement,
            potential_impact=potential_impact,
            related_asset_id=target_asset,
            priority_score=priority_score,
            initial_evidence_refs=[f"Precondition: {scenario.precondition}"]
        )

    def get_hypotheses(self, status: Optional[HypothesisStatus] = None) -> List[Hypothesis]:
        """Retrieve hypotheses, optionally filtered by status, ordered by priority."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(Hypothesis).where(Hypothesis.engagement_id == self.engagement_id)
            if status:
                stmt = stmt.where(Hypothesis.status == status)
            stmt = stmt.order_by(Hypothesis.priority_score.desc())
            return session.exec(stmt).all()

    def update_hypothesis_status(
        self,
        hypothesis_id: str,
        status: HypothesisStatus,
        conclusion: Optional[str] = None,
        confidence: Optional[ConfidenceLevel] = None
    ) -> Optional[Hypothesis]:
        """Update status and conclusion of an existing hypothesis."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(Hypothesis).where(
                Hypothesis.engagement_id == self.engagement_id,
                Hypothesis.id == hypothesis_id
            )
            hyp = session.exec(stmt).first()
            if not hyp:
                return None

            hyp.status = status
            if conclusion:
                hyp.conclusion = conclusion
            if confidence:
                hyp.confidence = confidence

            session.add(hyp)
            session.commit()
            session.refresh(hyp)
            return hyp

    def promote_to_finding(
        self,
        hypothesis_id: str,
        title: str,
        severity: FindingSeverity,
        affected_asset: str,
        reproduction_steps: str,
        remediation_advice: str
    ) -> Finding:
        """Promote a thoroughly verified hypothesis to an official Finding."""
        with self.db_manager.get_session(self.engagement_id) as session:
            # Mark hypothesis confirmed
            self.update_hypothesis_status(
                hypothesis_id=hypothesis_id,
                status=HypothesisStatus.CONFIRMED,
                conclusion="Verified via controlled experiment; alternative explanations disproven.",
                confidence=ConfidenceLevel.CONFIRMED
            )

            finding = Finding(
                engagement_id=self.engagement_id,
                hypothesis_id=hypothesis_id,
                title=title,
                severity=severity,
                affected_asset=affected_asset,
                reproduction_steps=reproduction_steps,
                remediation_advice=remediation_advice
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
            return finding

    def get_findings(self) -> List[Finding]:
        """Retrieve all verified findings for this engagement."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(Finding).where(Finding.engagement_id == self.engagement_id)
            return session.exec(stmt).all()
