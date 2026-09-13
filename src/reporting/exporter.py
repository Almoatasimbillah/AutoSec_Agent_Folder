"""Machine-Readable Data Exporter (Doc 10, Doc 22).

Exports complete assessment data as structured JSON for CI/CD, SIEM, or ticketing systems.
"""

from pathlib import Path
from typing import Dict, Any
import json
from sqlmodel import select

from ..storage.database import DatabaseManager
from ..knowledge.target_model import TargetModelManager
from ..models.entities import (
    Engagement,
    Policy,
    ScopeRule,
    Finding,
    Hypothesis,
    Decision,
    Evidence,
)


class ExportManager:
    """Produces canonical JSON exports of complete engagement data."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        target_model: TargetModelManager,
        engagement_id: str,
        base_data_dir: str = "data/engagements"
    ):
        self.db_manager = db_manager
        self.target_model = target_model
        self.engagement_id = engagement_id
        self.reports_dir = Path(base_data_dir) / engagement_id / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def export_json(self) -> str:
        """Export comprehensive machine-readable JSON deliverable."""
        with self.db_manager.get_session(self.engagement_id) as session:
            engagement_obj = session.exec(select(Engagement).where(Engagement.id == self.engagement_id)).first()
            policy_obj = session.exec(select(Policy).where(Policy.engagement_id == self.engagement_id)).first()
            scope_rules = session.exec(select(ScopeRule).where(ScopeRule.engagement_id == self.engagement_id)).all()
            findings = session.exec(select(Finding).where(Finding.engagement_id == self.engagement_id)).all()
            hypotheses = session.exec(select(Hypothesis).where(Hypothesis.engagement_id == self.engagement_id)).all()
            decisions = session.exec(select(Decision).where(Decision.engagement_id == self.engagement_id)).all()
            evidence_records = session.exec(select(Evidence).where(Evidence.engagement_id == self.engagement_id)).all()

            export_data: Dict[str, Any] = {
                "schema_version": "0.1.0",
                "engagement": engagement_obj.model_dump(mode="json") if engagement_obj else {},
                "policy": policy_obj.model_dump(mode="json") if policy_obj else {},
                "scope_rules": [r.model_dump(mode="json") for r in scope_rules],
                "attack_surface": {
                    "summary": self.target_model.get_summary(),
                    "topology": self.target_model.get_hierarchy(),
                },
                "findings": [f.model_dump(mode="json") for f in findings],
                "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
                "decisions": [d.model_dump(mode="json") for d in decisions],
                "evidence": [e.model_dump(mode="json") for e in evidence_records],
            }

        export_path = self.reports_dir / "engagement_export.json"
        export_path.write_text(json.dumps(export_data, indent=2), encoding="utf-8")
        return str(export_path.as_posix())
