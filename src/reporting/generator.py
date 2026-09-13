"""Report Generation and Evidence Manifest Engine (Doc 10, Doc 22).

Extracts data from the isolated engagement database and produces structured
reports (Executive, Technical, Mentor Debrief) and an evidence manifest.
"""

from pathlib import Path
from typing import Dict, List, Any
import json
from sqlmodel import select

from ..storage.database import DatabaseManager
from ..storage.evidence_vault import EvidenceVault
from ..knowledge.target_model import TargetModelManager
from ..models.entities import Engagement, Policy, ScopeRule, Finding, Hypothesis, Decision, Evidence
from .templates import (
    render_executive_report,
    render_technical_report,
    render_mentor_debrief,
)


class ReportGenerator:
    """Generates all formal deliverables and cryptographically verified evidence packages."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        evidence_vault: EvidenceVault,
        target_model: TargetModelManager,
        engagement_id: str,
        base_data_dir: str = "data/engagements"
    ):
        self.db_manager = db_manager
        self.evidence_vault = evidence_vault
        self.target_model = target_model
        self.engagement_id = engagement_id
        self.reports_dir = Path(base_data_dir) / engagement_id / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_all_reports(self) -> Dict[str, str]:
        """Generate Executive, Technical, Mentor Debrief reports and Evidence Manifest."""
        with self.db_manager.get_session(self.engagement_id) as session:
            # 1. Load data
            engagement_obj = session.exec(select(Engagement).where(Engagement.id == self.engagement_id)).first()
            policy_obj = session.exec(select(Policy).where(Policy.engagement_id == self.engagement_id)).first()
            scope_rules = session.exec(select(ScopeRule).where(ScopeRule.engagement_id == self.engagement_id)).all()
            findings = session.exec(select(Finding).where(Finding.engagement_id == self.engagement_id)).all()
            hypotheses = session.exec(select(Hypothesis).where(Hypothesis.engagement_id == self.engagement_id)).all()
            decisions = session.exec(select(Decision).where(Decision.engagement_id == self.engagement_id)).all()
            evidence_records = session.exec(select(Evidence).where(Evidence.engagement_id == self.engagement_id)).all()

            eng_dict = engagement_obj.model_dump() if engagement_obj else {}
            pol_dict = policy_obj.model_dump() if policy_obj else {}
            scope_list = [r.model_dump() for r in scope_rules]
            find_list = [f.model_dump() for f in findings]
            hyp_list = [h.model_dump() for h in hypotheses]
            dec_list = [d.model_dump() for d in decisions]

            # 2. Get target metrics & hierarchy
            metrics = self.target_model.get_summary()
            hierarchy = self.target_model.get_hierarchy()

        # 3. Render reports
        exec_content = render_executive_report(eng_dict, pol_dict, metrics, find_list)
        tech_content = render_technical_report(eng_dict, scope_list, hierarchy, find_list)
        mentor_content = render_mentor_debrief(eng_dict, dec_list, hyp_list)

        # 4. Save markdown files
        exec_path = self.reports_dir / "executive_report.md"
        tech_path = self.reports_dir / "technical_report.md"
        mentor_path = self.reports_dir / "mentor_debrief.md"

        exec_path.write_text(exec_content, encoding="utf-8")
        tech_path.write_text(tech_content, encoding="utf-8")
        mentor_path.write_text(mentor_content, encoding="utf-8")

        # 5. Build Evidence Manifest
        manifest_entries = []
        for ev in evidence_records:
            is_valid = self.evidence_vault.verify_integrity(ev.file_path, ev.sha256_hash)
            manifest_entries.append({
                "id": ev.id,
                "type": ev.artifact_type,
                "file_path": ev.file_path,
                "sha256_hash": ev.sha256_hash,
                "integrity_verified": is_valid
            })

        manifest_path = self.reports_dir / "manifest.json"
        manifest_data = {
            "engagement_id": self.engagement_id,
            "evidence_count": len(manifest_entries),
            "artifacts": manifest_entries
        }
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        return {
            "executive_report": str(exec_path.as_posix()),
            "technical_report": str(tech_path.as_posix()),
            "mentor_debrief": str(mentor_path.as_posix()),
            "manifest": str(manifest_path.as_posix()),
        }
