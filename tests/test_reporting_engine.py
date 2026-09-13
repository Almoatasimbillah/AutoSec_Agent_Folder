"""Unit tests for Reporting Engine and Deliverables (Doc 10, Doc 22)."""

import tempfile
from pathlib import Path
import json
import pytest

from src.storage.database import DatabaseManager
from src.storage.evidence_vault import EvidenceVault
from src.knowledge.target_model import TargetModelManager
from src.core.hypothesis_engine import HypothesisEngine
from src.reporting.generator import ReportGenerator
from src.reporting.exporter import ExportManager
from src.models.entities import Engagement, Policy, ScopeRule
from src.models.enums import ScopeRuleType, ScopeEffect, FindingSeverity, AssetType


def test_complete_reporting_and_manifest():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_mgr = DatabaseManager(base_data_dir=tmp_dir)
        vault = EvidenceVault(base_data_dir=tmp_dir)
        eng_id = "test_reporting_eng"

        # 1. Setup engagement and policy in DB
        with db_mgr.get_session(eng_id) as session:
            eng = Engagement(
                id=eng_id,
                name="Security Audit Test",
                target_summary="Acme Corp Test Environment",
                authorization_ref="AUTH-TEST-2026",
                researcher_identity="test-researcher"
            )
            pol = Policy(
                engagement_id=eng_id,
                program_name="Acme Testing",
                allowed_domains=["test.example.com"],
                forbidden_actions=["dos"]
            )
            rule = ScopeRule(
                engagement_id=eng_id,
                rule_type=ScopeRuleType.DOMAIN,
                pattern="test.example.com",
                effect=ScopeEffect.INCLUDE
            )
            session.add(eng)
            session.add(pol)
            session.add(rule)
            session.commit()

        # 2. Add target model items
        tm = TargetModelManager(db_mgr, eng_id)
        asset = tm.add_asset(AssetType.DOMAIN, "test.example.com", "recon")
        host = tm.add_host(asset.id, "test.example.com", ["192.168.1.50"])
        app = tm.add_application("TestApp", "https://test.example.com", ["Nginx", "Django"])
        tm.add_endpoint(app.id, "GET", "/api/v1/profile")

        # 3. Add hypothesis and finding
        hyp_engine = HypothesisEngine(db_mgr, eng_id)
        hyp = hyp_engine.create_hypothesis(
            statement="Profile endpoint allows parameter reflection",
            potential_impact="Information disclosure",
            priority_score=7.0
        )
        finding = hyp_engine.promote_to_finding(
            hypothesis_id=hyp.id,
            title="Profile Parameter Data Exposure",
            severity=FindingSeverity.MEDIUM,
            affected_asset="https://test.example.com/api/v1/profile",
            reproduction_steps="Send GET request with param X.",
            remediation_advice="Sanitize user input before reflection."
        )

        # 4. Store an evidence artifact
        evidence = vault.store_artifact(
            engagement_id=eng_id,
            artifact_type="http_traffic",
            content="HTTP/1.1 200 OK\r\n\r\nSample Response",
            file_extension="txt"
        )
        with db_mgr.get_session(eng_id) as session:
            session.add(evidence)
            session.commit()

        # 5. Generate All Reports
        generator = ReportGenerator(
            db_manager=db_mgr,
            evidence_vault=vault,
            target_model=tm,
            engagement_id=eng_id,
            base_data_dir=tmp_dir
        )
        reports = generator.generate_all_reports()

        assert Path(reports["executive_report"]).exists()
        assert Path(reports["technical_report"]).exists()
        assert Path(reports["mentor_debrief"]).exists()
        assert Path(reports["manifest"]).exists()

        # Verify Manifest content
        manifest_text = Path(reports["manifest"]).read_text(encoding="utf-8")
        manifest_data = json.loads(manifest_text)
        assert manifest_data["engagement_id"] == eng_id
        assert manifest_data["evidence_count"] == 1
        assert manifest_data["artifacts"][0]["integrity_verified"] is True

        # 6. Test JSON Export
        exporter = ExportManager(
            db_manager=db_mgr,
            target_model=tm,
            engagement_id=eng_id,
            base_data_dir=tmp_dir
        )
        export_file = exporter.export_json()
        assert Path(export_file).exists()

        export_data = json.loads(Path(export_file).read_text(encoding="utf-8"))
        assert export_data["engagement"]["name"] == "Security Audit Test"
        assert len(export_data["findings"]) == 1
        assert export_data["findings"][0]["title"] == "Profile Parameter Data Exposure"

        db_mgr.dispose()
