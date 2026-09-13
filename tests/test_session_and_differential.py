"""Unit tests for Session Management, Differential Auditing, and Hypothesis Engine (Doc 07, Doc 15, Doc 18)."""

import tempfile
import pytest
from src.storage.database import DatabaseManager
from src.session.manager import SessionManager
from src.core.hypothesis_engine import HypothesisEngine
from src.audit.differential import DifferentialAuditor, DifferentialComparisonResult
from src.models.enums import HypothesisStatus, ConfidenceLevel, FindingSeverity


def test_session_manager_identities():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_mgr = DatabaseManager(base_data_dir=tmp_dir)
        eng_id = "test_eng_sessions"

        mgr = SessionManager(db_mgr, eng_id)

        # 1. Create identities
        user_a = mgr.create_identity("UserA_Standard", "user")
        user_b = mgr.create_identity("UserB_Attacker", "user")

        assert user_a.identity_name == "UserA_Standard"
        assert user_b.identity_name == "UserB_Attacker"

        # 2. Attach session cookies
        sess_a = mgr.set_session_context(
            identity_id=user_a.id,
            cookies={"session_id": "token_aaa_111"}
        )
        assert sess_a.cookies["session_id"] == "token_aaa_111"

        sess_b = mgr.set_session_context(
            identity_id=user_b.id,
            cookies={"session_id": "token_bbb_222"}
        )
        assert sess_b.cookies["session_id"] == "token_bbb_222"

        # 3. Retrieve
        retrieved_a = mgr.get_session_for_identity("UserA_Standard")
        assert retrieved_a is not None
        assert retrieved_a.cookies["session_id"] == "token_aaa_111"

        db_mgr.dispose()


def test_hypothesis_lifecycle_and_promotion():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_mgr = DatabaseManager(base_data_dir=tmp_dir)
        eng_id = "test_eng_hyp"

        hyp_engine = HypothesisEngine(db_mgr, eng_id)

        # 1. Create candidate
        hyp = hyp_engine.create_hypothesis(
            statement="Order endpoint does not enforce user ownership checks.",
            potential_impact="Data leakage of customer invoices across accounts",
            priority_score=8.5
        )
        assert hyp.status == HypothesisStatus.CANDIDATE
        assert hyp.priority_score == 8.5

        # 2. Update status to TESTING
        updated = hyp_engine.update_hypothesis_status(
            hypothesis_id=hyp.id,
            status=HypothesisStatus.TESTING,
            confidence=ConfidenceLevel.HIGH
        )
        assert updated.status == HypothesisStatus.TESTING
        assert updated.confidence == ConfidenceLevel.HIGH

        # 3. Promote to Finding
        finding = hyp_engine.promote_to_finding(
            hypothesis_id=hyp.id,
            title="Broken Object-Level Authorization on Invoices Endpoint",
            severity=FindingSeverity.HIGH,
            affected_asset="/api/invoices/{id}",
            reproduction_steps="1. Authenticate as User B. 2. Request User A invoice ID. 3. Observe HTTP 200.",
            remediation_advice="Enforce tenancy checks in the database query verifying request.user.id == invoice.owner_id."
        )
        assert finding.title == "Broken Object-Level Authorization on Invoices Endpoint"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.affected_asset == "/api/invoices/{id}"

        # Verify hypothesis status became confirmed
        active_candidates = hyp_engine.get_hypotheses(status=HypothesisStatus.CANDIDATE)
        assert len(active_candidates) == 0

        confirmed = hyp_engine.get_hypotheses(status=HypothesisStatus.CONFIRMED)
        assert len(confirmed) == 1

        db_mgr.dispose()


@pytest.mark.asyncio
async def test_differential_auditor_logic():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_mgr = DatabaseManager(base_data_dir=tmp_dir)
        eng_id = "test_eng_diff"

        mgr = SessionManager(db_mgr, eng_id)
        u1 = mgr.create_identity("Alice", "user")
        u2 = mgr.create_identity("Bob", "user")

        mgr.set_session_context(u1.id, {"auth": "alice_token"})
        mgr.set_session_context(u2.id, {"auth": "bob_token"})

        auditor = DifferentialAuditor(mgr)

        # Verify auditor instantiation and session reading
        s1 = auditor.session_manager.get_session_for_identity("Alice")
        s2 = auditor.session_manager.get_session_for_identity("Bob")
        assert s1.cookies["auth"] == "alice_token"
        assert s2.cookies["auth"] == "bob_token"

        db_mgr.dispose()
