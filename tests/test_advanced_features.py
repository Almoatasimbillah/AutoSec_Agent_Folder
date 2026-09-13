import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from src.models.entities import ScopeRule, Policy, Finding
from src.models.enums import ScopeRuleType, ScopeEffect, FindingSeverity
from src.policy.scope_engine import ScopeEngine
from src.policy.policy_engine import PolicyEngine
from src.policy.action_gate import ActionGate
from src.tools.repeater import InteractiveRepeater, RepeaterResponse
from src.audit.advanced_probes import AdvancedApiAuditor
from src.reporting.bugbounty import BugBountyReportGenerator, CVSSScore
from src.core.copilot import SecurityCoPilot
from src.web.server import app


# ---------------------------------------------------------
# Fixtures
# ---------------------------------------------------------
@pytest.fixture
def test_action_gate():
    rules = [
        ScopeRule(
            engagement_id="test-eng",
            rule_type=ScopeRuleType.SUBDOMAIN_WILDCARD,
            pattern="*.juice-shop.herokuapp.com",
            effect=ScopeEffect.INCLUDE
        ),
        ScopeRule(
            engagement_id="test-eng",
            rule_type=ScopeRuleType.DOMAIN,
            pattern="secret.juice-shop.herokuapp.com",
            effect=ScopeEffect.EXCLUDE
        ),
    ]
    scope_engine = ScopeEngine(rules)
    policy = Policy(
        engagement_id="test-eng",
        required_headers={"X-Security-Research": "almoatasem_bellah"}
    )
    policy_engine = PolicyEngine(policy=policy)
    return ActionGate(scope_engine=scope_engine, policy_engine=policy_engine)


@pytest.fixture
def sample_finding():
    return Finding(
        id="f-test-101",
        engagement_id="eng-1",
        title="Missing Content-Security-Policy Header",
        severity=FindingSeverity.LOW,
        affected_asset="https://preview.owasp-juice.shop/#/",
        reproduction_steps="1. Send GET request.\n2. Observe absence of CSP header.",
        remediation_advice="Add Content-Security-Policy header."
    )


# ---------------------------------------------------------
# Interactive Repeater Tests
# ---------------------------------------------------------
@pytest.mark.asyncio
async def test_repeater_blocks_out_of_scope(test_action_gate):
    repeater = InteractiveRepeater(test_action_gate)
    res = await repeater.send_request(
        method="GET",
        url="https://secret.juice-shop.herokuapp.com/admin"
    )
    assert res.status_code == 403
    assert res.is_in_scope is False
    assert "Action Gate Denied" in res.body
    assert res.rejection_reason is not None


@pytest.mark.asyncio
async def test_repeater_allows_in_scope_and_injects_headers(test_action_gate):
    repeater = InteractiveRepeater(test_action_gate)
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.text = '{"status": "ok"}'

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_response
        res = await repeater.send_request(
            method="GET",
            url="https://sub.juice-shop.herokuapp.com/api/Users"
        )
        assert res.status_code == 200
        assert res.is_in_scope is True
        assert res.body == '{"status": "ok"}'
        
        # Verify injected mandatory header was passed to httpx
        called_headers = mock_req.call_args[1]["headers"]
        assert called_headers.get("X-Security-Research") == "almoatasem_bellah"


# ---------------------------------------------------------
# Bug Bounty Report Generator Tests
# ---------------------------------------------------------
def test_bounty_report_generation(sample_finding):
    report_md = BugBountyReportGenerator.generate_hackerone_markdown(
        finding=sample_finding,
        researcher_identity="almoatasem_bellah",
        researcher_name="المعتصم بالله (Al-Moatasem Bellah)",
        program_name="OWASP Juice Shop Bug Bounty"
    )
    assert "# [Vulnerability Report] Missing Content-Security-Policy Header" in report_md
    assert "المعتصم بالله (Al-Moatasem Bellah)" in report_md
    assert "@almoatasem_bellah" in report_md
    assert "OWASP Juice Shop Bug Bounty" in report_md
    assert "curl -i -s" in report_md
    assert "X-Security-Research: almoatasem_bellah" in report_md
    assert "CVSS:3.1" in report_md


def test_cvss_defaults_mapping():
    assert BugBountyReportGenerator.CVSS_DEFAULTS[FindingSeverity.CRITICAL].score == 9.8
    assert BugBountyReportGenerator.CVSS_DEFAULTS[FindingSeverity.HIGH].score == 7.5
    assert BugBountyReportGenerator.CVSS_DEFAULTS[FindingSeverity.MEDIUM].score == 5.3
    assert BugBountyReportGenerator.CVSS_DEFAULTS[FindingSeverity.LOW].score == 3.7
    assert BugBountyReportGenerator.CVSS_DEFAULTS[FindingSeverity.INFO].score == 0.0


# ---------------------------------------------------------
# AI Security Co-Pilot Tests
# ---------------------------------------------------------
def test_copilot_advice_for_403():
    copilot = SecurityCoPilot(engine_context=None)
    res = copilot.generate_advice("How can I bypass 403 Forbidden on the admin panel?")
    assert "403 Forbidden Bypass Strategies" in res.reply
    assert "X-Forwarded-For" in res.reply
    assert len(res.suggested_actions) > 0


def test_copilot_advice_for_idor():
    copilot = SecurityCoPilot(engine_context=None)
    res = copilot.generate_advice("Tell me how to test for IDOR or BOLA vulnerabilities")
    assert "IDOR" in res.reply
    assert len(res.suggested_actions) > 0


def test_copilot_general_summary():
    mock_engine = MagicMock()
    mock_engine.current_engagement.name = "Juice Shop Mission"
    mock_engine.current_engagement.target_summary = "OWASP vulnerable web application"
    mock_engine.hypothesis_engine.get_findings.return_value = []
    mock_engine.target_model.get_summary.return_value = {"endpoints": 5}

    copilot = SecurityCoPilot(engine_context=mock_engine)
    res = copilot.generate_advice("What is the current status of my assessment?")
    assert "Juice Shop Mission" in res.reply


# ---------------------------------------------------------
# Web Server Integration Tests for New Endpoints
# ---------------------------------------------------------
def test_web_api_copilot_endpoint():
    client = TestClient(app)
    res = client.post("/api/copilot/chat", json={"message": "What bypass headers should I try for 403?"})
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert "suggested_actions" in data
    assert "403" in data["reply"]


def test_web_api_repeater_and_quick_setup():
    client = TestClient(app)
    # Quick setup scope
    setup_res = client.post("/api/scope/quick-setup", json={
        "target_name": "Test Scope Program",
        "primary_target": "preview.owasp-juice.shop",
        "researcher_identity": "almoatasem_bellah"
    })
    assert setup_res.status_code == 200
    assert setup_res.json()["success"] is True

    # Denied out-of-scope repeater probe
    rep_denied = client.post("/api/tools/repeater", json={
        "method": "GET",
        "url": "https://malicious-external-site-not-in-scope.com/api"
    })
    assert rep_denied.status_code == 200
    data = rep_denied.json()
    assert data["status_code"] == 403
    assert data["is_in_scope"] is False
    assert "Action Gate Denied" in data["body"]
