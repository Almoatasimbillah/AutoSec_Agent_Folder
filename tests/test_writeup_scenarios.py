import pytest
from fastapi.testclient import TestClient

from src.knowledge.writeups import WriteupKnowledgeBase, SecurityScenario
from src.models.enums import FindingSeverity, HypothesisStatus
from src.web.server import app

client = TestClient(app)


def test_writeup_knowledge_base_initialization():
    kb = WriteupKnowledgeBase()
    scenarios = kb.get_all_scenarios()
    assert len(scenarios) >= 8
    
    cors_scen = kb.get_scenario("SCENARIO-H1-CORS-01")
    assert cors_scen is not None
    assert "CORS Misconfiguration" in cors_scen.title
    assert "HackerOne" in cors_scen.reference


def test_scenario_matching_by_technology():
    kb = WriteupKnowledgeBase()
    # Target running Express, Node, and Angular
    matches = kb.find_applicable_scenarios(
        detected_tech=["Express", "Node.js", "Angular"],
        endpoints=["/api/Users", "/ftp", "/main.js"]
    )
    assert len(matches) > 0
    top_match = matches[0]
    assert "scenario" in top_match
    assert top_match["relevance_score"] >= 2
    
    # Scenarios for Express/Node should be ranked high
    matched_ids = [m["scenario"].id for m in matches]
    assert "SCENARIO-H1-BOLA-03" in matched_ids or "SCENARIO-H1-CORS-01" in matched_ids


def test_custom_writeup_ingestion():
    kb = WriteupKnowledgeBase()
    custom = kb.import_custom_writeup(
        title="Prototype Pollution in Merge Utility",
        technologies=["node", "lodash", "express"],
        category="API Security",
        hypothesis_statement="Sending __proto__ in JSON merges pollutes Object prototype",
        summary="Exploitation of deep merge without key validation leads to property injection.",
        reference="Bugcrowd Report #99281",
        severity=FindingSeverity.HIGH,
        sample_path="/api/settings",
        sample_method="PUT",
        sample_body='{"__proto__": {"admin": true}}'
    )
    assert custom.id.startswith("SCENARIO-CUSTOM-")
    assert kb.get_scenario(custom.id) is not None

    # Verify custom scenario can now be matched
    matched = kb.find_applicable_scenarios(detected_tech=["lodash", "node"])
    assert any(m["scenario"].id == custom.id for m in matched)


def test_api_scenarios_endpoints():
    # 1. GET /api/scenarios
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    data = res.json()
    assert "total_scenarios" in data
    assert data["total_scenarios"] >= 8
    assert "scenarios" in data

    # 2. POST /api/scenarios/custom
    custom_res = client.post("/api/scenarios/custom", json={
        "title": "OAuth Token Leak via Referer Header",
        "technologies": ["oauth", "openid"],
        "category": "OAuth & Auth",
        "hypothesis_statement": "Authorization code is leaked via unstripped Referer headers on external assets",
        "summary": "External analytics scripts capture access token from URL parameters.",
        "reference": "Medium Security Writeup 2026",
        "severity": "HIGH",
        "sample_path": "/oauth/callback"
    })
    assert custom_res.status_code == 200
    c_data = custom_res.json()
    assert c_data["success"] is True
    created_id = c_data["scenario"]["id"]

    # 3. Quick setup engagement and apply scenario
    client.post("/api/scope/quick-setup", json={
        "target_name": "Test Playbooks Engagement",
        "primary_target": "preview.owasp-juice.shop",
        "researcher_identity": "almoatasem_bellah"
    })

    apply_res = client.post("/api/scenarios/apply", json={"scenario_id": created_id})
    assert apply_res.status_code == 200
    assert apply_res.json()["success"] is True
    assert "hypothesis_id" in apply_res.json()
