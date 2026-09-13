import pytest
from fastapi.testclient import TestClient
from src.web.server import app

client = TestClient(app)

SAMPLE_PROFILE_YAML = """
program_metadata:
  program_name: "Web API Test Target"
  target_summary: "Automated API Testing Engagement"
  authorization_reference: "TEST-AUTH-999"
  researcher_handle: "api_tester"
  platform: "HackerOne"

network_and_headers:
  mandatory_headers:
    X-HackerOne-Research: "api_tester"
  rate_limit_rps: 4

scope_definition:
  in_scope:
    - type: DOMAIN
      pattern: "*.web-test.com"
      notes: "Main site"
  out_of_scope:
    - type: DOMAIN
      pattern: "secret.web-test.com"
      notes: "Private sub"

rule_checkboxes:
  prohibit_dos_attacks: true
  prohibit_destructive_writes: true
  prohibit_credential_bruteforce: true
  prohibit_social_engineering: true
  prohibit_third_party_testing: true
"""


def test_health_check():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ONLINE"
    assert "version" in data


def test_index_page():
    res = client.get("/")
    assert res.status_code == 200


def test_import_and_scope_management():
    # 1. Import Profile
    res = client.post("/api/engagements/import", json={"yaml_content": SAMPLE_PROFILE_YAML})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["preflight_status"] == "PASSED"
    assert data["scope_rules_count"] == 2
    assert "X-HackerOne-Research" in data["mandatory_headers"]

    # 2. Check Current Engagement
    res = client.get("/api/engagements/current")
    assert res.status_code == 200
    eng_data = res.json()
    assert eng_data["active"] is True
    assert eng_data["name"] == "Web API Test Target"
    assert eng_data["mandatory_headers"]["X-HackerOne-Research"] == "api_tester"
    assert "dos" in eng_data["forbidden_actions"]

    # 3. List Scope Rules
    res = client.get("/api/scope")
    assert res.status_code == 200
    rules = res.json()["rules"]
    assert len(rules) == 2

    # 4. Dynamically Add In-Scope Rule
    add_res = client.post("/api/scope", json={
        "pattern": "api.web-test.com",
        "rule_type": "DOMAIN",
        "effect": "INCLUDE",
        "priority": 15,
        "notes": "Added at runtime"
    })
    assert add_res.status_code == 200
    new_rule = add_res.json()["rule"]
    assert new_rule["pattern"] == "api.web-test.com"
    rule_id = new_rule["id"]

    # Verify rule was added
    res = client.get("/api/scope")
    assert len(res.json()["rules"]) == 3

    # 5. Dynamically Delete the Scope Rule
    del_res = client.delete(f"/api/scope/{rule_id}")
    assert del_res.status_code == 200
    assert del_res.json()["success"] is True

    # Verify rule was deleted
    res = client.get("/api/scope")
    assert len(res.json()["rules"]) == 2


def test_attack_surface_and_hypotheses():
    res = client.get("/api/attack-surface")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "hierarchy" in data

    res = client.get("/api/hypotheses")
    assert res.status_code == 200
    assert "hypotheses" in res.json()


def test_four_pillars_web_api_endpoints():
    # 1. Proxy endpoints
    status_res = client.get("/api/proxy/status")
    assert status_res.status_code == 200
    assert "is_running" in status_res.json()
    
    traffic_res = client.get("/api/proxy/traffic")
    assert traffic_res.status_code == 200
    assert "traffic" in traffic_res.json()

    del_traffic_res = client.delete("/api/proxy/traffic")
    assert del_traffic_res.status_code == 200
    assert del_traffic_res.json()["success"] is True

    # 2. Attack graph endpoint
    graph_res = client.get("/api/attack-graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert "chains" in graph_data

    # 3. Parameter miner endpoint
    miner_res = client.post("/api/audit/param-miner/run", json={
        "endpoint_url": "https://api.web-test.com/items"
    })
    assert miner_res.status_code == 200
    miner_data = miner_res.json()
    assert "results" in miner_data


