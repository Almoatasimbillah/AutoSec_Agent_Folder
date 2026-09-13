import pytest
from unittest.mock import MagicMock
from src.knowledge.attack_graph import AttackGraphEngine
from src.models.entities import Finding
from src.models.enums import FindingSeverity

def test_attack_graph_generation_and_chaining():
    mock_hyp_engine = MagicMock()
    findings = [
        Finding(
            id="f-1",
            engagement_id="eng-1",
            title="Information Disclosure: Exposed Secret in JS Bundle",
            severity=FindingSeverity.HIGH,
            affected_asset="https://target.com/main.js",
            reproduction_steps="...",
            remediation_advice="..."
        ),
        Finding(
            id="f-2",
            engagement_id="eng-1",
            title="BOLA / Insecure Direct Object Reference on /api/Users/1",
            severity=FindingSeverity.HIGH,
            affected_asset="https://target.com/api/Users/1",
            reproduction_steps="...",
            remediation_advice="..."
        ),
        Finding(
            id="f-3",
            engagement_id="eng-1",
            title="CORS Misconfiguration with Origin Reflection",
            severity=FindingSeverity.MEDIUM,
            affected_asset="https://target.com/api/profile",
            reproduction_steps="...",
            remediation_advice="..."
        )
    ]
    mock_hyp_engine.get_findings.return_value = findings

    engine = AttackGraphEngine(hypothesis_engine=mock_hyp_engine)
    graph = engine.build_attack_graph(target_name="Juice Shop Target")

    assert len(graph.nodes) > 3
    assert len(graph.edges) > 3
    assert graph.total_chains >= 2

    # Verify Chain 1 (Secret + IDOR -> Critical)
    chain_names = [c.name for c in graph.chains]
    assert any("Credential" in name or "Object" in name for name in chain_names)
    assert graph.highest_cvss >= 9.0
