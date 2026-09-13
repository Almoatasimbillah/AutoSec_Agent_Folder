import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.audit.param_miner import ParameterAnomalyMiner
from src.policy.scope_engine import ScopeEngine
from src.policy.action_gate import ActionGate
from src.models.entities import ScopeRule
from src.models.enums import ScopeRuleType, ScopeEffect

@pytest.fixture
def mock_gate():
    rules = [
        ScopeRule(engagement_id="test", rule_type=ScopeRuleType.DOMAIN, pattern="app.local", effect=ScopeEffect.INCLUDE)
    ]
    scope_engine = ScopeEngine(rules)
    policy_engine = MagicMock()
    policy_engine.evaluate_action_compliance.return_value = MagicMock(is_compliant=True, required_headers_to_inject={})
    return ActionGate(scope_engine, policy_engine)

@pytest.mark.asyncio
async def test_param_miner_detects_reflection_and_status_drift(mock_gate):
    miner = ParameterAnomalyMiner(action_gate=mock_gate, researcher_tag="almoatasem_bellah")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        # Baseline response
        base_resp = MagicMock()
        base_resp.status_code = 200
        base_resp.content = b"<html>Normal Page</html>"
        base_resp.text = "<html>Normal Page</html>"

        # Probed response: reflects canary and triggers error
        def side_effect(url, **kwargs):
            if "debug=" in url:
                r = MagicMock()
                r.status_code = 500
                r.content = b"<html>Error: pcanarydebug99 not found with long output</html>"
                r.text = "<html>Error: pcanarydebug99 not found with long output</html>"
                return r
            return base_resp

        mock_get.side_effect = side_effect

        results = await miner.probe_endpoint("https://app.local/search", parameters_to_test=["debug", "normal_param"])
        assert len(results) > 0
        debug_res = next(r for r in results if r.parameter_name == "debug")
        assert debug_res.status_code_changed is True
        assert debug_res.is_reflected is True
        assert debug_res.anomaly_score >= 5.0
