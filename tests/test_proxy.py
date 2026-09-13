import pytest
import asyncio
from src.proxy.interceptor import PassiveInterceptionProxy, CapturedTrafficItem
from src.policy.scope_engine import ScopeEngine
from src.models.entities import ScopeRule
from src.models.enums import ScopeRuleType, ScopeEffect

@pytest.fixture
def test_scope():
    rules = [
        ScopeRule(engagement_id="test", rule_type=ScopeRuleType.DOMAIN, pattern="inscope.local", effect=ScopeEffect.INCLUDE),
        ScopeRule(engagement_id="test", rule_type=ScopeRuleType.DOMAIN, pattern="outscope.local", effect=ScopeEffect.EXCLUDE),
    ]
    return ScopeEngine(rules)

@pytest.mark.asyncio
async def test_proxy_lifecycle_and_buffer(test_scope):
    proxy = PassiveInterceptionProxy(scope_engine=test_scope, host="127.0.0.1", port=8099)
    assert proxy.is_running is False

    await proxy.start()
    assert proxy.is_running is True

    # Record synthetic traffic
    item_in = CapturedTrafficItem(
        method="GET",
        url="http://inscope.local/api/test",
        host="inscope.local",
        request_headers={"Authorization": "Bearer sample_token"},
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        is_in_scope=True
    )
    proxy.traffic_history.append(item_in)

    traffic = proxy.get_traffic(limit=10)
    assert len(traffic) == 1
    assert traffic[0].is_in_scope is True

    proxy.clear_traffic()
    assert len(proxy.get_traffic()) == 0

    await proxy.stop()
    assert proxy.is_running is False
