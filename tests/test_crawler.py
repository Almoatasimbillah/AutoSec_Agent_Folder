import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.recon.crawler import SPACrawler, CrawledEndpoint, CrawlResult
from src.models.entities import ScopeRule
from src.models.enums import ScopeRuleType, ScopeEffect
from src.policy.scope_engine import ScopeEngine
from src.policy.action_gate import ActionGate

@pytest.fixture
def mock_gate():
    rules = [
        ScopeRule(
            engagement_id="test",
            rule_type=ScopeRuleType.DOMAIN,
            pattern="target.com",
            effect=ScopeEffect.INCLUDE
        ),
        ScopeRule(
            engagement_id="test",
            rule_type=ScopeRuleType.DOMAIN,
            pattern="forbidden.com",
            effect=ScopeEffect.EXCLUDE
        )
    ]
    scope_engine = ScopeEngine(rules)
    policy_engine = MagicMock()
    policy_engine.evaluate_action_compliance.return_value = MagicMock(is_compliant=True, required_headers_to_inject={})
    return ActionGate(scope_engine, policy_engine)

@pytest.mark.asyncio
async def test_crawler_action_gate_blocks_out_of_scope(mock_gate):
    crawler = SPACrawler(action_gate=mock_gate)
    res = await crawler.crawl_target("https://forbidden.com")
    assert len(res.discovered_endpoints) == 0

@pytest.mark.asyncio
async def test_crawler_extracts_html_and_js_routes(mock_gate):
    sample_html = """
    <html>
      <head>
        <script src="/main.bundle.js"></script>
        <link rel="stylesheet" href="/style.css">
      </head>
      <body>
        <a href="/about-us">About</a>
        <a href="https://target.com/contact">Contact</a>
        <form action="/api/feedback" method="POST">
          <input name="comment" type="text">
          <input name="rating" type="number">
          <button type="submit">Send</button>
        </form>
      </body>
    </html>
    """

    sample_js = """
    const routes = [
      { path: 'dashboard', component: DashboardComponent },
      { path: 'profile/settings', component: SettingsComponent }
    ];
    function fetchUserData() {
      return fetch('/rest/user/data?id=123');
    }
    """

    crawler = SPACrawler(action_gate=mock_gate)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        def side_effect(url, **kwargs):
            mock_resp = MagicMock()
            if "main.bundle.js" in url:
                mock_resp.status_code = 200
                mock_resp.text = sample_js
            else:
                mock_resp.status_code = 200
                mock_resp.text = sample_html
            return mock_resp

        mock_get.side_effect = side_effect

        res = await crawler.crawl_target("https://target.com")
        assert len(res.discovered_endpoints) > 0
        paths = [e.path for e in res.discovered_endpoints]

        # Assert HTML elements extracted
        assert "/about-us" in paths
        assert "/api/feedback" in paths

        # Assert Angular/JS routes extracted
        assert "/dashboard" in paths or "/profile/settings" in paths
        assert any("rest" in p for p in paths)
