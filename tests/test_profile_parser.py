import pytest
import tempfile
import shutil
from pathlib import Path

from src.policy.profile_parser import ProfileParser
from src.policy.scope_manager import DynamicScopeManager
from src.policy.scope_engine import ScopeEngine
from src.storage.database import DatabaseManager
from src.models.enums import ScopeRuleType, ScopeEffect

SAMPLE_YAML = """
program_metadata:
  program_name: "Acme Corp Bug Bounty"
  target_summary: "Main public web applications and API gateway"
  authorization_reference: "H1-ACME-2026-XYZ"
  researcher_handle: "0xCyberHero"
  platform: "HackerOne"

network_and_headers:
  mandatory_headers:
    X-HackerOne-Research: "0xCyberHero"
    X-Bug-Bounty-Auth: "Token-12345"
  rate_limit_rps: 3

scope_definition:
  in_scope:
    - type: DOMAIN
      pattern: "*.acme.corp"
      notes: "Main web perimeter"
    - type: IP_RANGE
      pattern: "192.168.1.0/24"
      notes: "Internal staging IP range"
  out_of_scope:
    - type: DOMAIN
      pattern: "billing.acme.corp"
      notes: "Third-party payment gateway"

rule_checkboxes:
  prohibit_dos_attacks: true
  prohibit_destructive_writes: true
  prohibit_credential_bruteforce: true
  prohibit_social_engineering: true
  prohibit_third_party_testing: true
"""


def test_parse_yaml_profile():
    result = ProfileParser.parse_yaml(SAMPLE_YAML)
    
    # Verify Engagement
    assert result.engagement.name == "Acme Corp Bug Bounty"
    assert result.engagement.researcher_identity == "0xCyberHero"
    assert result.engagement.authorization_ref == "H1-ACME-2026-XYZ"
    assert result.engagement.rate_limit_rps == 3
    
    # Verify Policy & Headers
    assert result.policy.required_headers == {
        "X-HackerOne-Research": "0xCyberHero",
        "X-Bug-Bounty-Auth": "Token-12345"
    }
    assert "dos" in result.policy.forbidden_actions
    assert "destructive_write" in result.policy.forbidden_actions
    assert "brute_force" in result.policy.forbidden_actions
    assert "social_engineering" in result.policy.forbidden_actions
    
    # Verify Scope Rules (2 in-scope + 1 out-of-scope)
    assert len(result.scope_rules) == 3
    
    in_scope = [r for r in result.scope_rules if r.effect == ScopeEffect.INCLUDE]
    out_scope = [r for r in result.scope_rules if r.effect == ScopeEffect.EXCLUDE]
    
    assert len(in_scope) == 2
    assert len(out_scope) == 1
    assert out_scope[0].pattern == "billing.acme.corp"
    assert out_scope[0].priority == 50  # higher priority for exclusions
    
    # Verify Checkboxes
    assert result.rule_checkboxes["prohibit_dos_attacks"] is True


def test_parse_yaml_with_markdown_fences():
    fenced = f"```yaml\n{SAMPLE_YAML}\n```"
    result = ProfileParser.parse_yaml(fenced)
    assert result.engagement.name == "Acme Corp Bug Bounty"


def test_dynamic_scope_manager():
    temp_dir = tempfile.mkdtemp()
    db_mgr = DatabaseManager(base_data_dir=temp_dir)
    eng_id = "test-scope-eng-001"
    
    try:
        scope_engine = ScopeEngine()
        manager = DynamicScopeManager(db_mgr, scope_engine, eng_id)
        
        # Add in-scope rule
        r1 = manager.add_rule(
            pattern="*.example.com",
            rule_type=ScopeRuleType.DOMAIN,
            effect=ScopeEffect.INCLUDE,
            priority=10
        )
        assert r1.id is not None
        
        # Verify scope engine allows sub.example.com
        eval1 = scope_engine.evaluate("sub.example.com")
        assert eval1.is_allowed is True
        
        # Add out-of-scope rule dynamically
        r2 = manager.add_rule(
            pattern="admin.example.com",
            rule_type=ScopeRuleType.DOMAIN,
            effect=ScopeEffect.EXCLUDE,
            priority=50
        )
        
        # Verify exclusion overrides inclusion
        eval2 = scope_engine.evaluate("admin.example.com")
        assert eval2.is_allowed is False
        
        # Delete the exclusion rule
        deleted = manager.delete_rule(r2.id)
        assert deleted is True
        
        # Verify admin.example.com is back in scope
        eval3 = scope_engine.evaluate("admin.example.com")
        assert eval3.is_allowed is True
        
    finally:
        db_mgr.dispose()
        shutil.rmtree(temp_dir, ignore_errors=True)
