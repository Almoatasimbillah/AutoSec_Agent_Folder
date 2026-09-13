"""Unit tests for the Deterministic Scope Engine (Doc 05, Doc 16)."""

import pytest
from src.policy.scope_engine import ScopeEngine
from src.models.entities import ScopeRule
from src.models.enums import ScopeRuleType, ScopeEffect


def test_wildcard_subdomain_inclusion():
    rules = [
        ScopeRule(
            engagement_id="test-eng",
            rule_type=ScopeRuleType.SUBDOMAIN_WILDCARD,
            pattern="*.target.com",
            effect=ScopeEffect.INCLUDE
        )
    ]
    engine = ScopeEngine(rules)

    # In scope
    assert engine.evaluate("target.com").is_allowed is True
    assert engine.evaluate("api.target.com").is_allowed is True
    assert engine.evaluate("https://dev.portal.target.com/login").is_allowed is True

    # Out of scope
    assert engine.evaluate("evil-target.com").is_allowed is False
    assert engine.evaluate("target.org").is_allowed is False


def test_exclusion_overrides_inclusion():
    rules = [
        ScopeRule(
            engagement_id="test-eng",
            rule_type=ScopeRuleType.SUBDOMAIN_WILDCARD,
            pattern="*.target.com",
            effect=ScopeEffect.INCLUDE,
            priority=10
        ),
        ScopeRule(
            engagement_id="test-eng",
            rule_type=ScopeRuleType.DOMAIN,
            pattern="billing.target.com",
            effect=ScopeEffect.EXCLUDE,
            priority=50  # Even with lower priority, exclusions win
        )
    ]
    engine = ScopeEngine(rules)

    # General subdomain allowed
    assert engine.evaluate("api.target.com").is_allowed is True

    # Excluded domain blocked
    res = engine.evaluate("billing.target.com")
    assert res.is_allowed is False
    assert "EXCLUDE rule" in res.reason


def test_ip_cidr_evaluation():
    rules = [
        ScopeRule(
            engagement_id="test-eng",
            rule_type=ScopeRuleType.IP_CIDR,
            pattern="10.0.0.0/24",
            effect=ScopeEffect.INCLUDE
        )
    ]
    engine = ScopeEngine(rules)

    # In subnet
    assert engine.evaluate("10.0.0.15").is_allowed is True
    assert engine.evaluate("10.0.0.254").is_allowed is True

    # Out of subnet
    assert engine.evaluate("10.0.1.5").is_allowed is False
    assert engine.evaluate("192.168.1.1").is_allowed is False


def test_default_deny_when_empty():
    engine = ScopeEngine([])
    res = engine.evaluate("https://google.com")
    assert res.is_allowed is False
    assert "Default Deny" in res.reason
