"""Deterministic Scope Engine (Doc 05 & Doc 16).

Completely independent of LLMs. Evaluates target hosts, IPs, URLs, and domains
against structured engagement rules with strict exclusion-wins precedence.
"""

import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlparse
from pydantic import BaseModel

from ..models.entities import ScopeRule
from ..models.enums import ScopeRuleType, ScopeEffect


class ScopeEvaluationResult(BaseModel):
    """Deterministic result of evaluating an asset against scope."""
    is_allowed: bool
    reason: str
    matched_rule: Optional[ScopeRule] = None


class ScopeEngine:
    """Evaluates targets against in-memory or database scope rules."""

    def __init__(self, rules: Optional[List[ScopeRule]] = None):
        self.rules: List[ScopeRule] = rules or []

    def set_rules(self, rules: List[ScopeRule]) -> None:
        """Update active scope rules."""
        self.rules = rules

    def evaluate(self, target: str) -> ScopeEvaluationResult:
        """Evaluate a target string (domain, IP, or URL) against all rules.
        
        Rule Evaluation Order:
        1. Explicit EXCLUDE rules always win if matched.
        2. Higher priority rules evaluated first.
        3. If no INCLUDE rule matches, target is disallowed by default (Default-Deny).
        """
        if not self.rules:
            return ScopeEvaluationResult(
                is_allowed=False,
                reason="Default Deny: No scope rules defined for engagement."
            )

        # Normalize target to extract host and possible IP
        host, path = self._extract_host_and_path(target)

        # Sort rules: higher priority first
        sorted_rules = sorted(self.rules, key=lambda r: r.priority, reverse=True)

        # 1. First Pass: Check for any matching EXCLUDE rules
        for rule in sorted_rules:
            if rule.effect == ScopeEffect.EXCLUDE and self._matches_rule(rule, host, path, target):
                return ScopeEvaluationResult(
                    is_allowed=False,
                    reason=f"Blocked by explicit EXCLUDE rule: {rule.pattern} (Rule ID: {rule.id})",
                    matched_rule=rule
                )

        # 2. Second Pass: Check for matching INCLUDE rules
        for rule in sorted_rules:
            if rule.effect == ScopeEffect.INCLUDE and self._matches_rule(rule, host, path, target):
                return ScopeEvaluationResult(
                    is_allowed=True,
                    reason=f"Allowed by matching INCLUDE rule: {rule.pattern} (Rule ID: {rule.id})",
                    matched_rule=rule
                )

        # 3. Default Deny if no include rule matched
        return ScopeEvaluationResult(
            is_allowed=False,
            reason=f"Default Deny: Target '{target}' did not match any in-scope INCLUDE rules."
        )

    def _extract_host_and_path(self, target: str) -> tuple[str, str]:
        """Extract hostname and path from target."""
        target_str = target.strip()
        if "://" in target_str:
            parsed = urlparse(target_str)
            return parsed.hostname or "", parsed.path or "/"
        
        # Could be host/path or just host
        if "/" in target_str:
            parts = target_str.split("/", 1)
            return parts[0].strip(), "/" + parts[1]
        return target_str, "/"

    def _matches_rule(self, rule: ScopeRule, host: str, path: str, full_target: str) -> bool:
        """Evaluate match based on rule type."""
        pattern = rule.pattern.strip().lower()
        host_clean = host.lower()

        if rule.rule_type == ScopeRuleType.DOMAIN:
            if pattern.startswith("*.") or pattern.startswith("*"):
                base_domain = pattern.lstrip("*.")
                if host_clean == base_domain:
                    return True
                return host_clean.endswith("." + base_domain)
            return host_clean == pattern

        elif rule.rule_type == ScopeRuleType.SUBDOMAIN_WILDCARD:
            # Example: *.example.com matches example.com, api.example.com, test.api.example.com
            base_domain = pattern.lstrip("*.")
            if host_clean == base_domain:
                return True
            return host_clean.endswith("." + base_domain)

        elif rule.rule_type == ScopeRuleType.IP_EXACT:
            try:
                target_ip = ipaddress.ip_address(host_clean)
                rule_ip = ipaddress.ip_address(pattern)
                return target_ip == rule_ip
            except ValueError:
                return False

        elif rule.rule_type == ScopeRuleType.IP_CIDR:
            try:
                target_ip = ipaddress.ip_address(host_clean)
                network = ipaddress.ip_network(pattern, strict=False)
                return target_ip in network
            except ValueError:
                return False

        elif rule.rule_type == ScopeRuleType.URL_PREFIX:
            return full_target.startswith(rule.pattern)

        elif rule.rule_type == ScopeRuleType.URL_REGEX:
            try:
                return bool(re.search(rule.pattern, full_target))
            except re.error:
                return False

        return False
