"""Target Profile and Policy Parser (Doc 05 & User Checkbox System).

Parses standardized YAML profiles (such as those generated via ChatGPT prompt)
into Engagement, Policy, and ScopeRule entities, generating an interactive rule checklist.
"""

from typing import Dict, List, Any, Tuple
import yaml
from pydantic import BaseModel, Field

from ..models.entities import Engagement, Policy, ScopeRule
from ..models.enums import ScopeRuleType, ScopeEffect, AgentState


class ParsedProfileResult(BaseModel):
    """Result of parsing a standardized target profile YAML."""
    engagement: Engagement
    policy: Policy
    scope_rules: List[ScopeRule]
    rule_checkboxes: Dict[str, bool] = Field(default={})
    raw_metadata: Dict[str, Any] = Field(default={})


class ProfileParser:
    """Parses and normalizes target profile YAML strings or files."""

    @staticmethod
    def parse_yaml(yaml_content: str) -> ParsedProfileResult:
        """Parse YAML text and convert into entities and rule checkboxes."""
        clean_yaml = yaml_content.strip()
        # Remove code block fences if copied with ```yaml ... ```
        if clean_yaml.startswith("```"):
            lines = clean_yaml.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            clean_yaml = "\n".join(lines).strip()

        data = yaml.safe_load(clean_yaml) or {}

        meta = data.get("program_metadata", {})
        net = data.get("network_and_headers", {})
        scope_def = data.get("scope_definition", {})
        checkboxes = data.get("rule_checkboxes", {})

        # 1. Build Engagement
        engagement = Engagement(
            name=meta.get("program_name", "Unnamed Assessment"),
            target_summary=meta.get("target_summary", "Security Evaluation"),
            authorization_ref=meta.get("authorization_reference", "AUTH-PENDING"),
            researcher_identity=meta.get("researcher_handle", "sec-researcher"),
            rate_limit_rps=int(net.get("rate_limit_rps", 5)),
            status=AgentState.INITIALIZING
        )

        # 2. Derive forbidden actions from checkboxes
        forbidden_actions: List[str] = []
        if checkboxes.get("prohibit_dos_attacks", True):
            forbidden_actions.extend(["dos", "denial_of_service", "stress_test"])
        if checkboxes.get("prohibit_destructive_writes", True):
            forbidden_actions.extend(["destructive_write", "drop_table", "delete_all"])
        if checkboxes.get("prohibit_credential_bruteforce", True):
            forbidden_actions.extend(["brute_force", "credential_stuffing"])
        if checkboxes.get("prohibit_social_engineering", True):
            forbidden_actions.extend(["phishing", "social_engineering"])
        if checkboxes.get("prohibit_third_party_testing", True):
            forbidden_actions.extend(["third_party"])

        # 3. Build Policy
        mandatory_headers = net.get("mandatory_headers", {}) or {}
        policy = Policy(
            engagement_id=engagement.id,
            program_name=meta.get("program_name", ""),
            forbidden_actions=forbidden_actions,
            required_headers=mandatory_headers,
            is_confirmed_by_user=True
        )

        # 4. Build Scope Rules
        scope_rules: List[ScopeRule] = []

        def normalize_rule_type(t_str: str, pattern: str = "") -> ScopeRuleType:
            t = (t_str or "").strip().upper()
            if pattern.startswith("*.") or pattern.startswith("*"):
                return ScopeRuleType.SUBDOMAIN_WILDCARD
            mapping = {
                "DOMAIN": ScopeRuleType.DOMAIN,
                "SUBDOMAIN_WILDCARD": ScopeRuleType.SUBDOMAIN_WILDCARD,
                "IP_CIDR": ScopeRuleType.IP_CIDR,
                "IP_RANGE": ScopeRuleType.IP_CIDR,
                "CIDR": ScopeRuleType.IP_CIDR,
                "IP_EXACT": ScopeRuleType.IP_EXACT,
                "IP": ScopeRuleType.IP_EXACT,
                "URL_PREFIX": ScopeRuleType.URL_PREFIX,
                "URL": ScopeRuleType.URL_PREFIX,
                "URL_REGEX": ScopeRuleType.URL_REGEX
            }
            return mapping.get(t, ScopeRuleType.DOMAIN)

        # Parse In-Scope items
        for item in scope_def.get("in_scope", []):
            pattern = item.get("pattern", "").strip()
            if not pattern:
                continue
            rule_type = normalize_rule_type(item.get("type", "DOMAIN"), pattern)
            scope_rules.append(ScopeRule(
                engagement_id=engagement.id,
                rule_type=rule_type,
                pattern=pattern,
                effect=ScopeEffect.INCLUDE,
                priority=10,
                notes=item.get("notes")
            ))

        # Parse Out-Of-Scope items (Exclusions have higher priority: 50)
        for item in scope_def.get("out_of_scope", []):
            pattern = item.get("pattern", "").strip()
            if not pattern:
                continue
            rule_type = normalize_rule_type(item.get("type", "DOMAIN"), pattern)
            scope_rules.append(ScopeRule(
                engagement_id=engagement.id,
                rule_type=rule_type,
                pattern=pattern,
                effect=ScopeEffect.EXCLUDE,
                priority=50,
                notes=item.get("notes")
            ))

        return ParsedProfileResult(
            engagement=engagement,
            policy=policy,
            scope_rules=scope_rules,
            rule_checkboxes=checkboxes,
            raw_metadata=data
        )
