"""Canonical enumeration definitions across the architecture."""

from enum import Enum


class AgentState(str, Enum):
    """Lifecycle state machine stages (Doc 02, Doc 14)."""
    INITIALIZING = "INITIALIZING"
    POLICY_ANALYSIS = "POLICY_ANALYSIS"
    PREFLIGHT = "PREFLIGHT"
    RECON = "RECON"
    ASSET_MODELING = "ASSET_MODELING"
    APPLICATION_UNDERSTANDING = "APPLICATION_UNDERSTANDING"
    ATTACK_SURFACE_ANALYSIS = "ATTACK_SURFACE_ANALYSIS"
    HYPOTHESIS_GENERATION = "HYPOTHESIS_GENERATION"
    PRIORITIZATION = "PRIORITIZATION"
    TEST_PLANNING = "TEST_PLANNING"
    TEST_EXECUTION = "TEST_EXECUTION"
    RESULT_ANALYSIS = "RESULT_ANALYSIS"
    VERIFICATION = "VERIFICATION"
    HUMAN_ASSISTANCE = "HUMAN_ASSISTANCE"
    MEMORY_UPDATE = "MEMORY_UPDATE"
    REPLANNING = "REPLANNING"
    COVERAGE_EVALUATION = "COVERAGE_EVALUATION"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    BLOCKED = "BLOCKED"


class RiskLevel(str, Enum):
    """Action and test risk classification (Doc 05)."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    BLOCKED = "BLOCKED"


class ScopeRuleType(str, Enum):
    """Supported scope target definitions (Doc 05, Doc 15)."""
    DOMAIN = "DOMAIN"
    SUBDOMAIN_WILDCARD = "SUBDOMAIN_WILDCARD"
    IP_CIDR = "IP_CIDR"
    IP_EXACT = "IP_EXACT"
    URL_PREFIX = "URL_PREFIX"
    URL_REGEX = "URL_REGEX"


class ScopeEffect(str, Enum):
    """Scope rule decision effect."""
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class ConfidenceLevel(str, Enum):
    """Confidence calibration for observations and findings (Doc 03, Doc 15)."""
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class HypothesisStatus(str, Enum):
    """Scientific investigation status (Doc 07, Doc 15)."""
    CANDIDATE = "CANDIDATE"
    TESTING = "TESTING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"


class FindingSeverity(str, Enum):
    """Verified vulnerability severity."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionStatus(str, Enum):
    """Execution protocol lifecycle status (Doc 16)."""
    PROPOSED = "PROPOSED"
    VALIDATING = "VALIDATING"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class AssetType(str, Enum):
    """Discovered or provided asset types (Doc 03, Doc 15)."""
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    HOST = "HOST"
    PORT = "PORT"
    SERVICE = "SERVICE"
    APPLICATION = "APPLICATION"
    API = "API"
    ENDPOINT = "ENDPOINT"
