"""Canonical Data Model & Entities (Doc 03 & Doc 15).

Combines Pydantic v2 validation with SQLModel/SQLAlchemy relational persistence.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
import uuid
from sqlmodel import SQLModel, Field, JSON, Column
from pydantic import ConfigDict

from .enums import (
    AgentState,
    RiskLevel,
    ScopeRuleType,
    ScopeEffect,
    ConfidenceLevel,
    HypothesisStatus,
    FindingSeverity,
    ActionStatus,
    AssetType,
)


def generate_uuid() -> str:
    return str(uuid.uuid4())


class BaseModel(SQLModel):
    """Base schema for all persistent entities."""
    id: str = Field(default_factory=generate_uuid, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ----------------------------------------------------------------------
# 1. Engagement & Governance Layer
# ----------------------------------------------------------------------

class Engagement(BaseModel, table=True):
    """Container for an authorized assessment (Doc 03, Doc 15)."""
    name: str
    target_summary: str
    status: AgentState = Field(default=AgentState.INITIALIZING)
    authorization_ref: str
    researcher_identity: str
    rate_limit_rps: int = Field(default=5)
    current_run_id: Optional[str] = None
    time_budget_seconds: Optional[int] = None
    request_budget_count: Optional[int] = None


class Policy(BaseModel, table=True):
    """Normalized rules extracted from client/program requirements (Doc 05)."""
    engagement_id: str = Field(index=True)
    program_name: Optional[str] = None
    source_url_or_file: Optional[str] = None
    testing_window: Optional[str] = None
    allowed_domains: List[str] = Field(default=[], sa_column=Column(JSON))
    forbidden_actions: List[str] = Field(default=[], sa_column=Column(JSON))
    required_headers: Dict[str, str] = Field(default={}, sa_column=Column(JSON))
    is_confirmed_by_user: bool = Field(default=False)


class ScopeRule(BaseModel, table=True):
    """Deterministic scope rule definition."""
    engagement_id: str = Field(index=True)
    rule_type: ScopeRuleType
    pattern: str  # e.g., "api.example.com", "*.example.com", "192.168.1.0/24"
    effect: ScopeEffect = Field(default=ScopeEffect.INCLUDE)
    priority: int = Field(default=10)
    notes: Optional[str] = None


# ----------------------------------------------------------------------
# 2. Knowledge & Attack Surface Layer
# ----------------------------------------------------------------------

class Asset(BaseModel, table=True):
    """Discovered or configured asset."""
    engagement_id: str = Field(index=True)
    asset_type: AssetType
    value: str = Field(index=True)
    parent_id: Optional[str] = None
    discovery_source: str
    in_scope: bool = Field(default=True)
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.CONFIRMED)


class Host(BaseModel, table=True):
    """Network-level host information."""
    engagement_id: str = Field(index=True)
    asset_id: str = Field(index=True)
    hostname: str
    ip_addresses: List[str] = Field(default=[], sa_column=Column(JSON))
    os_detected: Optional[str] = None


class Service(BaseModel, table=True):
    """Network or application service exposed on a host."""
    engagement_id: str = Field(index=True)
    host_id: str = Field(index=True)
    port: int
    protocol: str = Field(default="tcp")
    service_name: str
    banner: Optional[str] = None


class Application(BaseModel, table=True):
    """Logical web or API application."""
    engagement_id: str = Field(index=True)
    name: str
    base_url: str
    technologies: List[str] = Field(default=[], sa_column=Column(JSON))
    auth_mechanisms: List[str] = Field(default=[], sa_column=Column(JSON))


class Endpoint(BaseModel, table=True):
    """Discovered HTTP/API interaction endpoint."""
    engagement_id: str = Field(index=True)
    application_id: str = Field(index=True)
    method: str  # GET, POST, PUT, DELETE, etc.
    path: str
    auth_required: bool = Field(default=False)
    parameters_schema: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    risk_notes: Optional[str] = None


class Parameter(BaseModel, table=True):
    """Specific endpoint parameter model."""
    endpoint_id: str = Field(index=True)
    name: str
    location: str  # query, header, cookie, body, path
    data_type: str = Field(default="string")
    observed_values: List[str] = Field(default=[], sa_column=Column(JSON))


# ----------------------------------------------------------------------
# 3. State & Multi-Account Identity Layer
# ----------------------------------------------------------------------

class UserIdentity(BaseModel, table=True):
    """Authorized test identity/role (User A, User B, Admin)."""
    engagement_id: str = Field(index=True)
    identity_name: str  # e.g., "UserA_Attacker", "UserB_Victim"
    role: str
    credentials_secret_ref: Optional[str] = None  # Pointer to secure vault, never plain password


class SessionRecord(BaseModel, table=True):
    """Authenticated interaction state."""
    engagement_id: str = Field(index=True)
    user_identity_id: str = Field(index=True)
    token_ref: Optional[str] = None
    cookies: Dict[str, str] = Field(default={}, sa_column=Column(JSON))
    is_active: bool = Field(default=True)


class ApplicationState(BaseModel, table=True):
    """Logical state representation (e.g., Cart Filled, MFA Prompt)."""
    engagement_id: str = Field(index=True)
    session_id: str = Field(index=True)
    state_key: str
    state_payload: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))


# ----------------------------------------------------------------------
# 4. Scientific Reasoning & Experiment Layer (Doc 07, Doc 15)
# ----------------------------------------------------------------------

class Observation(BaseModel, table=True):
    """Discovered technical observation (not yet a vulnerability)."""
    engagement_id: str = Field(index=True)
    description: str
    source_tool: str
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM)
    evidence_refs: List[str] = Field(default=[], sa_column=Column(JSON))
    related_endpoint_id: Optional[str] = None


class Hypothesis(BaseModel, table=True):
    """Security hypothesis undergoing testing."""
    engagement_id: str = Field(index=True)
    statement: str
    status: HypothesisStatus = Field(default=HypothesisStatus.CANDIDATE)
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM)
    potential_impact: str
    priority_score: float = Field(default=5.0)
    related_asset_id: Optional[str] = None
    evidence_refs: List[str] = Field(default=[], sa_column=Column(JSON))
    conclusion: Optional[str] = None


class Experiment(BaseModel, table=True):
    """Controlled security test designed to prove or disprove a hypothesis."""
    engagement_id: str = Field(index=True)
    hypothesis_id: str = Field(index=True)
    objective: str
    preconditions: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    expected_signal: str
    actual_signal: Optional[str] = None
    is_verified: bool = Field(default=False)
    conclusion: Optional[str] = None


class Mutation(BaseModel, table=True):
    """Records input alterations for reproducible testing."""
    experiment_id: str = Field(index=True)
    target_parameter: str
    strategy_name: str
    original_value: Optional[str] = None
    mutated_value_preview: str
    result_difference: Optional[str] = None


class Finding(BaseModel, table=True):
    """Fully verified security finding backed by proof."""
    engagement_id: str = Field(index=True)
    hypothesis_id: str = Field(index=True)
    title: str
    severity: FindingSeverity
    cvss_score: Optional[float] = None
    affected_asset: str
    evidence_refs: List[str] = Field(default=[], sa_column=Column(JSON))
    reproduction_steps: str
    remediation_advice: str


# ----------------------------------------------------------------------
# 5. Evidence & Decision Layer (Doc 10, Doc 16, Doc 22)
# ----------------------------------------------------------------------

class Evidence(BaseModel, table=True):
    """Proof artifact record."""
    engagement_id: str = Field(index=True)
    artifact_type: str  # http_request, http_response, screenshot, tool_output
    file_path: str
    sha256_hash: str = Field(index=True)
    metadata_info: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))


class Decision(BaseModel, table=True):
    """Auditable agent decision explanation (Doc 02, Doc 24)."""
    engagement_id: str = Field(index=True)
    action_taken: str
    rationale: str
    expected_outcome: str
    actual_outcome: Optional[str] = None
    next_planned_step: Optional[str] = None
    related_hypothesis_id: Optional[str] = None


class HumanTask(BaseModel, table=True):
    """Structured request for human collaboration (Doc 08, Doc 24)."""
    engagement_id: str = Field(index=True)
    why_needed: str
    action_required: str
    expected_return: str
    status: str = Field(default="OPEN")  # OPEN, RESOLVED, BLOCKED
    user_response: Optional[str] = None


class Checkpoint(BaseModel, table=True):
    """System state snapshot for long-running recovery (Doc 20)."""
    engagement_id: str = Field(index=True)
    state: AgentState
    snapshot_data: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
