"""Base Tool Adapter & Contracts (Doc 04 & Doc 16).

Decouples the Agent Brain from specific tool implementations. The Brain requests
capabilities; adapters execute actions and return normalized results.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from ..models.enums import RiskLevel


class ToolCapability(str, Enum):
    """Normalized capabilities requested by the Brain (Doc 04)."""
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_PROBING = "HTTP_PROBING"
    DNS_DISCOVERY = "DNS_DISCOVERY"
    SUBDOMAIN_ENUM = "SUBDOMAIN_ENUM"
    PORT_SCAN = "PORT_SCAN"
    BROWSER_WORKFLOW = "BROWSER_WORKFLOW"
    EVIDENCE_CAPTURE = "EVIDENCE_CAPTURE"


class ToolContract(BaseModel):
    """Tool specification and capabilities."""
    name: str
    version: str
    capability: ToolCapability
    risk_level: RiskLevel = RiskLevel.LOW
    timeout_seconds: int = 30
    requires_network: bool = True
    supported_os: List[str] = Field(default=["windows", "linux"])


class ToolExecutionRequest(BaseModel):
    """Input payload dispatched to a tool adapter."""
    engagement_id: str
    target: str
    capability: ToolCapability
    parameters: Dict[str, Any] = Field(default={})
    injected_headers: Dict[str, str] = Field(default={})
    timeout_seconds: Optional[int] = None


class ToolExecutionResult(BaseModel):
    """Normalized execution response returned to the Agent."""
    success: bool
    tool_name: str
    target: str
    observations: List[Dict[str, Any]] = Field(default=[])
    raw_output: str = ""
    error_message: Optional[str] = None
    execution_time_seconds: float = 0.0
    evidence_artifacts: List[Dict[str, Any]] = Field(default=[])


class BaseToolAdapter(ABC):
    """Abstract base class for all tool wrappers and adapters."""

    @abstractmethod
    def get_contract(self) -> ToolContract:
        """Return declared capabilities and risk constraints."""
        pass

    @abstractmethod
    async def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        """Safely execute the requested capability."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Verify tool availability and operational status."""
        pass
