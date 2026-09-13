"""Tool Registry (Doc 04 & Doc 10).

Central catalog of available capabilities and tool adapters.
"""

from typing import Dict, List, Optional
from .base import BaseToolAdapter, ToolCapability, ToolContract
from ..models.enums import RiskLevel


class ToolRegistry:
    """Manages tool adapters and resolves capability requests."""

    def __init__(self):
        self._adapters: Dict[str, BaseToolAdapter] = {}

    def register(self, adapter: BaseToolAdapter) -> None:
        """Register a new tool adapter."""
        contract = adapter.get_contract()
        self._adapters[contract.name] = adapter

    def get_adapter(self, name: str) -> Optional[BaseToolAdapter]:
        """Retrieve an adapter by name."""
        return self._adapters.get(name)

    def find_adapters_by_capability(self, capability: ToolCapability) -> List[BaseToolAdapter]:
        """Find all available adapters that satisfy a requested capability."""
        matches = []
        for adapter in self._adapters.values():
            if adapter.get_contract().capability == capability:
                matches.append(adapter)
        return matches

    def list_tools(self) -> List[ToolContract]:
        """Return contracts for all registered tools."""
        return [adapter.get_contract() for adapter in self._adapters.values()]

    def health_check_all(self) -> Dict[str, bool]:
        """Run health checks across all registered tools."""
        return {name: adapter.health_check() for name, adapter in self._adapters.items()}
