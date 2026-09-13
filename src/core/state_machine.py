"""Agent Lifecycle State Machine (Doc 02 & Doc 14).

Manages the explicit state transitions of an assessment, ensuring that phases
occur in an auditable sequence and triggering checkpoints on phase changes.
"""

from typing import Set, Dict, Optional, List
from ..models.enums import AgentState


# Valid forward and looping transitions
ALLOWED_TRANSITIONS: Dict[AgentState, Set[AgentState]] = {
    AgentState.INITIALIZING: {AgentState.POLICY_ANALYSIS, AgentState.BLOCKED},
    AgentState.POLICY_ANALYSIS: {AgentState.PREFLIGHT, AgentState.RECON, AgentState.BLOCKED},
    AgentState.PREFLIGHT: {AgentState.RECON, AgentState.BLOCKED, AgentState.PAUSED},
    AgentState.RECON: {AgentState.ASSET_MODELING, AgentState.BLOCKED, AgentState.PAUSED, AgentState.REPORTING},
    AgentState.ASSET_MODELING: {AgentState.APPLICATION_UNDERSTANDING, AgentState.RECON, AgentState.REPORTING, AgentState.BLOCKED},
    AgentState.APPLICATION_UNDERSTANDING: {AgentState.ATTACK_SURFACE_ANALYSIS, AgentState.RECON, AgentState.BLOCKED},
    AgentState.ATTACK_SURFACE_ANALYSIS: {AgentState.HYPOTHESIS_GENERATION, AgentState.RECON, AgentState.BLOCKED},
    AgentState.HYPOTHESIS_GENERATION: {AgentState.PRIORITIZATION, AgentState.ATTACK_SURFACE_ANALYSIS, AgentState.REPORTING, AgentState.BLOCKED},
    AgentState.PRIORITIZATION: {AgentState.TEST_PLANNING, AgentState.BLOCKED},
    AgentState.TEST_PLANNING: {AgentState.TEST_EXECUTION, AgentState.BLOCKED},
    AgentState.TEST_EXECUTION: {AgentState.RESULT_ANALYSIS, AgentState.BLOCKED},
    AgentState.RESULT_ANALYSIS: {AgentState.VERIFICATION, AgentState.REPLANNING, AgentState.MEMORY_UPDATE, AgentState.BLOCKED},
    AgentState.VERIFICATION: {AgentState.MEMORY_UPDATE, AgentState.REPLANNING, AgentState.REPORTING, AgentState.BLOCKED},
    AgentState.HUMAN_ASSISTANCE: {AgentState.PREFLIGHT, AgentState.TEST_PLANNING, AgentState.VERIFICATION, AgentState.BLOCKED},
    AgentState.MEMORY_UPDATE: {AgentState.REPLANNING, AgentState.COVERAGE_EVALUATION, AgentState.BLOCKED},
    AgentState.REPLANNING: {AgentState.HYPOTHESIS_GENERATION, AgentState.RECON, AgentState.TEST_PLANNING, AgentState.COVERAGE_EVALUATION, AgentState.BLOCKED},
    AgentState.COVERAGE_EVALUATION: {AgentState.REPORTING, AgentState.REPLANNING, AgentState.HYPOTHESIS_GENERATION, AgentState.COMPLETED},
    AgentState.REPORTING: {AgentState.COMPLETED, AgentState.BLOCKED},
    AgentState.PAUSED: {AgentState.PREFLIGHT, AgentState.RECON, AgentState.TEST_EXECUTION},
    AgentState.BLOCKED: {AgentState.HUMAN_ASSISTANCE, AgentState.COMPLETED, AgentState.INITIALIZING},
    AgentState.COMPLETED: {AgentState.RECON, AgentState.PREFLIGHT, AgentState.APPLICATION_UNDERSTANDING, AgentState.REPORTING, AgentState.POLICY_ANALYSIS, AgentState.INITIALIZING},
}


class InvalidStateTransitionError(Exception):
    """Raised when an illegal lifecycle transition is attempted."""
    pass


class LifecycleStateMachine:
    """State machine governing assessment progression."""

    def __init__(self, initial_state: AgentState = AgentState.INITIALIZING):
        self._current_state = initial_state
        self._history: List[AgentState] = [initial_state]

    @property
    def current_state(self) -> AgentState:
        return self._current_state

    @property
    def history(self) -> List[AgentState]:
        return list(self._history)

    def transition_to(self, new_state: AgentState, reason: Optional[str] = None) -> AgentState:
        """Attempt to advance or change state."""
        if new_state == self._current_state:
            return self._current_state

        allowed = ALLOWED_TRANSITIONS.get(self._current_state, set())
        
        # Allow transition to BLOCKED or PAUSED from any active state
        if new_state in {AgentState.BLOCKED, AgentState.PAUSED} and self._current_state != AgentState.COMPLETED:
            pass
        elif new_state not in allowed:
            raise InvalidStateTransitionError(
                f"Invalid transition from '{self._current_state.value}' to '{new_state.value}'. "
                f"Allowed target states: {[s.value for s in allowed]}"
            )

        self._current_state = new_state
        self._history.append(new_state)
        return self._current_state
