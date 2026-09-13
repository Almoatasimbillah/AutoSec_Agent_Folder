"""Unit tests for the Lifecycle State Machine (Doc 02, Doc 14)."""

import pytest
from src.core.state_machine import LifecycleStateMachine, InvalidStateTransitionError
from src.models.enums import AgentState


def test_valid_lifecycle_progression():
    sm = LifecycleStateMachine()
    assert sm.current_state == AgentState.INITIALIZING

    # Progress through legitimate phases
    sm.transition_to(AgentState.POLICY_ANALYSIS)
    assert sm.current_state == AgentState.POLICY_ANALYSIS

    sm.transition_to(AgentState.PREFLIGHT)
    assert sm.current_state == AgentState.PREFLIGHT

    sm.transition_to(AgentState.RECON)
    assert sm.current_state == AgentState.RECON

    assert len(sm.history) == 4


def test_invalid_lifecycle_transition_raises_error():
    sm = LifecycleStateMachine()
    # Cannot jump directly from INITIALIZING to TEST_EXECUTION
    with pytest.raises(InvalidStateTransitionError):
        sm.transition_to(AgentState.TEST_EXECUTION)


def test_transition_to_blocked():
    sm = LifecycleStateMachine()
    sm.transition_to(AgentState.POLICY_ANALYSIS)
    sm.transition_to(AgentState.BLOCKED)
    assert sm.current_state == AgentState.BLOCKED
