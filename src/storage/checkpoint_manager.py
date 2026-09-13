"""Checkpoint Manager (Doc 20 & Doc 24).

Captures and restores execution snapshots for long-running autonomous assessments.
"""

from typing import Dict, Any, Optional
from datetime import datetime
from sqlmodel import select

from .database import DatabaseManager
from ..models.entities import Checkpoint
from ..models.enums import AgentState


class CheckpointManager:
    """Saves and restores assessment checkpoints."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def save_checkpoint(
        self,
        engagement_id: str,
        current_state: AgentState,
        snapshot_data: Dict[str, Any]
    ) -> Checkpoint:
        """Save a new recovery checkpoint."""
        checkpoint = Checkpoint(
            engagement_id=engagement_id,
            state=current_state,
            snapshot_data=snapshot_data
        )
        with self.db_manager.get_session(engagement_id) as session:
            session.add(checkpoint)
            session.commit()
            session.refresh(checkpoint)
        return checkpoint

    def get_latest_checkpoint(self, engagement_id: str) -> Optional[Checkpoint]:
        """Retrieve the most recent checkpoint for an engagement."""
        with self.db_manager.get_session(engagement_id) as session:
            statement = (
                select(Checkpoint)
                .where(Checkpoint.engagement_id == engagement_id)
                .order_by(Checkpoint.created_at.desc())
            )
            result = session.exec(statement).first()
            return result
