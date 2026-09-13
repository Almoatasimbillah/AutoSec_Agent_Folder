"""Engagement Database Manager (Doc 03, Doc 11 & Doc 15).

Provides physical database isolation by maintaining an independent SQLite database
for every engagement in its dedicated directory.
"""

from pathlib import Path
from typing import Dict, Optional
from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy.engine import Engine


class DatabaseManager:
    """Manages isolated SQLite engines per engagement."""

    def __init__(self, base_data_dir: str = "data/engagements"):
        self.base_data_dir = Path(base_data_dir)
        self.base_data_dir.mkdir(parents=True, exist_ok=True)
        self._engines: Dict[str, Engine] = {}

    def get_engine(self, engagement_id: str) -> Engine:
        """Get or initialize SQLite engine for a specific engagement."""
        if engagement_id not in self._engines:
            engagement_dir = self.base_data_dir / engagement_id
            engagement_dir.mkdir(parents=True, exist_ok=True)
            
            db_path = engagement_dir / "engagement.db"
            engine = create_engine(
                f"sqlite:///{db_path.as_posix()}",
                connect_args={"check_same_thread": False},
                echo=False
            )
            # Create all canonical tables
            SQLModel.metadata.create_all(engine)
            self._engines[engagement_id] = engine

        return self._engines[engagement_id]

    def get_session(self, engagement_id: str) -> Session:
        """Get a fresh SQLModel Session for an engagement."""
        engine = self.get_engine(engagement_id)
        return Session(engine, expire_on_commit=False)

    def dispose(self, engagement_id: Optional[str] = None) -> None:
        """Dispose of engines to release open file locks (essential for Windows)."""
        if engagement_id:
            if engagement_id in self._engines:
                self._engines[engagement_id].dispose()
                del self._engines[engagement_id]
        else:
            for engine in self._engines.values():
                engine.dispose()
            self._engines.clear()
