"""Dynamic Scope Manager (Doc 05 & User Scope Control).

Enables adding, removing, and toggling In-Scope and Out-of-Scope rules at runtime
both in the database and the live active ScopeEngine.
"""

from typing import List, Optional
from sqlmodel import select

from ..storage.database import DatabaseManager
from ..models.entities import ScopeRule
from ..models.enums import ScopeRuleType, ScopeEffect
from .scope_engine import ScopeEngine


class DynamicScopeManager:
    """Manages active scope rules dynamically for an engagement."""

    def __init__(self, db_manager: DatabaseManager, scope_engine: ScopeEngine, engagement_id: str):
        self.db_manager = db_manager
        self.scope_engine = scope_engine
        self.engagement_id = engagement_id

    def list_rules(self) -> List[ScopeRule]:
        """Retrieve all active scope rules for the engagement."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(ScopeRule).where(ScopeRule.engagement_id == self.engagement_id).order_by(ScopeRule.priority.desc())
            return session.exec(stmt).all()

    def add_rule(
        self,
        pattern: str,
        rule_type: ScopeRuleType = ScopeRuleType.DOMAIN,
        effect: ScopeEffect = ScopeEffect.INCLUDE,
        priority: int = 10,
        notes: Optional[str] = None
    ) -> ScopeRule:
        """Add a new scope rule and update the live scope engine."""
        rule = ScopeRule(
            engagement_id=self.engagement_id,
            pattern=pattern.strip(),
            rule_type=rule_type,
            effect=effect,
            priority=priority,
            notes=notes
        )
        with self.db_manager.get_session(self.engagement_id) as session:
            session.add(rule)
            session.commit()
            session.refresh(rule)

        # Refresh in-memory scope engine
        self.sync_engine()
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        """Delete an existing scope rule."""
        with self.db_manager.get_session(self.engagement_id) as session:
            rule = session.exec(select(ScopeRule).where(ScopeRule.id == rule_id, ScopeRule.engagement_id == self.engagement_id)).first()
            if not rule:
                return False
            session.delete(rule)
            session.commit()

        self.sync_engine()
        return True

    def sync_engine(self) -> None:
        """Synchronize the in-memory ScopeEngine with all current DB rules."""
        rules = self.list_rules()
        self.scope_engine.set_rules(rules)
