"""Session and Multi-Account Identity Manager (Doc 03, Doc 15, Doc 18).

Manages authorized user identities (e.g., User A, User B, Admin) and maintains
their active authentication contexts (cookies, headers, and tokens) for differential testing.
"""

from typing import Dict, Optional, List
from sqlmodel import select

from ..storage.database import DatabaseManager
from ..models.entities import UserIdentity, SessionRecord
from ..models.enums import ConfidenceLevel


class SessionManager:
    """Manages test identities and their authenticated HTTP session contexts."""

    def __init__(self, db_manager: DatabaseManager, engagement_id: str):
        self.db_manager = db_manager
        self.engagement_id = engagement_id

    def create_identity(self, name: str, role: str) -> UserIdentity:
        """Register an authorized testing identity."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(UserIdentity).where(
                UserIdentity.engagement_id == self.engagement_id,
                UserIdentity.identity_name == name
            )
            existing = session.exec(stmt).first()
            if existing:
                return existing

            identity = UserIdentity(
                engagement_id=self.engagement_id,
                identity_name=name,
                role=role
            )
            session.add(identity)
            session.commit()
            session.refresh(identity)
            return identity

    def set_session_context(
        self,
        identity_id: str,
        cookies: Dict[str, str],
        token_ref: Optional[str] = None
    ) -> SessionRecord:
        """Update or create active session credentials for an identity."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(SessionRecord).where(
                SessionRecord.engagement_id == self.engagement_id,
                SessionRecord.user_identity_id == identity_id
            )
            rec = session.exec(stmt).first()
            if rec:
                rec.cookies = cookies
                rec.token_ref = token_ref
                rec.is_active = True
                session.add(rec)
                session.commit()
                session.refresh(rec)
                return rec

            new_session = SessionRecord(
                engagement_id=self.engagement_id,
                user_identity_id=identity_id,
                cookies=cookies,
                token_ref=token_ref,
                is_active=True
            )
            session.add(new_session)
            session.commit()
            session.refresh(new_session)
            return new_session

    def get_session_for_identity(self, identity_name: str) -> Optional[SessionRecord]:
        """Retrieve the session record for a named identity."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = (
                select(SessionRecord)
                .join(UserIdentity, SessionRecord.user_identity_id == UserIdentity.id)
                .where(
                    UserIdentity.engagement_id == self.engagement_id,
                    UserIdentity.identity_name == identity_name,
                    SessionRecord.is_active == True
                )
            )
            return session.exec(stmt).first()

    def list_identities(self) -> List[UserIdentity]:
        """List all registered identities for this engagement."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(UserIdentity).where(UserIdentity.engagement_id == self.engagement_id)
            return session.exec(stmt).all()
