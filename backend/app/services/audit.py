import logging
from sqlalchemy.orm import Session
from app.models.models import AuditLog

logger = logging.getLogger(__name__)


class AuditService:
    """Writes audit records to PostgreSQL."""

    def __init__(self, db: Session, tenant_id: int):
        self.db = db
        self.tenant_id = tenant_id

    def log(self, entry: dict) -> None:
        record = AuditLog(
            user_email=entry.get("user_email", "unknown"),
            role=entry.get("role", ""),
            resource=entry.get("resource", ""),
            action=entry.get("action", "query"),
            original_query=str(entry.get("original_query", ""))[:4000] if entry.get("original_query") else None,
            rewritten_query=str(entry.get("rewritten_query", ""))[:4000] if entry.get("rewritten_query") else None,
            policy_applied=entry.get("policy_applied"),
            row_count=entry.get("row_count"),
            tenant_id=self.tenant_id,
        )
        try:
            self.db.add(record)
            self.db.flush()
        except Exception:
            logger.exception("AuditService: failed to write audit record")
