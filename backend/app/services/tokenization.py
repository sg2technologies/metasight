import uuid
import logging
from sqlalchemy.orm import Session
from app.models.models import TokenVault
from app.core.encryption import aes_cipher

logger = logging.getLogger(__name__)


class TokenizationService:
    """AES token vault backed by PostgreSQL. Per-request instance (one DB session)."""

    def __init__(self, db: Session, tenant_id: int):
        self.db = db
        self.tenant_id = tenant_id
        self._cache: dict[str, str] = {}   # value → token (request-scoped)
        self._pending: list[TokenVault] = []  # batch buffer

    def tokenize(self, value: str, column_name: str | None = None) -> str:
        """Tokenize a single value (lazy — buffers until flush_batch is called)."""
        if value in self._cache:
            return self._cache[value]
        token = uuid.uuid4().hex
        encrypted = aes_cipher.encrypt(str(value))
        self._pending.append(TokenVault(
            token=token,
            encrypted_value=encrypted,
            column_name=column_name,
            tenant_id=self.tenant_id,
        ))
        self._cache[value] = token
        return token

    def flush_batch(self) -> int:
        """Bulk-insert all pending vault entries. Returns count flushed."""
        if not self._pending:
            return 0
        self.db.bulk_save_objects(self._pending)
        count = len(self._pending)
        self._pending = []
        logger.debug("TokenizationService: flushed %d vault entries", count)
        return count

    def detokenize(self, token: str, user: dict) -> str:
        if user.get("role") != "admin":
            raise PermissionError("Only admins may detokenize")
        entry = (
            self.db.query(TokenVault)
            .filter(TokenVault.token == token, TokenVault.tenant_id == self.tenant_id)
            .first()
        )
        if not entry:
            raise ValueError("Token not found")
        return aes_cipher.decrypt(entry.encrypted_value)

    def apply_to_rows(self, rows: list[dict], policy: dict, user: dict) -> list[dict]:
        """Post-process query result rows: tokenize flagged columns."""
        col_policies = policy.get("columns", {})
        for row in rows:
            for col, pol in col_policies.items():
                if col in row and pol.get("action") == "tokenize":
                    if user.get("role") not in pol.get("roles_exempt", []):
                        row[col] = self.tokenize(str(row[col]), column_name=col)
        return rows
