import logging
from app.models.models import Database, Schema, Table, ColumnEntity

try:
    from openmetadata.ingestion.sink.sink import Sink
except ImportError:
    # Allow the module to load without openmetadata-ingestion installed.
    # CustomSink will only be instantiated when a scan actually runs.
    Sink = object  # type: ignore[assignment,misc]
from sqlalchemy.dialects.postgresql import insert

logger = logging.getLogger(__name__)


class CustomSink(Sink):
    """Persists OpenMetadata records into the local PostgreSQL store.

    Inserts are batched and committed once in ``close()`` to avoid
    per-record round-trips on large schemas.
    """

    def __init__(self, db, tenant_id: int):
        self.db = db
        self.tenant_id = tenant_id
        self._record_count = 0

    def write_record(self, record: dict):
        rtype = record.get("type")
        try:
            if rtype == "database":
                stmt = insert(Database).values(
                    name=record["name"],
                    tenant_id=self.tenant_id,
                    data_source_id=record.get("data_source_id"),
                )
                self.db.execute(stmt.on_conflict_do_nothing())

            elif rtype == "schema":
                stmt = insert(Schema).values(
                    name=record["name"],
                    database_id=record["database_id"],
                    tenant_id=self.tenant_id,
                )
                self.db.execute(stmt.on_conflict_do_nothing())

            elif rtype == "table":
                stmt = insert(Table).values(
                    name=record["name"],
                    schema_id=record["schema_id"],
                    tenant_id=self.tenant_id,
                )
                self.db.execute(stmt.on_conflict_do_nothing())

            elif rtype == "column":
                stmt = insert(ColumnEntity).values(
                    name=record["name"],
                    type=record["col_type"],
                    table_id=record["table_id"],
                    tenant_id=self.tenant_id,
                )
                self.db.execute(stmt.on_conflict_do_nothing())

            else:
                logger.debug("CustomSink: unknown record type %r — skipped", rtype)
                return

            self._record_count += 1

        except Exception:
            logger.exception("CustomSink: failed to write record type=%r", rtype)
            raise

    def close(self):
        """Commit the entire ingestion batch as a single transaction."""
        try:
            self.db.commit()
            logger.info("CustomSink: committed %d records", self._record_count)
        except Exception:
            self.db.rollback()
            logger.exception("CustomSink: commit failed — rolled back")
            raise
