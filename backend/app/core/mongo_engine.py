"""
MongoDB query execution engine — connects to target, executes MQL, and formats as QueryResult.
"""
from __future__ import annotations

import logging
import time

import pymongo
import urllib.parse
from sqlalchemy.orm import Session

from app.core.query_engine import QueryResult
from app.ingestion.native_scanner import _cfg
from app.models.models import DataSource

logger = logging.getLogger(__name__)


def execute_mongo_query(
    source_id: int,
    query: dict,
    db: Session,
    limit: int = 1000,
) -> QueryResult:
    """
    Load DataSource by source_id, decrypt config, execute MongoDB query (find),
    and return a tabular QueryResult for the UI.
    """
    # ── 1. Load and decrypt DataSource ────────────────────────────────────────
    source: DataSource | None = db.get(DataSource, source_id)
    if source is None:
        raise ValueError(f"DataSource with id={source_id} not found.")

    encrypted_cfg: dict = source.encrypted_config or {}
    from app.core.encryption import aes_cipher
    try:
        config = {
            k: aes_cipher.decrypt(v) if isinstance(v, str) else v
            for k, v in encrypted_cfg.items()
        }
    except Exception as exc:
        raise ValueError(f"Failed to decrypt DataSource credentials: {exc}") from exc

    # ── 2. Build URI ──────────────────────────────────────────────────────────
    host     = _cfg(config, "host", "hostname", default="localhost")
    port     = int(_cfg(config, "port", default="27017"))
    username = _cfg(config, "user", "username")
    password = _cfg(config, "password")
    database = _cfg(config, "database", "dbname")
    auth_src = _cfg(config, "authSource", default="admin")

    if username and password:
        uri = (
            f"mongodb://{urllib.parse.quote_plus(username)}:"
            f"{urllib.parse.quote_plus(password)}@{host}:{port}/"
            f"?authSource={auth_src}"
        )
    elif username and not password:
        uri = f"mongodb://{host}:{port}/"
    else:
        uri = f"mongodb://{host}:{port}/"

    # ── 3. Parse Query Params ─────────────────────────────────────────────────
    coll_name = query.get("collection")
    if not coll_name:
        raise ValueError("MongoDB query must specify a 'collection'. E.g. {\"collection\": \"users\", \"filter\": {}}")

    filter_doc = query.get("filter", {})
    projection = query.get("projection")
    
    # Cap limit
    effective_limit = min(query.get("limit", limit), 10000)

    # ── 4. Execute ────────────────────────────────────────────────────────────
    t_start = time.perf_counter()
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
    
    try:
        mdb = client[database] if database else client.get_database("admin")
        coll = mdb[coll_name]
        
        cursor = coll.find(filter_doc, projection).limit(effective_limit)
        rows_raw = list(cursor)
    except Exception as exc:
        logger.error("MongoEngine: execution error for source_id=%d: %s", source_id, exc)
        client.close()
        raise RuntimeError(f"MongoDB execution failed: {exc}") from exc

    elapsed_ms = (time.perf_counter() - t_start) * 1000
    client.close()

    # ── 5. Format to Tabular QueryResult ──────────────────────────────────────
    if not rows_raw:
        return QueryResult(
            columns=[], rows=[], row_count=0,
            execution_time_ms=round(elapsed_ms, 2), dialect="mongodb"
        )

    # Gather all unique keys across all returned docs (since schema can vary)
    # We maintain insertion order by using dict internally.
    col_dict = {}
    for doc in rows_raw:
        for k in doc.keys():
            col_dict[k] = None
    columns = list(col_dict.keys())

    # Ensure stable column order and stringify complex types
    from bson import ObjectId
    import datetime
    
    def _serialize(v):
        if v is None: return None
        if isinstance(v, ObjectId): return str(v)
        if isinstance(v, dict): return str(v)
        if isinstance(v, list): return str(v)
        if isinstance(v, datetime.datetime): return v.isoformat()
        return v

    processed_rows = []
    for doc in rows_raw:
        row = [_serialize(doc.get(c)) for c in columns]
        processed_rows.append(row)

    return QueryResult(
        columns=columns,
        rows=processed_rows,
        row_count=len(processed_rows),
        execution_time_ms=round(elapsed_ms, 2),
        dialect="mongodb",
    )
