"""
Query execution engine — pooled SQLAlchemy connections to target data sources.
Only SELECT statements are permitted.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass

import sqlglot
from sqlalchemy import create_engine, func as sa_func, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.encryption import aes_cipher
from app.ingestion.native_scanner import _build_url

logger = logging.getLogger(__name__)

# ── Module-level engine pool (keyed by data_source_id) ────────────────────────
_ENGINE_POOL: dict[int, Engine] = {}

_POOL_SIZE = 3
_MAX_OVERFLOW = 5
_POOL_RECYCLE = 1800  # seconds

# Postgres-family source types
_POSTGRES_FAMILY = frozenset({
    "postgres", "postgresql", "redshift", "greenplum",
    "cockroach", "cockroachdb", "yugabyte",
})


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[list]        # raw (unmasked) rows
    row_count: int
    execution_time_ms: float
    dialect: str


def _get_or_create_engine(source_id: int, connector_type: str, config: dict) -> Engine:
    """Return a cached pooled engine, creating one if absent."""
    if source_id in _ENGINE_POOL:
        return _ENGINE_POOL[source_id]

    url, engine_kwargs = _build_url(connector_type, config)

    # SQLite doesn't support connection pools
    if connector_type.lower() == "sqlite":
        engine = create_engine(url, **engine_kwargs)
    else:
        engine = create_engine(
            url,
            pool_size=_POOL_SIZE,
            max_overflow=_MAX_OVERFLOW,
            pool_recycle=_POOL_RECYCLE,
            **engine_kwargs,
        )

    _ENGINE_POOL[source_id] = engine
    logger.info("QueryEngine: created engine pool for source_id=%d (%s)", source_id, connector_type)
    return engine


def invalidate_source_engine(source_id: int) -> None:
    """Dispose and remove a cached engine (call on credential update)."""
    engine = _ENGINE_POOL.pop(source_id, None)
    if engine is not None:
        try:
            engine.dispose()
        except Exception:
            logger.warning("QueryEngine: error disposing engine for source_id=%d", source_id)
        logger.info("QueryEngine: invalidated engine for source_id=%d", source_id)


def _validate_select(sql: str) -> None:
    """Raise ValueError if sql is not a pure SELECT statement."""
    try:
        statements = sqlglot.parse(sql)
    except Exception as exc:
        raise ValueError(f"SQL parse error: {exc}") from exc

    if not statements:
        raise ValueError("Empty SQL statement.")

    for stmt in statements:
        if not isinstance(stmt, sqlglot.exp.Select):
            raise ValueError(
                f"Only SELECT statements are allowed. Got: {type(stmt).__name__}"
            )
        # `SELECT ... INTO <table>` parses as exp.Select but sqlglot re-serializes
        # it as `CREATE TABLE ... AS SELECT ...`, which the target DB executes as
        # DDL — this is the actual execution gate, so it must be rejected here
        # even if it somehow slipped past the rewriter's own guard upstream.
        if list(stmt.find_all(sqlglot.exp.Into)):
            raise ValueError(
                "Query blocked: 'SELECT ... INTO' (table-creating SELECT) is not allowed."
            )


def _inject_limit(sql: str, limit: int, dialect: str = "postgres") -> str:
    """Inject or replace LIMIT clause in a SELECT statement."""
    glot_dialect = dialect.lower()
    if "postgres" in glot_dialect:
        glot_dialect = "postgres"
    elif "mysql" in glot_dialect:
        glot_dialect = "mysql"
    elif "mssql" in glot_dialect or "sqlserver" in glot_dialect or "tsql" in glot_dialect:
        glot_dialect = "tsql"
    elif "oracle" in glot_dialect or "oracledb" in glot_dialect:
        glot_dialect = "oracle"
    else:
        glot_dialect = "postgres"

    # For Oracle, skip sqlglot re-serialization entirely.
    # sqlglot's oracle dialect quotes all identifiers (e.g. ABM_CURRS → "ABM_CURRS"),
    # and quoted identifiers in Oracle only match the current user's own schema —
    # they bypass public synonym resolution — causing ORA-00942 for cross-schema tables.
    if glot_dialect == "oracle":
        clean = sql.rstrip().rstrip(";")
        lower = clean.lower()
        if "fetch first" not in lower and "fetch next" not in lower and "rownum" not in lower:
            return clean + f" FETCH FIRST {limit} ROWS ONLY"
        return clean  # already has pagination clause

    try:
        tree = sqlglot.parse_one(sql, read=glot_dialect)
        existing_limit = tree.args.get("limit")
        def _limit_node(n: int) -> sqlglot.exp.Limit:
            # sqlglot v29+: Limit uses `expression=`, not `this=`
            return sqlglot.exp.Limit(expression=sqlglot.exp.Literal.number(n))

        if existing_limit is None:
            tree.set("limit", _limit_node(limit))
        else:
            try:
                existing_val = int(existing_limit.expression.name)
                if existing_val > limit:
                    tree.set("limit", _limit_node(limit))
            except Exception:
                tree.set("limit", _limit_node(limit))
        return tree.sql(dialect=glot_dialect)
    except Exception as exc:
        logger.warning("sqlglot limit injection failed for %s: %s, using fallback", glot_dialect, exc)
        sql_lower = sql.lower().rstrip().rstrip(";")
        if "limit" not in sql_lower.split()[-3:]:
            clean_sql = sql.rstrip().rstrip(";")
            return clean_sql + f" LIMIT {limit}"
        return sql


def _oracle_qualify_tables(sql: str, source_id: int, tenant_id: int, db: Session) -> str:
    """
    For Oracle, look up each unqualified table reference in the MetaSight catalog
    and prepend its schema owner (e.g. ABM_CURRS → APPS.ABM_CURRS).

    This is necessary when the Oracle connecting user's default schema differs from
    the table's owning schema and no public synonym exists.  Uses plain string
    substitution instead of sqlglot serialization to avoid re-quoting identifiers.
    """
    from app.models.models import (
        Table as CatTable,
        Schema as CatSchema,
        Database as CatDatabase,
        DataSource as CatDataSource,
    )

    # sqlglot's Oracle dialect quotes every identifier (e.g. ABM_CURRS → "ABM_CURRS",
    # abm_currs → "abm_currs").  Quoted identifiers in Oracle are case-sensitive and
    # bypass public synonym resolution, so we strip quotes from all standard Oracle
    # identifiers here.  Identifiers with spaces or other non-standard characters
    # are intentionally left quoted.
    sql = re.sub(r'"([A-Za-z$_][A-Za-z0-9_$#]*)"', r'\1', sql)

    try:
        tree = sqlglot.parse_one(sql)
    except Exception:
        return sql

    # Collect table names from the AST — both unqualified and wrong-schema-qualified.
    # Maps uppercased_table_name → (user_supplied_schema_or_None, catalog_schema)
    to_fix: dict[str, tuple[str | None, str]] = {}

    for tbl_node in tree.find_all(sqlglot.exp.Table):
        tbl_name = tbl_node.name
        key = tbl_name.upper()
        if key in to_fix:
            continue
        user_schema = tbl_node.db.upper() if tbl_node.db else None
        try:
            row = (
                db.query(CatSchema.name)
                .join(CatTable, CatTable.schema_id == CatSchema.id)
                .join(CatDatabase, CatDatabase.id == CatSchema.database_id)
                .join(CatDataSource, CatDataSource.id == CatDatabase.data_source_id)
                .filter(
                    CatDataSource.id == source_id,
                    sa_func.upper(CatTable.name) == key,
                )
                .first()
            )
        except Exception as exc:
            logger.debug("Oracle schema lookup failed for %s: %s", tbl_name, exc)
            continue
        if not (row and row[0]):
            continue
        catalog_schema = row[0].upper()
        if user_schema and user_schema == catalog_schema:
            continue  # already using the correct schema
        to_fix[key] = (user_schema, catalog_schema)

    if not to_fix:
        return sql

    for tbl_upper, (user_schema, catalog_schema) in to_fix.items():
        if user_schema:
            # Replace WRONG_SCHEMA.TABLE with CATALOG_SCHEMA.TABLE
            pattern = re.compile(
                r'(?i)' + re.escape(user_schema) + r'\.' +
                r'(?:"?' + re.escape(tbl_upper) + r'"?)',
            )
            replacement = f"{catalog_schema}.{tbl_upper}"
            new_sql = pattern.sub(replacement, sql)
            if new_sql != sql:
                logger.info("Oracle: corrected schema %s.%s → %s.%s", user_schema, tbl_upper, catalog_schema, tbl_upper)
                sql = new_sql
        else:
            # Inject schema for completely unqualified reference
            pattern = re.compile(
                r'(?<!\.)(?:"' + re.escape(tbl_upper) + r'"|(?<!["\w])' + re.escape(tbl_upper) + r'(?!["\w]))',
                re.IGNORECASE,
            )
            replacement = f"{catalog_schema}.{tbl_upper}"
            sql = pattern.sub(replacement, sql)
            logger.debug("Oracle: qualified %s → %s", tbl_upper, replacement)

    return sql


def execute_query(
    source_id: int,
    sql: str,
    db: Session,
    limit: int = 1000,
) -> QueryResult:
    """
    Load DataSource by source_id, decrypt config, execute SQL, return QueryResult.

    Security:
      - Only SELECT statements allowed.
      - LIMIT capped at min(requested_limit, 10000).
    """
    from app.models.models import DataSource  # local import to avoid circular deps

    # ── 1. Load and decrypt DataSource ────────────────────────────────────────
    source: DataSource | None = db.get(DataSource, source_id)
    if source is None:
        raise ValueError(f"DataSource with id={source_id} not found.")

    encrypted_cfg: dict = source.encrypted_config or {}
    try:
        config = {
            k: aes_cipher.decrypt(v) if isinstance(v, str) else v
            for k, v in encrypted_cfg.items()
        }
    except Exception as exc:
        raise ValueError(f"Failed to decrypt DataSource credentials: {exc}") from exc

    connector_type = source.type

    # ── 2. Cap limit ──────────────────────────────────────────────────────────
    effective_limit = min(limit, 10000)

    # ── 3. Validate: only SELECT ──────────────────────────────────────────────
    _validate_select(sql)

    # ── 4. For Oracle, inject schema qualifiers from the MetaSight catalog ───────
    #    This resolves ORA-00942 when the connecting user's default schema differs
    #    from the table's owning schema and no public synonym exists.
    if connector_type.lower() in ("oracle", "oracledb"):
        sql = _oracle_qualify_tables(sql, source_id, source.tenant_id, db)

    # ── 5. Inject LIMIT using database dialect ────────────────────────────────
    sql_with_limit = _inject_limit(sql, effective_limit, dialect=connector_type)

    # ── 6. Get/create pooled engine ───────────────────────────────────────────
    engine = _get_or_create_engine(source_id, connector_type, config)

    # ── 7. Execute ────────────────────────────────────────────────────────────
    logger.info("QueryEngine [%s] source_id=%d — executing:\n%s", connector_type, source_id, sql_with_limit)
    t_start = time.perf_counter()
    try:
        with engine.connect() as conn:
            result = conn.execute(text(sql_with_limit))
            columns = list(result.keys())
            rows = [list(row) for row in result.fetchall()]
    except Exception as exc:
        logger.error("QueryEngine: execution error for source_id=%d: %s", source_id, exc)
        raise RuntimeError(f"Query execution failed: {exc}") from exc

    elapsed_ms = (time.perf_counter() - t_start) * 1000
    logger.info("QueryEngine [%s] source_id=%d — returned %d rows in %.1f ms", connector_type, source_id, len(rows), elapsed_ms)

    return QueryResult(
        columns=columns,
        rows=rows,
        row_count=len(rows),
        execution_time_ms=round(elapsed_ms, 2),
        dialect=connector_type,
    )
