"""
Shared guard -> resolve -> rewrite logic for MetaSight's "prepare" surface —
used identically by app/api/gateway.py (the Go wire-protocol gateway) and,
via a direct import, Enterprise's /sdk/prepare (metasight_enterprise/api/sdk.py,
for engines/situations the gateway doesn't cover — Oracle, MongoDB, or
clients that can't be network-routed through a gateway host). Deliberately
the ONLY place this logic lives: neither the SDK's driver wrapper nor the
Go gateway's protocol adapters re-implement policy/rewrite logic
themselves — they call back here (via their respective HTTP endpoints) for
a decision, then execute the rewritten query and apply masking on their
own side.

Mirrors app/api/query.py::execute_query_endpoint's guard/resolve/rewrite
steps exactly, minus execution — reuses the same rewriter/policy-engine
helpers that endpoint already uses.
"""
from __future__ import annotations

from typing import Any, List, Optional

from fastapi import HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.models import DataSource
from app.rewriters.sql_rewriter import SQLRewriter, _guard_sql
from app.rewriters.mongo_rewriter import MongoRewriter
from app.services.policy_engine import PolicyEngine
from app.services.masking import masking_level_for_role
from app.services.settings_service import get_settings

_sql_rewriter = SQLRewriter()
_mongo_rewriter = MongoRewriter()

_NOSQL_TYPES = {"mongodb", "elasticsearch", "opensearch", "dynamodb", "redis"}


def _get_dialect(source_type: str) -> str:
    """Mirrors app/api/query.py::_get_dialect exactly — kept as a local copy
    since that one is a private module-level function, not meant for import."""
    _dialect_map = {
        "postgres": "postgres", "postgresql": "postgres",
        "redshift": "redshift", "greenplum": "postgres",
        "cockroach": "postgres", "yugabyte": "postgres",
        "mysql": "mysql", "mariadb": "mysql", "tidb": "mysql",
        "mssql": "tsql", "sqlserver": "tsql", "azuresql": "tsql",
        "snowflake": "snowflake", "bigquery": "bigquery",
        "duckdb": "duckdb", "clickhouse": "clickhouse",
        "databricks": "databricks", "spark": "spark",
        "trino": "trino", "presto": "presto",
        "oracle": "oracle", "oracledb": "oracle",
    }
    return _dialect_map.get(source_type.lower(), "postgres")


class PrepareResponse(BaseModel):
    allowed: bool
    reason: Optional[str] = None
    rewritten_query: Optional[Any] = None
    tables: List[str] = []
    denied_columns: List[str] = []
    masked_columns: List[str] = []
    column_pii_map: dict = {}
    masking_level: str = "full"
    policy_classification: Optional[str] = None


def prepare(db: Session, tenant_id: int, effective_user: dict, source_id: int, query: Any) -> PrepareResponse:
    """Guard + policy + rewrite a query for the given identity/source.
    Never executes anything. Raises HTTPException only for caller errors
    (bad source_id, malformed query shape, an actual server error evaluating
    policy) — a policy *denial* is a normal PrepareResponse(allowed=False),
    not an HTTP error, so callers (SDK, gateway) get one response shape to
    branch on regardless of failure mode."""
    source = db.get(DataSource, source_id)
    if source is None:
        raise HTTPException(404, f"DataSource with id={source_id} not found.")
    source_type = source.type
    is_nosql = source_type in _NOSQL_TYPES

    if is_nosql:
        if not isinstance(query, dict):
            raise HTTPException(422, "NoSQL query must be an object with collection/filter/projection")
        mongo_query = query
        primary_table = mongo_query.get("collection", "default")

        engine_svc = PolicyEngine(db, tenant_id)
        try:
            decision = engine_svc.decide(primary_table, effective_user, source_type=source_type, source_id=source_id)
        except PermissionError as exc:
            return PrepareResponse(allowed=False, reason=str(exc), tables=[primary_table])
        except Exception as exc:
            raise HTTPException(500, f"Policy evaluation error: {exc}")

        if not decision.allowed:
            return PrepareResponse(allowed=False, reason=f"Access denied to resource '{primary_table}'.", tables=[primary_table])

        col_dict = {}
        for c in decision.denied_columns: col_dict[c] = {"action": "deny"}
        for c in decision.masked_columns: col_dict[c] = {"action": "mask"}
        for c in decision.tokenized_columns: col_dict[c] = {"action": "mask"}  # no client-side tokenize path yet — mask instead, fail-safe
        policy_dict = {"row_filters": decision.row_filter_conditions, "columns": col_dict}
        rewritten = _mongo_rewriter.rewrite(dict(mongo_query), policy_dict, effective_user)

        masked_cols = list(set(decision.masked_columns) | set(decision.tokenized_columns))
        role_levels = get_settings(tenant_id, db).get("masking", {}).get("role_levels", None)
        return PrepareResponse(
            allowed=True,
            rewritten_query=rewritten,
            tables=[primary_table],
            denied_columns=decision.denied_columns,
            masked_columns=masked_cols,
            column_pii_map=decision.column_pii_map,
            masking_level=masking_level_for_role(effective_user["role"], role_levels),
            policy_classification=decision.classification,
        )

    if not isinstance(query, str):
        raise HTTPException(422, "SQL query must be a string")
    sql = query

    try:
        _guard_sql(sql)
    except ValueError as exc:
        return PrepareResponse(allowed=False, reason=str(exc))

    tables = _sql_rewriter.get_tables(sql)
    if not tables:
        return PrepareResponse(allowed=False, reason="Could not extract table name from SQL.")

    engine_svc = PolicyEngine(db, tenant_id)
    table_policies = {}
    for table_name in tables:
        try:
            decision = engine_svc.decide(table_name, effective_user, source_type=source_type, source_id=source_id)
        except PermissionError as exc:
            return PrepareResponse(allowed=False, reason=str(exc), tables=tables)
        except Exception as exc:
            raise HTTPException(500, f"Policy evaluation error: {exc}")
        if not decision.allowed:
            return PrepareResponse(allowed=False, reason=f"Access denied to resource '{table_name}'.", tables=tables)
        table_policies[table_name] = decision

    try:
        rewritten_sql, meta = _sql_rewriter.rewrite_with_meta(sql, table_policies, dialect=_get_dialect(source_type))
    except ValueError as exc:
        return PrepareResponse(allowed=False, reason=str(exc), tables=tables)

    primary_decision = table_policies[tables[0]]

    masked_col_keys = list(meta.masked_columns.keys()) or [
        c for dec in table_policies.values() for c in dec.masked_columns
    ]
    tokenize_cols = list(meta.tokenized_columns.keys()) or [
        c for dec in table_policies.values() for c in dec.tokenized_columns
    ]
    denied_col_keys = list(meta.denied_columns) or [
        c for dec in table_policies.values() for c in dec.denied_columns
    ]
    for col in tokenize_cols:
        if col not in masked_col_keys:
            masked_col_keys.append(col)  # no client-side tokenize path yet — mask instead, fail-safe

    combined_pii_map: dict = {}
    for dec in table_policies.values():
        combined_pii_map.update(dec.column_pii_map)
    for dec in table_policies.values():
        for col, mtype in dec.column_masking_type_map.items():
            if mtype:
                combined_pii_map[col] = mtype

    role_levels = get_settings(tenant_id, db).get("masking", {}).get("role_levels", None)
    return PrepareResponse(
        allowed=True,
        rewritten_query=rewritten_sql,
        tables=tables,
        denied_columns=denied_col_keys,
        masked_columns=masked_col_keys,
        column_pii_map=combined_pii_map,
        masking_level=masking_level_for_role(effective_user["role"], role_levels),
        policy_classification=primary_decision.classification,
    )
