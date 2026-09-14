"""
PostgreSQL-native Row Level Security (RLS) backstop.
Applied when a PolicyRule is created/updated for a postgres-family source.
"""
from __future__ import annotations

import logging

from sqlalchemy import create_engine, text

from app.ingestion.native_scanner import _build_url

logger = logging.getLogger(__name__)

_POSTGRES_FAMILY = frozenset({
    "postgres", "postgresql", "redshift", "greenplum",
    "cockroach", "cockroachdb", "yugabyte",
})


def _is_postgres(source_type: str) -> bool:
    return source_type.lower() in _POSTGRES_FAMILY


def sync_pg_rls(policy_rule, data_source, db_config: dict) -> dict:
    """
    For PostgreSQL targets, enable RLS and create/replace a policy
    using current_setting() so the gateway can inject user context.

    Non-postgres sources: no-op (returns status=skipped).

    Args:
        policy_rule: PolicyRule ORM object (has .resource, .row_filters).
        data_source:  DataSource ORM object (has .type).
        db_config:    Decrypted config dict.

    Returns:
        dict with "status" and "sql_applied".
    """
    source_type = data_source.type
    if not _is_postgres(source_type):
        return {"status": "skipped", "sql_applied": []}

    resource = policy_rule.resource
    row_filters: list[dict] = policy_rule.row_filters or []
    policy_name = f"dg_{resource}_rls"

    # Build USING clause from row_filters
    # {user.region} → current_setting('app.user_region', true)
    # {user.email}  → current_setting('app.user_email', true)
    # {user.role}   → current_setting('app.user_role', true)
    # {user.tenant_id} → current_setting('app.tenant_id', true)
    _placeholder_map = {
        "{user.email}":      "current_setting('app.user_email', true)",
        "{user.role}":       "current_setting('app.user_role', true)",
        "{user.region}":     "current_setting('app.user_region', true)",
        "{user.tenant_id}":  "current_setting('app.tenant_id', true)",
        "{user.department}": "current_setting('app.user_department', true)",
    }

    using_clauses: list[str] = []
    for rf in row_filters:
        col = rf.get("column", "")
        operator = rf.get("operator", "=")
        raw_value = str(rf.get("value", ""))

        # Replace placeholder with current_setting() call
        pg_value = raw_value
        for placeholder, pg_fn in _placeholder_map.items():
            pg_value = pg_value.replace(placeholder, pg_fn)

        # If still a literal (no placeholder substituted), wrap in single quotes
        if pg_value == raw_value and not pg_value.startswith("current_setting"):
            pg_value = f"'{pg_value}'"

        if col and operator:
            using_clauses.append(f"{col} {operator} {pg_value}")

    using_expr = " AND ".join(using_clauses) if using_clauses else "true"

    sqls = [
        f"ALTER TABLE {resource} ENABLE ROW LEVEL SECURITY;",
        f"ALTER TABLE {resource} FORCE ROW LEVEL SECURITY;",
        f"DROP POLICY IF EXISTS {policy_name} ON {resource};",
        (
            f"CREATE POLICY {policy_name} ON {resource} "
            f"USING ({using_expr});"
        ),
    ]

    try:
        url, engine_kwargs = _build_url(source_type, db_config)
        engine = create_engine(url, **engine_kwargs)
        with engine.connect() as conn:
            for sql in sqls:
                conn.execute(text(sql))
            conn.commit()
        engine.dispose()
        logger.info("pg_rls: applied RLS policy '%s' on table '%s'", policy_name, resource)
        return {"status": "ok", "sql_applied": sqls}
    except Exception as exc:
        logger.warning("pg_rls: failed to apply RLS for '%s': %s", resource, exc)
        return {"status": "error", "error": str(exc), "sql_applied": sqls}


def apply_session_context(conn, user: dict) -> None:
    """
    Set session-level variables on a PostgreSQL connection before executing a query.
    Uses SET LOCAL so variables are scoped to the current transaction.

    Args:
        conn: An active SQLAlchemy connection.
        user: JWT payload dict with sub, role, tenant_id, and optional attributes.
    """
    settings = {
        "app.user_email":      user.get("sub", ""),
        "app.user_role":       user.get("role", ""),
        "app.user_region":     user.get("region", ""),
        "app.tenant_id":       str(user.get("tenant_id", "")),
        "app.user_department": user.get("department", ""),
    }
    for key, value in settings.items():
        # Escape single quotes in value
        safe_value = str(value).replace("'", "''")
        conn.execute(text(f"SET LOCAL {key} = '{safe_value}'"))
