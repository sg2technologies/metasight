"""
Native DB Audit Poller
======================
Polls database-native audit sources on a Celery beat schedule and ingests
the results as DBActivity records (same path as the agent DAM ingest).

Supported sources:
  PostgreSQL → pg_stat_activity (live sessions) + pgaudit log table if present
  SQL Server → sys.dm_exec_sessions + sys.dm_exec_requests
  Oracle     → UNIFIED_AUDIT_TRAIL (requires AUDIT_ADMIN or AUDIT_VIEWER role)
  MySQL      → information_schema.PROCESSLIST

Each DataSource has a DamPollWatermark row that tracks `last_polled_at`
so we only fetch events newer than the previous run.

Call `poll_all_sources(db)` from the Celery task — it handles its own
sub-connections to each target database and writes back to the main DB.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

# Operations we care about (skip idle/sleep/background)
_SKIP_STATES = {"idle", "idle in transaction (aborted)", "disabled", "Sleep"}


def poll_all_sources(db: Session) -> dict:
    """
    Entry point called by the Celery task.
    Iterates all database-type DataSources across all tenants and polls each one.
    Returns a summary dict.
    """
    from app.models.models import DataSource
    from app.core.encryption import aes_cipher

    sources = db.query(DataSource).filter(
        DataSource.category == "database",
    ).all()

    ingested_total = 0
    errors = []

    for ds in sources:
        try:
            if ds.vault_path:
                from app.core.vault_client import fetch_from_vault
                cfg = fetch_from_vault(ds.vault_path) or {}
            else:
                cfg = {k: aes_cipher.decrypt(v) for k, v in (ds.encrypted_config or {}).items()}

            db_type = ds.type.lower().split("+")[0]
            watermark = _get_watermark(ds.id, db)
            since = watermark.last_polled_at - timedelta(seconds=30)  # 30s overlap to avoid gaps

            events = _poll_source(db_type, cfg, ds.id, since)
            for evt in events:
                _ingest_event(evt, ds.tenant_id, db)
                ingested_total += 1

            watermark.last_polled_at = datetime.now(timezone.utc)
            db.commit()
        except Exception as exc:
            log.warning("DAM poll failed for source %s (%s): %s", ds.id, ds.name, exc)
            errors.append({"source_id": ds.id, "error": str(exc)})

    return {"ingested": ingested_total, "errors": errors}


def _get_watermark(data_source_id: int, db: Session):
    from app.models.dam import DamPollWatermark
    wm = db.query(DamPollWatermark).filter(
        DamPollWatermark.data_source_id == data_source_id,
    ).first()
    if not wm:
        wm = DamPollWatermark(
            data_source_id = data_source_id,
            last_polled_at = datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        db.add(wm)
        db.flush()
    return wm


def _poll_source(db_type: str, cfg: dict, source_id: int, since: datetime) -> list[dict]:
    """Dispatch to the right polling query based on db_type."""
    fn = {
        "postgres":  _poll_postgres,
        "postgresql": _poll_postgres,
        "mssql":     _poll_mssql,
        "sqlserver": _poll_mssql,
        "oracle":    _poll_oracle,
        "mysql":     _poll_mysql,
        "mariadb":   _poll_mysql,
    }.get(db_type)

    if fn is None:
        return []

    try:
        return fn(cfg, source_id, since)
    except Exception as exc:
        log.warning("Poll query failed (%s, source=%s): %s", db_type, source_id, exc)
        return []


def _connect(db_type: str, cfg: dict):
    from sqlalchemy import create_engine
    from app.ingestion.native_scanner import _build_url
    url, connect_args = _build_url(db_type, cfg)
    engine = create_engine(url, connect_args=connect_args, pool_pre_ping=True,
                           pool_size=1, max_overflow=0)
    return engine


def _poll_postgres(cfg: dict, source_id: int, since: datetime) -> list[dict]:
    from sqlalchemy import text
    engine = _connect("postgres", cfg)
    events = []
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT
                    pid::text            AS session_pid,
                    usename              AS db_user,
                    client_addr::text    AS client_ip,
                    application_name     AS client_app,
                    datname              AS db_name,
                    state,
                    query,
                    query_start
                FROM pg_stat_activity
                WHERE state NOT IN ('idle', 'disabled')
                  AND pid != pg_backend_pid()
                  AND query_start >= :since
                LIMIT 500
            """), {"since": since}).fetchall()

            for r in rows:
                op = _classify_sql(r.query)
                if not op:
                    continue
                events.append({
                    "agent_name":    "native-poller",
                    "db_type":       "postgres",
                    "data_source_id": source_id,
                    "db_user":       r.db_user or "",
                    "client_ip":     r.client_ip,
                    "client_app":    r.client_app,
                    "db_name":       r.db_name,
                    "operation":     op,
                    "sql_text":      (r.query or "")[:4000],
                    "occurred_at":   r.query_start,
                    "session_pid":   r.session_pid,
                    "status":        "SUCCESS",
                })
    finally:
        engine.dispose()
    return events


def _poll_mssql(cfg: dict, source_id: int, since: datetime) -> list[dict]:
    from sqlalchemy import text
    engine = _connect("mssql", cfg)
    events = []
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT
                    s.session_id,
                    s.login_name         AS db_user,
                    s.client_net_address AS client_ip,
                    s.program_name       AS client_app,
                    DB_NAME(s.database_id) AS db_name,
                    r.status,
                    SUBSTRING(st.text, 1, 4000) AS sql_text,
                    r.start_time
                FROM sys.dm_exec_sessions s
                JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
                CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) st
                WHERE s.is_user_process = 1
                  AND r.start_time >= :since
            """), {"since": since}).fetchall()

            for r in rows:
                op = _classify_sql(r.sql_text)
                if not op:
                    continue
                events.append({
                    "agent_name":    "native-poller",
                    "db_type":       "mssql",
                    "data_source_id": source_id,
                    "db_user":       r.db_user or "",
                    "client_ip":     r.client_ip,
                    "client_app":    r.client_app,
                    "db_name":       r.db_name,
                    "operation":     op,
                    "sql_text":      r.sql_text,
                    "occurred_at":   r.start_time,
                    "session_pid":   str(r.session_id),
                    "status":        "SUCCESS",
                })
    finally:
        engine.dispose()
    return events


def _poll_oracle(cfg: dict, source_id: int, since: datetime) -> list[dict]:
    """Poll Oracle UNIFIED_AUDIT_TRAIL. Requires AUDIT_VIEWER or AUDIT_ADMIN role."""
    from sqlalchemy import text
    engine = _connect("oracle", cfg)
    events = []
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT
                    EVENT_TIMESTAMP,
                    DB_USER,
                    OS_USER,
                    USERHOST      AS client_host,
                    OS_PROCESS    AS session_pid,
                    OBJECT_SCHEMA AS schema_name,
                    OBJECT_NAME   AS object_name,
                    ACTION_NAME   AS operation,
                    SQL_TEXT,
                    RETURN_CODE
                FROM UNIFIED_AUDIT_TRAIL
                WHERE EVENT_TIMESTAMP > :since
                ORDER BY EVENT_TIMESTAMP
                FETCH FIRST 1000 ROWS ONLY
            """), {"since": since}).fetchall()

            for r in rows:
                events.append({
                    "agent_name":    "native-poller",
                    "db_type":       "oracle",
                    "data_source_id": source_id,
                    "db_user":       r.db_user or "",
                    "os_user":       r.os_user,
                    "client_host":   r.client_host,
                    "schema_name":   r.schema_name,
                    "object_name":   r.object_name,
                    "operation":     _normalize_oracle_op(r.operation),
                    "sql_text":      (r.sql_text or "")[:4000],
                    "occurred_at":   r.event_timestamp,
                    "session_pid":   r.session_pid,
                    "status":        "SUCCESS" if r.return_code == 0 else "FAILED",
                })
    finally:
        engine.dispose()
    return events


def _poll_mysql(cfg: dict, source_id: int, since: datetime) -> list[dict]:
    from sqlalchemy import text
    engine = _connect("mysql", cfg)
    events = []
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT
                    ID            AS pid,
                    USER          AS db_user,
                    HOST          AS client_host,
                    DB            AS db_name,
                    COMMAND       AS command,
                    INFO          AS sql_text,
                    TIME          AS exec_time_sec
                FROM information_schema.PROCESSLIST
                WHERE COMMAND NOT IN ('Sleep', 'Binlog Dump', 'Daemon')
                  AND INFO IS NOT NULL
                LIMIT 500
            """)).fetchall()

            now = datetime.now(timezone.utc)
            for r in rows:
                op = _classify_sql(r.sql_text) or r.command.upper()
                if not op or op in ("SLEEP", "DAEMON", "BINLOG DUMP"):
                    continue
                # MySQL PROCESSLIST doesn't expose start_time directly; estimate from TIME
                occurred = now - timedelta(seconds=int(r.exec_time_sec or 0))
                if occurred < since:
                    continue
                events.append({
                    "agent_name":    "native-poller",
                    "db_type":       "mysql",
                    "data_source_id": source_id,
                    "db_user":       r.db_user or "",
                    "client_host":   r.client_host,
                    "db_name":       r.db_name,
                    "operation":     op,
                    "sql_text":      (r.sql_text or "")[:4000],
                    "exec_time_ms":  int(r.exec_time_sec or 0) * 1000,
                    "occurred_at":   occurred,
                    "session_pid":   str(r.pid),
                    "status":        "SUCCESS",
                })
    finally:
        engine.dispose()
    return events


def _ingest_event(evt: dict, tenant_id: int, db: Session) -> None:
    """Write a single polled event as a DBActivity row (no HTTP round-trip)."""
    import hashlib
    from app.models.dam import DBActivity

    op = evt.get("operation", "").upper()
    sql_text = evt.get("sql_text") or ""
    sql_hash = hashlib.sha256(sql_text.encode()).hexdigest()[:16] if sql_text else None

    # Basic risk score
    risk_map = {
        "DROP": 0.6, "TRUNCATE": 0.6, "ALTER": 0.4, "GRANT": 0.5,
        "REVOKE": 0.4, "DELETE": 0.3, "UPDATE": 0.2, "INSERT": 0.15,
        "EXEC": 0.2, "SELECT": 0.05,
    }
    risk_score = risk_map.get(op, 0.1)
    risk_flags = []

    db_user = (evt.get("db_user") or "").lower()
    if any(p in db_user for p in ("sys", "dba", "admin", "root", "sa")):
        risk_score = min(risk_score + 0.2, 1.0)
        risk_flags.append("PRIVILEGED_USER")

    activity = DBActivity(
        tenant_id      = tenant_id,
        agent_name     = evt.get("agent_name", "native-poller"),
        data_source_id = evt.get("data_source_id"),
        db_type        = evt.get("db_type", ""),
        db_user        = evt.get("db_user", ""),
        os_user        = evt.get("os_user"),
        client_ip      = evt.get("client_ip"),
        client_host    = evt.get("client_host"),
        client_app     = evt.get("client_app"),
        db_name        = evt.get("db_name"),
        schema_name    = evt.get("schema_name"),
        object_name    = evt.get("object_name"),
        operation      = op,
        sql_text       = sql_text or None,
        sql_hash       = sql_hash,
        exec_time_ms   = evt.get("exec_time_ms"),
        status         = evt.get("status", "SUCCESS"),
        occurred_at    = evt.get("occurred_at") or datetime.now(timezone.utc),
        risk_score     = round(risk_score, 3),
        risk_flags     = risk_flags,
        session_pid    = evt.get("session_pid"),
    )
    db.add(activity)
    db.flush()

    if risk_score >= 0.7:
        # RiskAlert is an Enterprise-edition model (app/enterprise/models/pam.py).
        # Community's native DAM polling still logs the DBActivity row above
        # either way — risk-alerting on it is an Enterprise bonus when that
        # package happens to be installed, not a Community capability.
        try:
            from metasight_enterprise.models.pam import RiskAlert
        except ImportError:
            RiskAlert = None
        if RiskAlert is not None:
            alert = RiskAlert(
                tenant_id   = tenant_id,
                session_id  = None,
                alert_type  = "PRIVILEGED_USER" if "PRIVILEGED_USER" in risk_flags else "HIGH_RISK_OP",
                severity    = "HIGH" if risk_score >= 0.7 else "MEDIUM",
                risk_score  = risk_score,
                description = f"{op} by {evt.get('db_user')} on {evt.get('object_name')} (native poll)",
                evidence    = {"activity_id": activity.id, "risk_flags": risk_flags},
            )
            db.add(alert)


def _classify_sql(sql: Optional[str]) -> Optional[str]:
    """Extract the DML/DDL verb from a SQL string."""
    if not sql:
        return None
    first = sql.strip().split()[0].upper() if sql.strip() else ""
    known = {"SELECT", "INSERT", "UPDATE", "DELETE", "EXEC", "EXECUTE",
             "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE", "CALL"}
    return first if first in known else None


def _normalize_oracle_op(oracle_action: Optional[str]) -> str:
    """Map Oracle ACTION_NAME to our canonical operation names."""
    if not oracle_action:
        return "UNKNOWN"
    mapping = {
        "SELECT":          "SELECT",
        "INSERT":          "INSERT",
        "UPDATE":          "UPDATE",
        "DELETE":          "DELETE",
        "EXECUTE":         "EXEC",
        "EXECUTE PROCEDURE": "EXEC",
        "CREATE TABLE":    "CREATE",
        "ALTER TABLE":     "ALTER",
        "DROP TABLE":      "DROP",
        "TRUNCATE TABLE":  "TRUNCATE",
        "GRANT":           "GRANT",
        "REVOKE":          "REVOKE",
        "LOGON":           "LOGIN",
        "LOGOFF":          "LOGOUT",
    }
    return mapping.get(oracle_action.upper(), oracle_action.upper()[:32])
