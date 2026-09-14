"""
Native database scanner using SQLAlchemy reflection + sqlglot type normalization.

Supports every database with a SQLAlchemy dialect:
  PostgreSQL family : postgres, redshift, greenplum, cockroach, yugabyte
  MySQL family      : mysql, mariadb, doris, tidb
  SQL Server family : mssql, sqlserver, azuresql, synapse, fabric
  Oracle            : oracle
  SQLite            : sqlite
  Snowflake         : snowflake
  BigQuery          : bigquery
  DuckDB            : duckdb
  ClickHouse        : clickhouse
  Databricks        : databricks, delta_lake
  Trino             : trino
  Presto            : presto
  Hive/Spark        : hive, spark, sparksql, impala
  Athena            : athena
  Teradata          : teradata
  Vertica           : vertica
  DB2               : db2
  Exasol            : exasol
  Druid             : druid
  PinotDB           : pinotdb
  SAP HANA          : saphana

Non-SQL connectors (MongoDB, Cassandra, Elasticsearch, DynamoDB, …) raise
NotImplementedError so the caller can fall back gracefully.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

import sqlglot
from sqlalchemy import create_engine, inspect, select, text, update as sa_update
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models.models import (
    Database as DBDatabase,
    Schema as DBSchema,
    Table as DBTable,
    ColumnEntity,
)

logger = logging.getLogger(__name__)

# Commit to PostgreSQL after this many tables — limits transaction size and memory
_COMMIT_EVERY = 200
# Max rows per batch INSERT to stay within PostgreSQL parameter limit (32767 / 8 cols)
_COL_BATCH_SIZE = 1000


def _write_progress(db: Session, scan_id: int, progress: dict) -> None:
    """Write live scan progress to scan_runs.progress (best-effort)."""
    try:
        from app.models.models import ScanRun
        db.execute(sa_update(ScanRun).where(ScanRun.id == scan_id).values(progress=progress))
        db.commit()
    except Exception:
        pass


# ── PII auto-detection ────────────────────────────────────────────────────────

_PII_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"(?i)\bemail\b"), "PII", "PII"),
    (re.compile(r"(?i)\bssn\b|\bsocial_security\b"), "PII", "PII"),
    (re.compile(r"(?i)\bphone\b|\bcell\b|\bmobile\b"), "PII", "PII"),
    (re.compile(r"(?i)\bpassword\b|\bpasshash\b|\bsecret\b"), "PSI", "RESTRICTED"),
    (re.compile(r"(?i)\baddress\b|\bcity\b|\bzip\b"), "PII", "PII"),
    (re.compile(r"(?i)\bcredit_card\b|\bcc_num\b"), "PSI", "FINANCIAL"),
    (re.compile(r"(?i)\bmedical\b|\bhealth\b|\bpatient\b|\bdiagnosis\b"), "PHI", "PII"),
]

def _detect_pii(col_name: str) -> tuple[Optional[str], Optional[str]]:
    for pattern, pii_type, classification in _PII_PATTERNS:
        if pattern.search(col_name):
            return pii_type, classification
    return None, None


# ── Type normalization via sqlglot ─────────────────────────────────────────────

# Map our connector type → sqlglot dialect name (None = no normalization)
_SQLGLOT_DIALECT: dict[str, str | None] = {
    "postgres":    "postgres",
    "postgresql":  "postgres",
    "redshift":    "redshift",
    "greenplum":   "postgres",
    "cockroach":   "postgres",
    "yugabyte":    "postgres",
    "mysql":       "mysql",
    "mariadb":     "mysql",
    "doris":       "doris",
    "tidb":        "mysql",
    "mssql":       "tsql",
    "sqlserver":   "tsql",
    "azuresql":    "tsql",
    "synapse":     "tsql",
    "fabric":      "tsql",
    "oracle":      "oracle",
    "sqlite":      "sqlite",
    "snowflake":   "snowflake",
    "bigquery":    "bigquery",
    "duckdb":      "duckdb",
    "clickhouse":  "clickhouse",
    "databricks":  "databricks",
    "delta_lake":  "databricks",
    "trino":       "trino",
    "presto":      "presto",
    "hive":        "hive",
    "spark":       "spark",
    "sparksql":    "spark",
    "impala":      "hive",
    "athena":      "athena",
    "teradata":    "teradata",
    "druid":       "druid",
    "exasol":      "exasol",
    # drivers without sqlglot dialect — return as-is
    "vertica":     None,
    "db2":         None,
    "saphana":     None,
    "pinotdb":     None,
}


def _normalize_type(sa_type_obj, connector_type: str) -> str:
    """
    Convert a SQLAlchemy type object to a canonical string via sqlglot.
    Falls back to str(type) if sqlglot can't parse it.
    """
    raw = str(sa_type_obj)
    dialect = _SQLGLOT_DIALECT.get(connector_type.lower())
    if not dialect:
        return raw
    try:
        # Wrap in a dummy CREATE TABLE so sqlglot can parse the type token
        parsed = sqlglot.parse_one(f"CREATE TABLE _t (_c {raw})", dialect=dialect)
        col_def = parsed.find(sqlglot.exp.ColumnDef)
        if col_def and col_def.kind is not None:
            return col_def.kind.sql()   # canonical ANSI form
    except Exception:
        pass
    return raw


# ── Schema exclusion lists ─────────────────────────────────────────────────────

_EXCLUDE_SCHEMAS: dict[str, set[str]] = {
    "postgres":   {"pg_catalog", "information_schema", "pg_toast"},
    "redshift":   {"pg_catalog", "information_schema", "pg_toast"},
    "greenplum":  {"pg_catalog", "information_schema", "pg_toast"},
    "cockroach":  {"pg_catalog", "information_schema", "crdb_internal"},
    "yugabyte":   {"pg_catalog", "information_schema"},
    "mysql":      {"information_schema", "performance_schema", "mysql", "sys"},
    "mariadb":    {"information_schema", "performance_schema", "mysql", "sys"},
    "doris":      {"information_schema"},
    "tidb":       {"information_schema", "performance_schema", "mysql", "sys"},
    "mssql":      {"sys", "INFORMATION_SCHEMA"},
    "sqlserver":  {"sys", "INFORMATION_SCHEMA"},
    "azuresql":   {"sys", "INFORMATION_SCHEMA"},
    "synapse":    {"sys", "INFORMATION_SCHEMA"},
    "fabric":     {"sys", "INFORMATION_SCHEMA"},
    "oracle":     set(),
    "snowflake":  {"INFORMATION_SCHEMA"},
    "bigquery":   set(),
    "duckdb":     {"information_schema", "pg_catalog"},
    "clickhouse": {"information_schema", "INFORMATION_SCHEMA", "system"},
    "databricks": {"information_schema"},
    "delta_lake": {"information_schema"},
    "trino":      {"information_schema"},
    "presto":     {"information_schema"},
    "hive":       set(),
    "spark":      {"information_schema"},
    "athena":     {"information_schema"},
    "teradata":   {"DBC", "dbcmngr", "SYSLIB", "TDWM"},
    "vertica":    {"v_catalog", "v_monitor", "v_internal"},
    "db2":        {"SYSIBM", "SYSCAT", "SYSSTAT", "SYSPUBLIC"},
    "saphana":    {"SYS", "HANA_XS_BASE"},
    "exasol":     {"SYS"},
    "druid":      set(),
    "pinotdb":    set(),
    "sqlite":     set(),
}


def _excluded_schemas(connector_type: str) -> set[str]:
    ct = connector_type.lower()
    return _EXCLUDE_SCHEMAS.get(ct, set())


# ── Fast schema stats — no write to DB ────────────────────────────────────────

def list_schemas_with_stats(source_type: str, config: dict) -> list:
    """
    Returns a fast schema listing with table/row-count estimates.
    Does NOT write to the DB — used for the schema browser UI before running a scan.
    Each item: {"schema_name": str, "table_count": int, "estimated_rows": int}
    """
    from app.ingestion.nosql_scanner import is_nosql
    if is_nosql(source_type):
        return []

    url, engine_kwargs = _build_url(source_type, config)
    engine = create_engine(url, **engine_kwargs)
    ct = source_type.lower()
    excluded = _excluded_schemas(ct)

    try:
        with engine.connect() as conn:
            return _fast_schema_stats(conn, ct, excluded)
    except Exception as exc:
        logger.warning("Fast schema stats failed for %s, using inspector fallback: %s", source_type, exc)
        try:
            inspector = inspect(engine)
            excl_lower = {e.lower() for e in excluded}
            return [
                {"schema_name": s, "table_count": 0, "estimated_rows": 0}
                for s in inspector.get_schema_names()
                if s.lower() not in excl_lower
            ]
        except Exception:
            return []
    finally:
        engine.dispose()


def _fast_schema_stats(conn, ct: str, excluded: set) -> list:
    """Per-database aggregate query: schema name + table count + estimated row count."""

    def excl(col: str) -> str:
        if not excluded:
            return ""
        vals = ", ".join(f"'{e}'" for e in excluded)
        return f"AND {col} NOT IN ({vals})"

    if ct in ("oracle", "oracledb"):
        # ALL_TABLES.NUM_ROWS = last-analyzed stat; accurate after GATHER_SCHEMA_STATS
        # LEFT JOIN all_users so we list all schemas (even empty ones)
        sql = f"""
            SELECT u.username, COUNT(t.table_name), COALESCE(SUM(t.num_rows), 0)
            FROM all_users u
            LEFT JOIN all_tables t ON t.owner = u.username
            WHERE 1=1 {excl("u.username")}
            GROUP BY u.username ORDER BY u.username
        """
    elif ct in ("postgres", "postgresql", "redshift", "greenplum", "cockroach", "yugabyte"):
        # reltuples = -1 means never analyzed; clamp to 0
        sql = f"""
            SELECT n.nspname,
                   COUNT(c.relname),
                   COALESCE(SUM(GREATEST(c.reltuples::bigint, 0)), 0)
            FROM pg_namespace n
            LEFT JOIN pg_class c ON c.relnamespace = n.oid AND c.relkind = 'r'
            WHERE n.nspname NOT LIKE 'pg_%' {excl("n.nspname")}
            GROUP BY n.nspname ORDER BY n.nspname
        """
    elif ct in ("mysql", "mariadb", "tidb", "doris"):
        sql = f"""
            SELECT TABLE_SCHEMA, COUNT(*), COALESCE(SUM(TABLE_ROWS), 0)
            FROM information_schema.TABLES
            WHERE TABLE_TYPE = 'BASE TABLE' {excl("TABLE_SCHEMA")}
            GROUP BY TABLE_SCHEMA ORDER BY TABLE_SCHEMA
        """
    elif ct in ("mssql", "sqlserver", "azuresql", "synapse", "fabric"):
        sql = f"""
            SELECT s.name, COUNT(t.name), COALESCE(SUM(p.rows), 0)
            FROM sys.schemas s
            LEFT JOIN sys.tables t ON t.schema_id = s.schema_id
            LEFT JOIN sys.indexes i
                   ON i.object_id = t.object_id AND i.index_id IN (0, 1)
            LEFT JOIN sys.partitions p
                   ON p.object_id = t.object_id AND p.index_id = i.index_id
            WHERE 1=1 {excl("s.name")}
            GROUP BY s.name ORDER BY s.name
        """
    else:
        raise NotImplementedError(f"No fast stats query for connector type '{ct}'")

    result = conn.execute(text(sql))
    return [
        {
            "schema_name": str(row[0]),
            "table_count": int(row[1] or 0),
            "estimated_rows": int(row[2] or 0),
        }
        for row in result
    ]


# ── SQLAlchemy URL builders ────────────────────────────────────────────────────

def _cfg(c: dict, *keys, default=""):
    """Try multiple key aliases, return first match."""
    for k in keys:
        if k in c and c[k] is not None and str(c[k]).strip():
            return str(c[k]).strip()
    return default


def _build_url(connector_type: str, cfg: dict) -> tuple[URL, dict]:
    """
    Returns (SQLAlchemy URL, create_engine kwargs) for the given connector type.
    Raises ImportError with pip install hint if the required driver is missing.
    Raises NotImplementedError for non-SQL connectors.
    """
    ct = connector_type.lower()
    host     = _cfg(cfg, "host", "hostPort", default="localhost")
    port_raw = _cfg(cfg, "port")
    user     = _cfg(cfg, "username", "user")
    password = _cfg(cfg, "password")
    database = _cfg(cfg, "database", "dbname", "catalog")

    def port(default: int) -> int:
        try:
            return int(port_raw) if port_raw else default
        except ValueError:
            return default

    # ── PostgreSQL family ──────────────────────────────────────────────────────
    if ct in ("postgres", "postgresql", "redshift", "greenplum", "cockroach",
              "cockroachdb", "yugabyte"):
        _require("psycopg2", "psycopg2-binary")
        driver = "postgresql+psycopg2"
        return (
            URL.create(driver, username=user, password=password,
                       host=host, port=port(5432), database=database or "postgres"),
            {},
        )

    # ── MySQL family ──────────────────────────────────────────────────────────
    if ct in ("mysql", "mariadb", "doris", "tidb"):
        _require("pymysql", "PyMySQL")
        return (
            URL.create("mysql+pymysql", username=user, password=password,
                       host=host, port=port(3306), database=database),
            {"connect_args": {"connect_timeout": 10}},
        )

    # ── SQL Server family ──────────────────────────────────────────────────────
    if ct in ("mssql", "sqlserver", "azuresql", "synapse", "fabric"):
        if _driver_available("pymssql"):
            return (
                URL.create("mssql+pymssql", username=user, password=password,
                           host=host, port=port(1433), database=database),
                {},
            )
        _require("pyodbc", "pyodbc")
        driver_str = "ODBC Driver 17 for SQL Server"
        return (
            URL.create("mssql+pyodbc", username=user, password=password,
                       host=host, port=port(1433), database=database,
                       query={"driver": driver_str}),
            {},
        )

    # ── Oracle ────────────────────────────────────────────────────────────────
    if ct in ("oracle", "oracledb"):
        service = _cfg(cfg, "oracleServiceName", "serviceName", "service_name", "sid", default=database)
        thick_mode = _cfg(cfg, "thick_mode", "thickMode", default="").lower() in ("true", "1", "yes")
        lib_dir = _cfg(cfg, "oracle_client_path", "oracleClientPath", default="") or None

        if _driver_available("oracledb"):
            if thick_mode:
                import oracledb as _odb
                try:
                    _odb.init_oracle_client(lib_dir=lib_dir)
                except Exception:
                    pass  # already initialized or lib_dir auto-detected
            return (
                URL.create("oracle+oracledb", username=user, password=password),
                {
                    "connect_args": {
                        "host": host,
                        "port": port(1521),
                        "service_name": service,
                    }
                },
            )
        _require("cx_Oracle", "cx_Oracle")
        return (
            URL.create("oracle+cx_oracle", username=user, password=password,
                       host=host, port=port(1521), database=service),
            {},
        )

    # ── SQLite ────────────────────────────────────────────────────────────────
    if ct == "sqlite":
        from sqlalchemy.engine import make_url
        db_path = _cfg(cfg, "database", "path", default=":memory:")
        if not db_path:
            db_path = ":memory:"
        return make_url(f"sqlite:///{db_path}"), {}

    # ── Snowflake ─────────────────────────────────────────────────────────────
    if ct == "snowflake":
        _require("snowflake.sqlalchemy", "snowflake-sqlalchemy")
        account   = _cfg(cfg, "account")
        warehouse = _cfg(cfg, "warehouse")
        role      = _cfg(cfg, "role")
        schema    = _cfg(cfg, "connectionOptions.defaultSchemaName", "schema")
        q: dict = {}
        if warehouse:
            q["warehouse"] = warehouse
        if role:
            q["role"] = role
        if schema:
            q["schema"] = schema
        return (
            URL.create("snowflake", username=user, password=password,
                       host=account, database=database, query=q),
            {},
        )

    # ── BigQuery ──────────────────────────────────────────────────────────────
    if ct == "bigquery":
        _require("sqlalchemy_bigquery", "sqlalchemy-bigquery")
        project = _cfg(cfg, "projectId", "project", default=database)
        dataset = _cfg(cfg, "datasetId", "dataset")
        location = _cfg(cfg, "location", default="US")
        cred_file = _cfg(cfg, "credentialsPath", "keyfile")
        connect_args: dict = {"location": location}
        if cred_file:
            connect_args["credentials_path"] = cred_file
        db_str = f"{project}/{dataset}" if dataset else project
        return URL.create(f"bigquery://{db_str}"), {"connect_args": connect_args}

    # ── DuckDB ────────────────────────────────────────────────────────────────
    if ct == "duckdb":
        _require("duckdb_engine", "duckdb-engine")
        db_path = _cfg(cfg, "database", "path", default=":memory:")
        return URL.create(f"duckdb:///{db_path}"), {}

    # ── ClickHouse ────────────────────────────────────────────────────────────
    if ct == "clickhouse":
        if _driver_available("clickhouse_connect"):
            _require("clickhouse_connect", "clickhouse-connect")
            return (
                URL.create("clickhouse+http", username=user, password=password,
                           host=host, port=port(8123), database=database),
                {},
            )
        _require("clickhouse_driver", "clickhouse-driver")
        return (
            URL.create("clickhouse+native", username=user, password=password,
                       host=host, port=port(9000), database=database),
            {},
        )

    # ── Databricks / Delta Lake ───────────────────────────────────────────────
    if ct in ("databricks", "delta_lake"):
        _require("databricks.sqlalchemy", "databricks-sql-connector")
        http_path  = _cfg(cfg, "httpPath", "http_path")
        catalog    = _cfg(cfg, "catalog", default="hive_metastore")
        schema_str = _cfg(cfg, "schema", default="default")
        return (
            URL.create(
                "databricks",
                host=host,
                query={
                    "http_path": http_path,
                    "token":     password,
                    "catalog":   catalog,
                    "schema":    schema_str,
                },
            ),
            {},
        )

    # ── Trino ─────────────────────────────────────────────────────────────────
    if ct == "trino":
        _require("trino.sqlalchemy", "trino")
        catalog = _cfg(cfg, "catalog", default=database)
        return (
            URL.create("trino", username=user, password=password or None,
                       host=host, port=port(8080), database=catalog),
            {},
        )

    # ── Presto ────────────────────────────────────────────────────────────────
    if ct == "presto":
        _require("pyhive.sqlalchemy_presto", "pyhive[presto]")
        catalog = _cfg(cfg, "catalog", default=database)
        return (
            URL.create("presto", username=user, host=host,
                       port=port(8080), database=catalog),
            {},
        )

    # ── Hive / Spark / Impala ─────────────────────────────────────────────────
    if ct in ("hive", "spark", "sparksql"):
        _require("pyhive.sqlalchemy_hive", "pyhive[hive]")
        return (
            URL.create("hive", username=user, host=host,
                       port=port(10000), database=database),
            {},
        )

    if ct == "impala":
        _require("impala.sqlalchemy", "impyla")
        return (
            URL.create("impala", username=user, password=password,
                       host=host, port=port(21050), database=database),
            {},
        )

    # ── Athena ────────────────────────────────────────────────────────────────
    if ct == "athena":
        _require("pyathena", "pyathena")
        region        = _cfg(cfg, "awsConfig.awsRegion", "region", default="us-east-1")
        s3_staging    = _cfg(cfg, "s3StagingDir", "s3_staging_dir")
        access_key    = _cfg(cfg, "awsConfig.awsAccessKeyId", "accessKey")
        secret_key    = _cfg(cfg, "awsConfig.awsSecretAccessKey", "secretKey")
        work_group    = _cfg(cfg, "workgroup", default="primary")
        q2: dict = {"s3_staging_dir": s3_staging, "region_name": region,
                    "work_group": work_group}
        return (
            URL.create("awsathena+rest",
                       username=access_key or None, password=secret_key or None,
                       host=f"athena.{region}.amazonaws.com", port=443,
                       database=database, query=q2),
            {},
        )

    # ── Teradata ──────────────────────────────────────────────────────────────
    if ct == "teradata":
        _require("teradatasqlalchemy", "teradatasqlalchemy")
        return (
            URL.create("teradatasql", username=user, password=password,
                       host=host, database=database),
            {},
        )

    # ── Vertica ───────────────────────────────────────────────────────────────
    if ct == "vertica":
        _require("vertica_python", "vertica-python")
        return (
            URL.create("vertica+vertica_python", username=user, password=password,
                       host=host, port=port(5433), database=database),
            {},
        )

    # ── DB2 ───────────────────────────────────────────────────────────────────
    if ct == "db2":
        _require("ibm_db_sa", "ibm-db-sa")
        return (
            URL.create("ibm_db_sa+pyodbc", username=user, password=password,
                       host=host, port=port(50000), database=database),
            {},
        )

    # ── SAP HANA ──────────────────────────────────────────────────────────────
    if ct == "saphana":
        _require("hdbcli", "hdbcli")
        return (
            URL.create("hana+hdbcli", username=user, password=password,
                       host=host, port=port(39015), database=database),
            {},
        )

    # ── Exasol ────────────────────────────────────────────────────────────────
    if ct == "exasol":
        _require("sqlalchemy_exasol", "sqlalchemy-exasol")
        return (
            URL.create("exa+pyodbc", username=user, password=password,
                       host=host, port=port(8563), database=database),
            {},
        )

    # ── Druid ─────────────────────────────────────────────────────────────────
    if ct == "druid":
        _require("pydruid", "pydruid")
        return (
            URL.create("druid", username=user, password=password,
                       host=host, port=port(8082), database=database or "druid"),
            {},
        )

    # ── PinotDB ───────────────────────────────────────────────────────────────
    if ct == "pinotdb":
        _require("pinotdb", "pinotdb")
        return (
            URL.create("pinot", username=user, password=password,
                       host=host, port=port(8000), database=database),
            {},
        )

    # ── Connectors with no SQLAlchemy URL — handled by nosql_scanner.py ─────────
    # These should never reach _build_url because run_native_scan routes them
    # through run_nosql_scan first. The list here is a safety net.
    _NO_SQL_URL = {
        "mongodb", "cassandra", "elasticsearch", "opensearch", "dynamodb",
        "redis", "couchbase", "bigtable", "hbase", "neo4j",
        "kafka", "kinesis", "pubsub", "eventhub", "pulsar",
        "s3_datalake", "adls_datalake", "gcs_datalake", "iceberg",
        "superset", "tableau", "metabase", "looker", "powerbi",
        "mlflow", "sagemaker", "vertex", "dbt", "airflow",
        "glue", "nifi", "fivetran",
    }
    if ct in _NO_SQL_URL:
        raise NotImplementedError(
            f"'{connector_type}' has no SQLAlchemy URL — "
            "it should be handled by nosql_scanner.py. "
            "This is a routing bug; please report it."
        )

    raise NotImplementedError(
        f"No native scanner mapping for connector type '{connector_type}'. "
        "Add it to native_scanner.py or use the OpenMetadata workflow."
    )


# ── Driver availability helpers ────────────────────────────────────────────────

def _driver_available(module: str) -> bool:
    import importlib
    try:
        importlib.import_module(module)
        return True
    except ImportError:
        return False


def _require(module: str, pip_name: str):
    if not _driver_available(module):
        raise ImportError(
            f"Required driver '{module}' is not installed. "
            f"Run: pip install {pip_name}"
        )


def _is_scan_cancelled(db: Session, scan_id: Optional[int]) -> bool:
    if not scan_id:
        return False
    try:
        from app.models.models import ScanRun, ScanRunStatus
        status = db.query(ScanRun.status).filter(ScanRun.id == scan_id).scalar()
        return status == ScanRunStatus.FAILED
    except Exception as exc:
        logger.warning("Error checking scan cancellation for run %s: %s", scan_id, exc)
    return False


# ── Bulk metadata fetch (one query per schema instead of one per table) ────────

def _oracle_type_str(data_type: str, length, precision, scale) -> str:
    """Assemble an Oracle type string from ALL_TAB_COLUMNS components."""
    dt = (data_type or "UNKNOWN").upper()
    if dt in ("NUMBER", "FLOAT"):
        if precision is not None and scale is not None and int(scale) != 0:
            return f"{dt}({precision},{scale})"
        if precision is not None:
            return f"{dt}({precision})"
        return dt
    if dt in ("VARCHAR2", "NVARCHAR2", "CHAR", "NCHAR", "RAW"):
        if length:
            return f"{dt}({length})"
        return dt
    return dt


def _bulk_get_columns(engine, connector_type: str, schema_name: str) -> dict:
    """
    Fetch ALL column metadata for a schema in a single SQL query against the
    database's own catalog views.  Returns {table_name: [{"name":…, "type":…}]}
    or empty dict on failure (caller falls back to inspector per-table).
    """
    ct = connector_type.lower()
    try:
        with engine.connect() as conn:
            if ct in ("oracle", "oracledb"):
                sql = text(
                    "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, DATA_LENGTH,"
                    "       DATA_PRECISION, DATA_SCALE "
                    "FROM ALL_TAB_COLUMNS "
                    "WHERE OWNER = :schema "
                    "ORDER BY TABLE_NAME, COLUMN_ID"
                )
                rows = conn.execute(sql, {"schema": schema_name.upper()}).fetchall()
                result: dict = {}
                for tbl, col, dtype, length, prec, scale in rows:
                    result.setdefault(tbl, []).append(
                        {"name": col, "type": _oracle_type_str(dtype, length, prec, scale)}
                    )
                return result

            if ct in ("postgres", "postgresql", "redshift", "greenplum", "cockroach", "yugabyte"):
                sql = text(
                    "SELECT table_name, column_name, udt_name "
                    "FROM information_schema.columns "
                    "WHERE table_schema = :schema "
                    "ORDER BY table_name, ordinal_position"
                )
                rows = conn.execute(sql, {"schema": schema_name}).fetchall()
                result = {}
                for tbl, col, udt in rows:
                    result.setdefault(tbl, []).append({"name": col, "type": udt or "UNKNOWN"})
                return result

            if ct in ("mysql", "mariadb", "tidb", "doris"):
                sql = text(
                    "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE "
                    "FROM information_schema.COLUMNS "
                    "WHERE TABLE_SCHEMA = :schema "
                    "ORDER BY TABLE_NAME, ORDINAL_POSITION"
                )
                rows = conn.execute(sql, {"schema": schema_name}).fetchall()
                result = {}
                for tbl, col, ctype in rows:
                    result.setdefault(tbl, []).append({"name": col, "type": ctype or "UNKNOWN"})
                return result

            if ct in ("mssql", "sqlserver", "azuresql", "synapse", "fabric"):
                sql = text(
                    "SELECT c.TABLE_NAME, c.COLUMN_NAME, "
                    "       c.DATA_TYPE "
                    "       + CASE WHEN c.CHARACTER_MAXIMUM_LENGTH IS NOT NULL "
                    "              THEN '(' + CAST(c.CHARACTER_MAXIMUM_LENGTH AS VARCHAR) + ')' "
                    "              WHEN c.NUMERIC_PRECISION IS NOT NULL "
                    "              THEN '(' + CAST(c.NUMERIC_PRECISION AS VARCHAR) "
                    "                   + CASE WHEN c.NUMERIC_SCALE IS NOT NULL "
                    "                          THEN ',' + CAST(c.NUMERIC_SCALE AS VARCHAR) "
                    "                          ELSE '' END + ')' "
                    "              ELSE '' END AS full_type "
                    "FROM INFORMATION_SCHEMA.COLUMNS c "
                    "WHERE c.TABLE_SCHEMA = :schema "
                    "ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION"
                )
                rows = conn.execute(sql, {"schema": schema_name}).fetchall()
                result = {}
                for tbl, col, ftype in rows:
                    result.setdefault(tbl, []).append({"name": col, "type": ftype or "UNKNOWN"})
                return result

    except Exception as exc:
        logger.debug(
            "Bulk column fetch unavailable for schema %s (%s): %s — using inspector fallback",
            schema_name, connector_type, exc,
        )
    return {}


# ── Batch ORM write helpers ───────────────────────────────────────────────────

def _upsert_db(db: Session, name: str, data_source_id: int, tenant_id: int) -> int:
    # Filter by (name, data_source_id, tenant_id) so two sources with the same
    # DB name (e.g. both Oracle instances named "ORCL") each get their own
    # Database row and never overwrite each other's catalog hierarchy.
    existing = (
        db.query(DBDatabase)
        .filter(
            DBDatabase.name == name,
            DBDatabase.data_source_id == data_source_id,
            DBDatabase.tenant_id == tenant_id,
        )
        .first()
    )
    if existing:
        return existing.id
    new_db = DBDatabase(name=name, data_source_id=data_source_id, tenant_id=tenant_id)
    db.add(new_db)
    db.flush()
    return new_db.id


def _upsert_schema(db: Session, name: str, database_id: int, tenant_id: int) -> int:
    stmt = (
        pg_insert(DBSchema)
        .values(name=name, database_id=database_id, tenant_id=tenant_id)
        .on_conflict_do_nothing(constraint="_schema_db_tenant_uc")
        .returning(DBSchema.id)
    )
    row = db.execute(stmt).fetchone()
    if row is None:
        row = db.execute(
            db.query(DBSchema.id)
            .filter(
                DBSchema.name == name,
                DBSchema.database_id == database_id,
                DBSchema.tenant_id == tenant_id,
            )
            .statement
        ).fetchone()
    db.flush()
    return row[0]


def _batch_upsert_tables(
    db: Session, names: list[str], schema_id: int, tenant_id: int
) -> dict[str, int]:
    """Insert all tables for a schema in one statement. Returns {name: id}."""
    if not names:
        return {}
    db.execute(
        pg_insert(DBTable)
        .values([{"name": n, "schema_id": schema_id, "tenant_id": tenant_id} for n in names])
        .on_conflict_do_nothing(constraint="_table_schema_tenant_uc")
    )
    db.flush()
    rows = db.execute(
        select(DBTable.name, DBTable.id).where(
            DBTable.schema_id == schema_id,
            DBTable.tenant_id == tenant_id,
            DBTable.name.in_(names),
        )
    ).fetchall()
    return {r[0]: r[1] for r in rows}


def _batch_upsert_columns(db: Session, col_rows: list[dict]) -> None:
    """Batch-insert columns, chunked to avoid PostgreSQL parameter limits."""
    if not col_rows:
        return
    for i in range(0, len(col_rows), _COL_BATCH_SIZE):
        chunk = col_rows[i : i + _COL_BATCH_SIZE]
        ins = pg_insert(ColumnEntity).values(chunk)
        db.execute(
            ins.on_conflict_do_update(
                constraint="_col_table_tenant_uc",
                set_={
                    "type": ins.excluded.type,
                    "suggested_pii_type": ins.excluded.suggested_pii_type,
                },
            )
        )


# ── Single-item helpers (used by nosql_scanner) ───────────────────────────────

def _upsert_table(db: Session, name: str, schema_id: int, tenant_id: int) -> int:
    """Upsert a single table and return its id."""
    result = _batch_upsert_tables(db, [name], schema_id, tenant_id)
    return result[name]


def _upsert_column(
    db: Session,
    name: str,
    col_type: str,
    table_id: int,
    tenant_id: int,
    pii_type: Optional[str] = None,
) -> None:
    """Upsert a single column (convenience wrapper for nosql_scanner)."""
    suggested_pii, _ = _detect_pii(name)
    _batch_upsert_columns(db, [{
        "name": name,
        "type": col_type,
        "table_id": table_id,
        "tenant_id": tenant_id,
        "pii_type": pii_type,
        "suggested_pii_type": suggested_pii,
        "classification": None,
        "action": None,
    }])


# ── Universal reflection-based SQL scanner ─────────────────────────────────────

def _scan_via_sqlalchemy(
    engine,
    connector_type: str,
    db_name: str,
    data_source_id: int,
    tenant_id: int,
    db: Session,
    selected_schemas: Optional[list] = None,
    scan_id: Optional[int] = None,
) -> dict:
    """
    Introspect the target via SQLAlchemy's Inspector API + bulk catalog queries.

    For Oracle, PostgreSQL, MySQL, and SQL Server the column metadata is fetched
    for an entire schema in a single SQL query (ALL_TAB_COLUMNS / information_schema),
    reducing 10K+ per-table round-trips to 1 query per schema.  All table and column
    writes are batched for maximum throughput.  Intermediate commits every
    _COMMIT_EVERY tables prevent runaway transaction size.
    """
    inspector   = inspect(engine)
    excluded    = {e.lower() for e in _excluded_schemas(connector_type)}
    all_schemas = inspector.get_schema_names()
    schemas     = [s for s in all_schemas if s.lower() not in excluded]

    if selected_schemas:
        selected_set = {s.lower() for s in selected_schemas}
        available = len(schemas)
        schemas = [s for s in schemas if s.lower() in selected_set]
        logger.info(
            "scan:%s | [%s] %s | %d schemas selected (of %d available, %d system excluded)",
            scan_id or "sync", connector_type, db_name,
            len(schemas), available, len(all_schemas) - available,
        )
    else:
        logger.info(
            "scan:%s | [%s] %s | %d schemas to scan (%d system schemas excluded)",
            scan_id or "sync", connector_type, db_name,
            len(schemas), len(all_schemas) - len(schemas),
        )

    scan_start = time.monotonic()
    counts = {"schemas": 0, "tables": 0, "columns": 0, "views": 0}
    schemas_total = len(schemas)
    database_id = _upsert_db(db, db_name, data_source_id, tenant_id)
    tables_since_commit = 0

    for schema_idx, schema_name in enumerate(schemas, start=1):
        if _is_scan_cancelled(db, scan_id):
            logger.warning("scan:%s | cancelled by user after %d schemas", scan_id, counts["schemas"])
            raise RuntimeError("Scan stopped by user")

        schema_start = time.monotonic()
        logger.info(
            "scan:%s | schema %s (%d/%d) | starting …",
            scan_id or "sync", schema_name, schema_idx, schemas_total,
        )

        # Write progress so the UI can show current schema immediately
        if scan_id:
            _write_progress(db, scan_id, {
                "current_schema": schema_name,
                "schemas_done": counts["schemas"],
                "schemas_total": schemas_total,
                "tables_done": counts["tables"],
                "columns_done": counts["columns"],
                "phase": "scanning",
            })

        schema_id = _upsert_schema(db, schema_name, database_id, tenant_id)
        counts["schemas"] += 1

        table_names = inspector.get_table_names(schema=schema_name)
        view_names: list[str] = []
        try:
            view_names = inspector.get_view_names(schema=schema_name)
        except Exception:
            pass

        all_names = table_names + view_names
        if not all_names:
            logger.info(
                "scan:%s | schema %s | empty (no tables or views) — skipping",
                scan_id or "sync", schema_name,
            )
            continue

        logger.info(
            "scan:%s | schema %s | %d tables  %d views — fetching column metadata …",
            scan_id or "sync", schema_name, len(table_names), len(view_names),
        )

        # ── One INSERT for all tables in this schema ───────────────────────────
        table_name_to_id = _batch_upsert_tables(db, all_names, schema_id, tenant_id)
        counts["tables"] += len(table_names)
        counts["views"]  += len(view_names)

        # ── One SQL query for all column metadata in this schema ───────────────
        bulk_cols = _bulk_get_columns(engine, connector_type, schema_name)
        if bulk_cols:
            logger.info(
                "scan:%s | schema %s | bulk catalog fetch: %d tables with column data (1 query)",
                scan_id or "sync", schema_name, len(bulk_cols),
            )
        else:
            logger.info(
                "scan:%s | schema %s | bulk fetch unavailable — using per-table inspector fallback",
                scan_id or "sync", schema_name,
            )

        schema_col_count = 0
        for t_name in all_names:
            if _is_scan_cancelled(db, scan_id):
                logger.warning("scan:%s | cancelled by user mid-schema %s", scan_id, schema_name)
                raise RuntimeError("Scan stopped by user")

            table_id = table_name_to_id.get(t_name)
            if table_id is None:
                continue

            raw_cols = bulk_cols.get(t_name)
            if raw_cols is not None:
                col_defs = [
                    {"name": c["name"], "type": _normalize_type(c["type"], connector_type)}
                    for c in raw_cols
                ]
            else:
                # Inspector fallback for dialects without bulk fetch
                try:
                    raw_defs = inspector.get_columns(t_name, schema=schema_name)
                    col_defs = [
                        {
                            "name": c["name"],
                            "type": _normalize_type(c.get("type", "UNKNOWN"), connector_type),
                        }
                        for c in raw_defs
                    ]
                except Exception as exc:
                    logger.warning(
                        "scan:%s | %s.%s | could not read columns: %s",
                        scan_id or "sync", schema_name, t_name, exc,
                    )
                    col_defs = []

            col_rows = []
            for c in col_defs:
                pii_type, _ = _detect_pii(c["name"])
                col_rows.append({
                    "name": c["name"],
                    "type": c["type"],
                    "table_id": table_id,
                    "tenant_id": tenant_id,
                    "pii_type": None,
                    "suggested_pii_type": pii_type,
                    "classification": None,
                    "action": None,
                })

            _batch_upsert_columns(db, col_rows)
            counts["columns"]  += len(col_rows)
            schema_col_count   += len(col_rows)
            tables_since_commit += 1

            if tables_since_commit >= _COMMIT_EVERY:
                db.commit()
                tables_since_commit = 0
                if scan_id:
                    _write_progress(db, scan_id, {
                        "current_schema": schema_name,
                        "current_table": t_name,
                        "schemas_done": counts["schemas"],
                        "schemas_total": schemas_total,
                        "tables_done": counts["tables"],
                        "columns_done": counts["columns"],
                        "phase": "scanning",
                    })
                logger.info(
                    "scan:%s | checkpoint | schemas=%d/%d  tables=%d  cols=%d",
                    scan_id or "sync",
                    counts["schemas"], schemas_total,
                    counts["tables"], counts["columns"],
                )

        schema_elapsed = time.monotonic() - schema_start
        logger.info(
            "scan:%s | schema %s DONE | tables=%d  cols=%d  elapsed=%.1fs",
            scan_id or "sync", schema_name,
            len(all_names), schema_col_count, schema_elapsed,
        )

    db.commit()
    total_elapsed = time.monotonic() - scan_start
    logger.info(
        "scan:%s | [%s] %s COMPLETE | schemas=%d  tables=%d  views=%d  cols=%d  total=%.1fs",
        scan_id or "sync", connector_type, db_name,
        counts["schemas"], counts["tables"], counts["views"], counts["columns"],
        total_elapsed,
    )
    return counts


# ── Public entry point ─────────────────────────────────────────────────────────

def run_native_scan(
    source_type: str,
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
    selected_schemas: Optional[list] = None,
    scan_id: Optional[int] = None,
) -> dict:
    """
    Main entry point. Routes to the correct scanner based on connector type:
      • SQL connectors  → SQLAlchemy reflection (this file)
      • NoSQL/non-SQL   → dedicated adapters in nosql_scanner.py
    If selected_schemas is provided, only those schemas are scanned (batch mode).
    Raises ImportError with pip-install hint if the DB driver is missing.
    """
    from app.ingestion.nosql_scanner import is_nosql, run_nosql_scan
    if is_nosql(source_type):
        return run_nosql_scan(source_type, config, data_source_id, tenant_id, db)

    url, engine_kwargs = _build_url(source_type, config)

    from app.models.models import DataSource as DBDataSourceModel
    ds_obj = db.query(DBDataSourceModel).filter(DBDataSourceModel.id == data_source_id).first()
    ds_name = ds_obj.name if ds_obj else None

    db_name = (
        _cfg(config, "database", "dbname", "catalog")
        or url.database
        or ds_name
        or source_type
    )

    logger.info(
        "scan:%s | [%s] connecting to %s …",
        scan_id or "sync", source_type, db_name,
    )
    engine = create_engine(url, **engine_kwargs)
    try:
        ping_sql = "SELECT 1 FROM DUAL" if source_type.lower() in ("oracle", "oracledb") else "SELECT 1"
        t0 = time.monotonic()
        with engine.connect() as conn:
            conn.execute(text(ping_sql))
        logger.info(
            "scan:%s | [%s] %s connected (%.0fms) — starting discovery",
            scan_id or "sync", source_type, db_name, (time.monotonic() - t0) * 1000,
        )

        return _scan_via_sqlalchemy(
            engine, source_type, db_name, data_source_id, tenant_id, db,
            selected_schemas=selected_schemas,
            scan_id=scan_id,
        )
    except Exception:
        logger.exception(
            "scan:%s | [%s] %s FAILED", scan_id or "sync", source_type, db_name,
        )
        raise
    finally:
        engine.dispose()
