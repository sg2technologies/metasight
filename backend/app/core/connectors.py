"""
Static catalog of all supported connector types, aligned with OpenMetadata v1.12.x.
Each entry maps a slug (used as DataSource.type in the DB) to its display metadata.
"""
from typing import Dict, List

# ── Catalog definition ────────────────────────────────────────────────────────

CONNECTOR_CATALOG: List[Dict] = [
    # ── Database ──────────────────────────────────────────────────────────────
    {"type": "adls_datalake",  "display_name": "ADLS Datalake",   "category": "database"},
    {"type": "athena",         "display_name": "Athena",           "category": "database"},
    {"type": "azuresql",       "display_name": "Azure SQL",        "category": "database"},
    {"type": "bigquery",       "display_name": "BigQuery",         "category": "database"},
    {"type": "bigtable",       "display_name": "BigTable",         "category": "database"},
    {"type": "cassandra",      "display_name": "Cassandra",        "category": "database"},
    {"type": "clickhouse",     "display_name": "ClickHouse",       "category": "database"},
    {"type": "cockroach",      "display_name": "CockroachDB",      "category": "database"},
    {"type": "couchbase",      "display_name": "Couchbase",        "category": "database"},
    {"type": "databricks",     "display_name": "Databricks",       "category": "database"},
    {"type": "db2",            "display_name": "DB2",              "category": "database"},
    {"type": "dbt",            "display_name": "dbt",              "category": "database"},
    {"type": "delta_lake",     "display_name": "Delta Lake",       "category": "database"},
    {"type": "doris",          "display_name": "Doris",            "category": "database"},
    {"type": "druid",          "display_name": "Druid",            "category": "database"},
    {"type": "dynamodb",       "display_name": "DynamoDB",         "category": "database"},
    {"type": "exasol",         "display_name": "Exasol",           "category": "database"},
    {"type": "gcs_datalake",   "display_name": "GCS Datalake",     "category": "database"},
    {"type": "glue",           "display_name": "Glue",             "category": "database"},
    {"type": "greenplum",      "display_name": "Greenplum",        "category": "database"},
    {"type": "hive",           "display_name": "Hive",             "category": "database"},
    {"type": "impala",         "display_name": "Impala",           "category": "database"},
    {"type": "mariadb",        "display_name": "MariaDB",          "category": "database"},
    {"type": "mongodb",        "display_name": "MongoDB",          "category": "database"},
    {"type": "mssql",          "display_name": "MSSQL",            "category": "database"},
    {"type": "mysql",          "display_name": "MySQL",            "category": "database"},
    {"type": "oracle",         "display_name": "Oracle",           "category": "database"},
    {"type": "oracle_erp",     "display_name": "Oracle ERP",       "category": "database"},
    {"type": "pinotdb",        "display_name": "PinotDB",          "category": "database"},
    {"type": "postgres",       "display_name": "PostgreSQL",       "category": "database"},
    {"type": "presto",         "display_name": "Presto",           "category": "database"},
    {"type": "redshift",       "display_name": "Redshift",         "category": "database"},
    {"type": "s3_datalake",    "display_name": "S3 Datalake",      "category": "database"},
    {"type": "salesforce",     "display_name": "Salesforce",       "category": "database"},
    {"type": "sap_erp",        "display_name": "SAP ERP",          "category": "database"},
    {"type": "sap_hana",       "display_name": "SAP HANA",         "category": "database"},
    {"type": "singlestore",    "display_name": "SingleStore",      "category": "database"},
    {"type": "snowflake",      "display_name": "Snowflake",        "category": "database"},
    {"type": "sqlite",         "display_name": "SQLite",           "category": "database"},
    {"type": "starrocks",      "display_name": "StarRocks",        "category": "database"},
    {"type": "teradata",       "display_name": "Teradata",         "category": "database"},
    {"type": "timescaledb",    "display_name": "TimescaleDB",      "category": "database"},
    {"type": "trino",          "display_name": "Trino",            "category": "database"},
    {"type": "unity_catalog",  "display_name": "Unity Catalog",    "category": "database"},
    {"type": "vertica",        "display_name": "Vertica",          "category": "database"},

    # ── Dashboard ─────────────────────────────────────────────────────────────
    {"type": "grafana",        "display_name": "Grafana",          "category": "dashboard"},
    {"type": "hex",            "display_name": "Hex",              "category": "dashboard"},
    {"type": "lightdash",      "display_name": "Lightdash",        "category": "dashboard"},
    {"type": "looker",         "display_name": "Looker",           "category": "dashboard"},
    {"type": "metabase",       "display_name": "Metabase",         "category": "dashboard"},
    {"type": "microstrategy",  "display_name": "MicroStrategy",    "category": "dashboard"},
    {"type": "mode",           "display_name": "Mode",             "category": "dashboard"},
    {"type": "powerbi",        "display_name": "PowerBI",          "category": "dashboard"},
    {"type": "qlik_cloud",     "display_name": "Qlik Cloud",       "category": "dashboard"},
    {"type": "qlik_sense",     "display_name": "Qlik Sense",       "category": "dashboard"},
    {"type": "quicksight",     "display_name": "QuickSight",       "category": "dashboard"},
    {"type": "redash",         "display_name": "Redash",           "category": "dashboard"},
    {"type": "sigma",          "display_name": "Sigma",            "category": "dashboard"},
    {"type": "superset",       "display_name": "Superset",         "category": "dashboard"},
    {"type": "tableau",        "display_name": "Tableau",          "category": "dashboard"},
    {"type": "domo_dashboard", "display_name": "Domo",             "category": "dashboard"},

    # ── Messaging ─────────────────────────────────────────────────────────────
    {"type": "kafka",          "display_name": "Kafka",            "category": "messaging"},
    {"type": "kinesis",        "display_name": "Kinesis",          "category": "messaging"},
    {"type": "redpanda",       "display_name": "Redpanda",         "category": "messaging"},

    # ── Pipeline ──────────────────────────────────────────────────────────────
    {"type": "airbyte",        "display_name": "Airbyte",          "category": "pipeline"},
    {"type": "airflow",        "display_name": "Airflow",          "category": "pipeline"},
    {"type": "dagster",        "display_name": "Dagster",          "category": "pipeline"},
    {"type": "dbt_cloud",      "display_name": "dbt Cloud",        "category": "pipeline"},
    {"type": "domo_pipeline",  "display_name": "Domo Pipeline",    "category": "pipeline"},
    {"type": "fivetran",       "display_name": "Fivetran",         "category": "pipeline"},
    {"type": "flink",          "display_name": "Flink",            "category": "pipeline"},
    {"type": "glue_pipeline",  "display_name": "Glue Pipeline",    "category": "pipeline"},
    {"type": "kafka_connect",  "display_name": "Kafka Connect",    "category": "pipeline"},
    {"type": "nifi",           "display_name": "NiFi",             "category": "pipeline"},
    {"type": "openlineage",    "display_name": "OpenLineage",      "category": "pipeline"},
    {"type": "spline",         "display_name": "Spline",           "category": "pipeline"},
    {"type": "wherescape",     "display_name": "Wherescape",       "category": "pipeline"},

    # ── ML Model ──────────────────────────────────────────────────────────────
    {"type": "mlflow",         "display_name": "MLflow",           "category": "ml_model"},
    {"type": "sagemaker",      "display_name": "SageMaker",        "category": "ml_model"},

    # ── Storage ───────────────────────────────────────────────────────────────
    {"type": "s3_storage",     "display_name": "Amazon S3",        "category": "storage"},
    {"type": "azure_blob",     "display_name": "Azure Blob Storage","category": "storage"},
    {"type": "gcs_storage",    "display_name": "Google Cloud Storage","category": "storage"},

    # ── Search ────────────────────────────────────────────────────────────────
    {"type": "elasticsearch",  "display_name": "Elasticsearch",    "category": "search"},
    {"type": "opensearch",     "display_name": "OpenSearch",       "category": "search"},

    # ── Drive ─────────────────────────────────────────────────────────────────
    {"type": "sftp",           "display_name": "SFTP",             "category": "drive"},
    {"type": "custom_drive",   "display_name": "Custom Drive",     "category": "drive"},

    # ── Metadata ──────────────────────────────────────────────────────────────
    {"type": "alation_sink",   "display_name": "Alation",          "category": "metadata"},
    {"type": "amundsen",       "display_name": "Amundsen",         "category": "metadata"},
    {"type": "atlas",          "display_name": "Atlas",            "category": "metadata"},

    # ── API ───────────────────────────────────────────────────────────────────
    {"type": "rest",           "display_name": "REST",             "category": "api"},
]

# Fast lookup: type slug → entry
_BY_TYPE: Dict[str, Dict] = {c["type"]: c for c in CONNECTOR_CATALOG}

VALID_TYPES: frozenset = frozenset(_BY_TYPE.keys())
VALID_CATEGORIES: frozenset = frozenset(c["category"] for c in CONNECTOR_CATALOG)


def get_connector(type_slug: str) -> Dict | None:
    return _BY_TYPE.get(type_slug)


def get_category_for_type(type_slug: str) -> str | None:
    entry = _BY_TYPE.get(type_slug)
    return entry["category"] if entry else None


def catalog_by_category() -> Dict[str, List[Dict]]:
    """Return connectors grouped by category, each category sorted by display_name."""
    result: Dict[str, List[Dict]] = {}
    for c in CONNECTOR_CATALOG:
        result.setdefault(c["category"], []).append(c)
    for lst in result.values():
        lst.sort(key=lambda x: x["display_name"].lower())
    return result
