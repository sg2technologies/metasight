"""
NoSQL / non-SQL connector scanners.

Each scanner introspects the target and returns the same counts dict
as the SQL scanner:  {"schemas": N, "tables": N, "columns": N}

The ORM upsert helpers (_upsert_db/schema/table/column) are imported
from native_scanner so metadata is stored in exactly the same tables.

Supported:
  mongodb       — pymongo
  cassandra     — cassandra-driver
  elasticsearch — elasticsearch-py
  opensearch    — opensearch-py
  dynamodb      — boto3
  redis         — redis-py
  couchbase     — couchbase SDK  (best-effort)
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urljoin
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.ingestion.native_scanner import (
    _upsert_db,
    _upsert_schema,
    _upsert_table,
    _upsert_column,
    _detect_pii,
)

logger = logging.getLogger(__name__)


# ── Config helpers ────────────────────────────────────────────────────────────

def _g(config: dict, *keys: str, default: str = "") -> str:
    for k in keys:
        if k in config and config[k]:
            return str(config[k])
    return default


# ── MongoDB ───────────────────────────────────────────────────────────────────

_MONGO_SYSTEM_DBS = {"admin", "local", "config"}
_SAMPLE_SIZE = 100   # documents sampled per collection to infer schema


def _infer_mongo_fields(collection, sample_size: int = _SAMPLE_SIZE) -> dict[str, str]:
    """
    Sample documents from a MongoDB collection and return
    {field_name: bson_type_string} inferred from the sample.
    Handles nested documents by flattening with dot-notation (one level).
    """
    fields: dict[str, str] = {}
    try:
        docs = list(collection.find({}, limit=sample_size))
    except Exception as exc:
        logger.warning("mongo sample error %s: %s", collection.name, exc)
        return fields

    for doc in docs:
        for key, value in doc.items():
            if key == "_id":
                continue
            if key not in fields:
                fields[key] = _bson_type(value)
            # Flatten one level of nested docs to expose sub-fields
            if isinstance(value, dict):
                for sub_key, sub_val in value.items():
                    compound = f"{key}.{sub_key}"
                    if compound not in fields:
                        fields[compound] = _bson_type(sub_val)
    return fields


def _bson_type(value: Any) -> str:
    import datetime
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "double"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (datetime.datetime, datetime.date)):
        return "date"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    try:
        # ObjectId, Binary, etc.
        return type(value).__name__.lower()
    except Exception:
        return "unknown"


def scan_mongodb(
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
) -> dict:
    try:
        import pymongo
    except ImportError:
        raise ImportError(
            "pymongo is not installed. Run: pip install pymongo"
        )

    host     = _g(config, "host", "hostname", default="localhost")
    port     = int(_g(config, "port", default="27017"))
    username = _g(config, "user", "username")
    password = _g(config, "password")
    database = _g(config, "database", "dbname")
    auth_src = _g(config, "authSource", default="admin")

    # Build connection URI — only include credentials when both user AND password exist
    import urllib.parse
    if username and password:
        uri = (
            f"mongodb://{urllib.parse.quote_plus(username)}:"
            f"{urllib.parse.quote_plus(password)}@{host}:{port}/"
            f"?authSource={auth_src}"
        )
    elif username and not password:
        # username present but no password — connect without auth
        # (covers local dev MongoDB with --noauth or access-control disabled)
        logger.warning(
            "MongoDB username '%s' provided but no password — connecting without auth. "
            "Set a password in the data source config for production use.",
            username,
        )
        uri = f"mongodb://{host}:{port}/"
    else:
        uri = f"mongodb://{host}:{port}/"

    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=10_000)
    try:
        client.admin.command("ping")
    except Exception as exc:
        raise ConnectionError(f"MongoDB connection failed: {exc}") from exc

    counts = {"schemas": 0, "tables": 0, "columns": 0}

    # Determine which databases to scan
    if database:
        db_names = [database]
    else:
        try:
            db_names = [
                n for n in client.list_database_names()
                if n not in _MONGO_SYSTEM_DBS
            ]
        except Exception:
            db_names = [database or "unknown"]

    for db_name in db_names:
        database_id = _upsert_db(db, db_name, data_source_id, tenant_id)
        # MongoDB has no "schemas" — use a single schema named "default"
        schema_id = _upsert_schema(db, "default", database_id, tenant_id)
        counts["schemas"] += 1

        mdb = client[db_name]
        try:
            collection_names = mdb.list_collection_names()
        except Exception as exc:
            logger.warning("Cannot list collections in %s: %s", db_name, exc)
            continue

        for coll_name in collection_names:
            if coll_name.startswith("system."):
                continue
            table_id = _upsert_table(db, coll_name, schema_id, tenant_id)
            counts["tables"] += 1

            fields = _infer_mongo_fields(mdb[coll_name])
            # Always include _id
            _upsert_column(db, "_id", "ObjectId", table_id, tenant_id)
            counts["columns"] += 1

            for field_name, field_type in fields.items():
                _upsert_column(db, field_name, field_type, table_id, tenant_id)
                counts["columns"] += 1

    db.commit()
    client.close()
    logger.info("MongoDB scan complete [%s:%d]: %s", host, port, counts)
    return counts


# ── Elasticsearch / OpenSearch ────────────────────────────────────────────────

def scan_elasticsearch(
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
    connector_type: str = "elasticsearch",
) -> dict:
    host   = _g(config, "host", "hostname", default="localhost")
    port   = int(_g(config, "port", default="9200"))
    scheme = _g(config, "scheme", "protocol", default="http")
    user   = _g(config, "user", "username")
    passwd = _g(config, "password")
    url    = f"{scheme}://{host}:{port}"

    if connector_type == "opensearch":
        try:
            from opensearchpy import OpenSearch
            kwargs: dict = {"hosts": [url]}
            if user:
                kwargs["http_auth"] = (user, passwd)
            client = OpenSearch(**kwargs)
            indices = client.indices.get_mapping(index="*")
        except ImportError:
            raise ImportError("Run: pip install opensearch-py")
    else:
        try:
            from elasticsearch import Elasticsearch
            kwargs2: dict = {"hosts": [url]}
            if user:
                kwargs2["basic_auth"] = (user, passwd)
            client = Elasticsearch(**kwargs2)
            indices = client.indices.get_mapping(index="*")
        except ImportError:
            raise ImportError("Run: pip install elasticsearch")

    counts = {"schemas": 0, "tables": 0, "columns": 0}
    db_name = _g(config, "database", default=connector_type)
    database_id = _upsert_db(db, db_name, data_source_id, tenant_id)
    schema_id   = _upsert_schema(db, "indices", database_id, tenant_id)
    counts["schemas"] += 1

    for index_name, mapping in indices.items():
        if index_name.startswith("."):   # skip internal indices
            continue
        table_id = _upsert_table(db, index_name, schema_id, tenant_id)
        counts["tables"] += 1

        props = (mapping.get("mappings") or {}).get("properties") or {}
        for field_name, field_meta in props.items():
            field_type = field_meta.get("type", "object")
            _upsert_column(db, field_name, field_type, table_id, tenant_id)
            counts["columns"] += 1

    db.commit()
    logger.info("%s scan complete [%s]: %s", connector_type, url, counts)
    return counts


# ── Cassandra ─────────────────────────────────────────────────────────────────

_CASSANDRA_SYSTEM_KS = {
    "system", "system_auth", "system_distributed",
    "system_schema", "system_traces",
}


def scan_cassandra(
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
) -> dict:
    try:
        from cassandra.cluster import Cluster
        from cassandra.auth import PlainTextAuthProvider
    except ImportError:
        raise ImportError("Run: pip install cassandra-driver")

    host     = _g(config, "host", "hostname", default="localhost")
    port     = int(_g(config, "port", default="9042"))
    user     = _g(config, "user", "username")
    passwd   = _g(config, "password")
    keyspace = _g(config, "database", "keyspace")

    auth = PlainTextAuthProvider(user, passwd) if user else None
    cluster = Cluster([host], port=port, auth_provider=auth,
                      connect_timeout=10)
    session = cluster.connect()

    counts = {"schemas": 0, "tables": 0, "columns": 0}
    db_name    = _g(config, "database", default="cassandra")
    database_id = _upsert_db(db, db_name, data_source_id, tenant_id)

    keyspaces = (
        [keyspace] if keyspace
        else [
            r.keyspace_name
            for r in session.execute(
                "SELECT keyspace_name FROM system_schema.keyspaces"
            )
            if r.keyspace_name not in _CASSANDRA_SYSTEM_KS
        ]
    )

    for ks_name in keyspaces:
        schema_id = _upsert_schema(db, ks_name, database_id, tenant_id)
        counts["schemas"] += 1

        tables = session.execute(
            "SELECT table_name FROM system_schema.tables WHERE keyspace_name=%s",
            [ks_name],
        )
        for table_row in tables:
            tbl_name = table_row.table_name
            table_id = _upsert_table(db, tbl_name, schema_id, tenant_id)
            counts["tables"] += 1

            cols = session.execute(
                "SELECT column_name, type FROM system_schema.columns "
                "WHERE keyspace_name=%s AND table_name=%s",
                [ks_name, tbl_name],
            )
            for col in cols:
                _upsert_column(db, col.column_name, col.type, table_id, tenant_id)
                counts["columns"] += 1

    db.commit()
    cluster.shutdown()
    logger.info("Cassandra scan complete [%s:%d]: %s", host, port, counts)
    return counts


# ── DynamoDB ──────────────────────────────────────────────────────────────────

def scan_dynamodb(
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
) -> dict:
    try:
        import boto3
    except ImportError:
        raise ImportError("Run: pip install boto3")

    region   = _g(config, "region", "aws_region", default="us-east-1")
    key_id   = _g(config, "aws_access_key_id", "access_key")
    secret   = _g(config, "aws_secret_access_key", "secret_key")
    endpoint = _g(config, "endpoint_url")   # for DynamoDB Local

    kwargs: dict = {"region_name": region}
    if key_id:
        kwargs["aws_access_key_id"] = key_id
        kwargs["aws_secret_access_key"] = secret
    if endpoint:
        kwargs["endpoint_url"] = endpoint

    dynamo = boto3.client("dynamodb", **kwargs)

    counts = {"schemas": 0, "tables": 0, "columns": 0}
    db_name    = f"dynamodb-{region}"
    database_id = _upsert_db(db, db_name, data_source_id, tenant_id)
    schema_id   = _upsert_schema(db, "default", database_id, tenant_id)
    counts["schemas"] += 1

    paginator = dynamo.get_paginator("list_tables")
    for page in paginator.paginate():
        for table_name in page.get("TableNames", []):
            table_id = _upsert_table(db, table_name, schema_id, tenant_id)
            counts["tables"] += 1

            try:
                desc = dynamo.describe_table(TableName=table_name)
                attr_defs = desc["Table"].get("AttributeDefinitions", [])
                for attr in attr_defs:
                    col_name = attr["AttributeName"]
                    col_type = {"S": "string", "N": "number", "B": "binary"}.get(
                        attr["AttributeType"], attr["AttributeType"]
                    )
                    _upsert_column(db, col_name, col_type, table_id, tenant_id)
                    counts["columns"] += 1
            except Exception as exc:
                logger.warning("DynamoDB describe_table %s: %s", table_name, exc)

    db.commit()
    logger.info("DynamoDB scan complete [%s]: %s", region, counts)
    return counts


# ── Redis ─────────────────────────────────────────────────────────────────────

def scan_redis(
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
) -> dict:
    try:
        import redis
    except ImportError:
        raise ImportError("Run: pip install redis")

    host   = _g(config, "host", "hostname", default="localhost")
    port   = int(_g(config, "port", default="6379"))
    passwd = _g(config, "password")
    db_num = int(_g(config, "database", "db", default="0"))

    r = redis.Redis(host=host, port=port, password=passwd or None,
                    db=db_num, socket_connect_timeout=5)
    r.ping()

    counts  = {"schemas": 0, "tables": 0, "columns": 0}
    db_name = f"redis-{host}:{port}"
    database_id = _upsert_db(db, db_name, data_source_id, tenant_id)
    schema_id   = _upsert_schema(db, f"db{db_num}", database_id, tenant_id)
    counts["schemas"] += 1

    # Scan up to 500 keys and infer types
    type_buckets: dict[str, set[str]] = {}
    cursor = 0
    scanned = 0
    while scanned < 500:
        cursor, keys = r.scan(cursor=cursor, count=100)
        for raw_key in keys:
            key = raw_key.decode(errors="replace") if isinstance(raw_key, bytes) else raw_key
            try:
                ktype = r.type(raw_key).decode()
            except Exception:
                ktype = "unknown"
            # Group keys by prefix (before first colon)
            prefix = key.split(":")[0] if ":" in key else key
            type_buckets.setdefault(prefix, set()).add(ktype)
            scanned += 1
        if cursor == 0:
            break

    for prefix, types in type_buckets.items():
        table_id = _upsert_table(db, prefix, schema_id, tenant_id)
        counts["tables"] += 1
        for t in types:
            _upsert_column(db, "value", t, table_id, tenant_id)
            counts["columns"] += 1

    db.commit()
    r.close()
    logger.info("Redis scan complete [%s:%d db%d]: %s", host, port, db_num, counts)
    return counts


# ── Amazon S3 ─────────────────────────────────────────────────────────────────

def scan_s3(
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
) -> dict:
    try:
        import boto3
        import csv
        import io
    except ImportError:
        raise ImportError("Run: pip install boto3")

    bucket_name = _g(config, "bucket_name", "bucket", default="")
    region      = _g(config, "region", "aws_region", "awsRegion", default="us-east-1")
    key_id      = _g(config, "aws_access_key_id", "access_key", "accessKey", "access_key_id")
    secret      = _g(config, "aws_secret_access_key", "secret_key", "secretKey", "secret_access_key")

    if not bucket_name:
        raise ValueError("Bucket name is required for S3 scan")

    kwargs: dict = {"region_name": region}
    if key_id:
        kwargs["aws_access_key_id"] = key_id
        kwargs["aws_secret_access_key"] = secret

    s3 = boto3.client("s3", **kwargs)

    counts = {"schemas": 0, "tables": 0, "columns": 0}
    db_name = "Amazon-S3"
    database_id = _upsert_db(db, db_name, data_source_id, tenant_id)
    
    # We treat each bucket as a "schema"
    schema_id = _upsert_schema(db, bucket_name, database_id, tenant_id)
    counts["schemas"] += 1

    # List up to 100 objects and treat them as "tables"
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
        for obj in resp.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"): # Skip folders
                continue
                
            size = obj["Size"]
            # Treat each file as a TABLE
            table_id = _upsert_table(db, key, schema_id, tenant_id)
            counts["tables"] += 1
            
            # Infer type from extension
            ext = key.split(".")[-1].lower() if "." in key else "file"
            
            # For CSV/TXT, try to peek at columns
            if ext in ("csv", "txt", "tsv"):
                try:
                    # Get the first 8KB for header discovery
                    head_resp = s3.get_object(Bucket=bucket_name, Key=key, Range='bytes=0-8191')
                    content = head_resp['Body'].read().decode('utf-8', errors='replace')
                    
                    # Simple CSV header detection
                    delimiter = ',' if ext == 'csv' else '\t' if ext == 'tsv' else None
                    if not delimiter:
                        # Try to guess
                        first_line = content.split('\n')[0]
                        if '\t' in first_line: delimiter = '\t'
                        elif ',' in first_line: delimiter = ','
                        else: delimiter = ','
                        
                    f = io.StringIO(content)
                    reader = csv.reader(f, delimiter=delimiter)
                    headers = next(reader, [])
                    
                    if headers:
                        for col_name in headers:
                            clean_col = col_name.strip()
                            if clean_col:
                                _upsert_column(db, clean_col, "string", table_id, tenant_id)
                                counts["columns"] += 1
                    else:
                        _upsert_column(db, "data", "string", table_id, tenant_id)
                        counts["columns"] += 1
                except Exception as exc:
                    logger.warning("Could not parse headers for S3 object %s: %s", key, exc)
                    _upsert_column(db, "data", "string", table_id, tenant_id)
                    counts["columns"] += 1
            else:
                # Generic column for other files
                col_type = f"{ext.upper()} ({size} bytes)"
                _upsert_column(db, "content", col_type, table_id, tenant_id)
                counts["columns"] += 1
                
    except Exception as exc:
        logger.error("S3 list_objects %s failed: %s", bucket_name, exc)
        raise ConnectionError(f"S3 connection failed: {exc}")

    db.commit()
    logger.info("S3 scan complete [%s]: %s", bucket_name, counts)
    return counts


# Oracle ERP Cloud

_DEFAULT_ORACLE_ERP_RESOURCES = [
    {
        "module": "Financials",
        "name": "Invoices",
        "path": "/fscmRestApi/resources/latest/invoices",
    },
    {
        "module": "Financials",
        "name": "Payments",
        "path": "/fscmRestApi/resources/latest/payments",
    },
    {
        "module": "Procurement",
        "name": "PurchaseOrders",
        "path": "/fscmRestApi/resources/latest/purchaseOrders",
    },
    {
        "module": "Projects",
        "name": "Projects",
        "path": "/fscmRestApi/resources/latest/projects",
    },
]


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _field_type(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _resource_entries(config: dict) -> list[dict[str, str]]:
    resources = config.get("resources")
    if isinstance(resources, str):
        resources = [
            {"name": p.strip("/").split("/")[-1], "path": p.strip()}
            for p in re.split(r"[\r\n,]+", resources)
            if p.strip()
        ]
    if not resources:
        resources = _DEFAULT_ORACLE_ERP_RESOURCES

    entries: list[dict[str, str]] = []
    default_module = _g(config, "module", default="Oracle ERP")
    for item in resources:
        if isinstance(item, str):
            path = item
            name = path.strip("/").split("/")[-1] or "resource"
            module = default_module
        elif isinstance(item, dict):
            path = str(item.get("path") or item.get("endpoint") or "").strip()
            name = str(item.get("name") or path.strip("/").split("/")[-1] or "resource")
            module = str(item.get("module") or default_module)
        else:
            continue
        if path:
            entries.append({"module": module, "name": name, "path": path})
    return entries


def _extract_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def scan_oracle_erp(
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
) -> dict:
    try:
        import httpx
    except ImportError:
        raise ImportError("Run: pip install httpx")

    base_url = _g(config, "base_url", "host", "url").rstrip("/")
    if not base_url:
        raise ValueError("base_url is required for Oracle ERP scan")

    username = _g(config, "username", "user")
    password = _g(config, "password")
    token = _g(config, "token", "bearer_token", "access_token")
    timeout = float(_g(config, "timeout", default="30"))
    verify_ssl = _as_bool(config.get("verify_ssl"), default=True)
    sample_size = int(_g(config, "sample_size", default="25"))

    headers = {"Accept": "application/json"}
    auth = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif username:
        auth = (username, password)

    counts = {"schemas": 0, "tables": 0, "columns": 0}
    db_name = _g(config, "name", "instance_name", default="Oracle ERP")
    database_id = _upsert_db(db, db_name, data_source_id, tenant_id)
    schema_ids: dict[str, int] = {}

    params = {"limit": sample_size, "onlyData": "true"}
    with httpx.Client(
        base_url=base_url,
        headers=headers,
        auth=auth,
        timeout=timeout,
        verify=verify_ssl,
        follow_redirects=True,
    ) as client:
        for resource in _resource_entries(config):
            module = resource["module"]
            if module not in schema_ids:
                schema_ids[module] = _upsert_schema(db, module, database_id, tenant_id)
                counts["schemas"] += 1

            url = urljoin(base_url + "/", resource["path"].lstrip("/"))
            try:
                response = client.get(url, params=params)
                response.raise_for_status()
            except Exception as exc:
                raise ConnectionError(
                    f"Oracle ERP resource '{resource['name']}' failed at {url}: {exc}"
                ) from exc

            rows = _extract_items(response.json())
            table_id = _upsert_table(db, resource["name"], schema_ids[module], tenant_id)
            counts["tables"] += 1

            fields: dict[str, str] = {}
            for row in rows[:sample_size]:
                for key, value in row.items():
                    if key == "links":
                        continue
                    fields.setdefault(str(key), _field_type(value))

            if not fields:
                fields["payload"] = "object"

            for field_name, field_type in sorted(fields.items()):
                _upsert_column(db, field_name, field_type, table_id, tenant_id)
                counts["columns"] += 1

    db.commit()
    logger.info("Oracle ERP scan complete [%s]: %s", base_url, counts)
    return counts


# ── Dispatch table ────────────────────────────────────────────────────────────

_NOSQL_SCANNERS = {
    "mongodb":        scan_mongodb,
    "cassandra":      scan_cassandra,
    "elasticsearch":  scan_elasticsearch,
    "opensearch":     lambda cfg, ds, t, db: scan_elasticsearch(cfg, ds, t, db, "opensearch"),
    "dynamodb":       scan_dynamodb,
    "redis":          scan_redis,
    "s3_storage":     scan_s3,
    "s3_datalake":    scan_s3,
    "oracle_erp":     scan_oracle_erp,
}


def is_nosql(connector_type: str) -> bool:
    return connector_type.lower() in _NOSQL_SCANNERS


def run_nosql_scan(
    connector_type: str,
    config: dict,
    data_source_id: int,
    tenant_id: int,
    db: Session,
) -> dict:
    """
    Entry point for all non-SQL connectors.
    Raises ImportError with pip hint if the required driver is missing.
    Raises NotImplementedError for connector types without a scanner.
    """
    ct = connector_type.lower()
    scanner = _NOSQL_SCANNERS.get(ct)
    if scanner is None:
        raise NotImplementedError(
            f"No scanner implemented for '{connector_type}'. "
            "Supported NoSQL types: " + ", ".join(sorted(_NOSQL_SCANNERS))
        )
    return scanner(config, data_source_id, tenant_id, db)
