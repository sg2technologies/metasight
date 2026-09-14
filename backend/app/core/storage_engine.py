"""
Storage query execution engine — fetches objects from S3/GCS/Azure and parses them for tabular preview.
"""
from __future__ import annotations

import logging
import time
import io
import csv
import re
import sqlglot
from sqlalchemy.orm import Session

from app.core.query_engine import QueryResult
from app.models.models import DataSource
from app.ingestion.native_scanner import _cfg

logger = logging.getLogger(__name__)

def execute_storage_query(
    source_id: int,
    sql: str,
    db: Session,
    limit: int = 1000,
) -> QueryResult:
    """
    Load DataSource, parse SQL to find the S3 object key, fetch and return tabular rows.
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

    # ── 2. Parse SQL for Resource Name (Table), Columns, and Limit ─────────────
    try:
        parsed = sqlglot.parse_one(sql)
        tables = [t.name for t in parsed.find_all(sqlglot.exp.Table)]
        if not tables:
            raise ValueError("Could not find resource name in SQL")
        object_key = tables[0]
        
        # Extract requested columns (for filtering later)
        requested_columns = []
        for proj in parsed.expressions:
            if isinstance(proj, sqlglot.exp.Star):
                requested_columns = ["*"]
                break
            name = proj.alias or proj.name
            if name:
                requested_columns.append(name)
        
        # Extract limit
        limit_node = parsed.args.get("limit")
        if limit_node:
            try:
                limit = int(limit_node.expression.name)
            except:
                pass
                
    except Exception as exc:
        logger.warning("StorageEngine: fallback parsing for SQL: %s", exc)
        # Fallback regex if sqlglot fails on complex paths
        match = re.search(r'FROM\s+["\']?([^"\']+)["\']?', sql, re.IGNORECASE)
        if match:
            object_key = match.group(1)
            requested_columns = ["*"]
        else:
            raise ValueError(f"Failed to parse resource name from SQL: {sql}")

    t_start = time.perf_counter()
    
    # ── 3. Execute based on connector type ────────────────────────────────────
    ct = source.type.lower()
    
    if ct in ("s3_storage", "s3_datalake"):
        all_cols, all_rows = _fetch_s3(config, object_key, limit + 10) # fetch a few extra for safety
    else:
        raise NotImplementedError(f"Preview not implemented for storage type '{ct}'")

    # ── 4. Apply Column Selection & Limit ─────────────────────────────────────
    if "*" in requested_columns or not requested_columns:
        final_cols = all_cols
        final_rows = all_rows[:limit]
    else:
        # Filter columns to only those requested
        indices = []
        final_cols = []
        for req in requested_columns:
            if req in all_cols:
                indices.append(all_cols.index(req))
                final_cols.append(req)
            else:
                # Handle cases where rewriter might have added aliases or placeholders
                final_cols.append(req)
                indices.append(None)
        
        final_rows = []
        for r in all_rows[:limit]:
            final_rows.append([ (r[i] if i is not None and i < len(r) else None) for i in indices ])

    elapsed_ms = (time.perf_counter() - t_start) * 1000

    return QueryResult(
        columns=final_cols,
        rows=final_rows,
        row_count=len(final_rows),
        execution_time_ms=round(elapsed_ms, 2),
        dialect=ct,
    )

def _fetch_s3(config: dict, key: str, limit: int) -> tuple[list[str], list[list]]:
    import boto3
    bucket_name = _cfg(config, "bucket_name", "bucket")
    region      = _cfg(config, "region", "aws_region", default="us-east-1")
    key_id      = _cfg(config, "aws_access_key_id", "access_key")
    secret      = _cfg(config, "aws_secret_access_key", "secret_key")

    kwargs: dict = {"region_name": region}
    if key_id:
        kwargs["aws_access_key_id"] = key_id
        kwargs["aws_secret_access_key"] = secret

    s3 = boto3.client("s3", **kwargs)
    
    try:
        # Fetch the first 1MB of the file (enough for a preview)
        resp = s3.get_object(Bucket=bucket_name, Key=key, Range='bytes=0-1048575')
        content = resp['Body'].read().decode('utf-8', errors='replace')
        
        ext = key.split('.')[-1].lower() if '.' in key else 'file'
        
        if ext in ("csv", "txt", "tsv"):
            delimiter = ',' if ext == 'csv' else '\t' if ext == 'tsv' else None
            if not delimiter:
                first_line = content.split('\n')[0]
                delimiter = '\t' if '\t' in first_line else ','
                
            f = io.StringIO(content)
            reader = csv.reader(f, delimiter=delimiter)
            columns = next(reader, [])
            rows = []
            for i, row in enumerate(reader):
                if i >= limit:
                    break
                rows.append(row)
            return columns, rows
        else:
            # For non-tabular files, return a single 'content' column with a snippet
            return ["content"], [[content[:2000] + ("..." if len(content) > 2000 else "")]]
            
    except Exception as exc:
        logger.error("S3 fetch failed for %s/%s: %s", bucket_name, key, exc)
        raise RuntimeError(f"S3 fetch failed: {exc}")
