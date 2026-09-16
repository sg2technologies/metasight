"""
Query proxy — applies policy rewriting + post-query tokenization + audit.

Endpoints:
  POST /query          — rewrite-only (legacy, backward-compat)
  POST /query/execute  — full gateway: rewrite → execute → mask → tokenize → audit
  POST /query/detokenize — reverse a token (admin only)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Any

from app.core.deps import get_db, get_current_user
from app.models.models import PolicyRule, ColumnEntity, Table, AuditLog, DataSource, SecurityEvent
from app.rewriters.sql_rewriter import SQLRewriter, _guard_sql
from app.rewriters.mongo_rewriter import MongoRewriter
from starlette.requests import Request

from app.services.tokenization import TokenizationService
from app.services.audit import AuditService
from app.services.governance_audit import record_privileged_activity
from app.services.masking import mask_row, masking_level_for_role, infer_tags, infer_pii_type
from app.services.policy_engine import PolicyEngine
from app.services.risk_scorer import score_query, RiskScore
from app.core.query_engine import execute_query, _POSTGRES_FAMILY
from app.core.storage_engine import execute_storage_query
from app.schemas.schemas import (
    QueryRequest,
    QueryResponse,
    ExecuteQueryRequest,
    ExecuteQueryResponse,
    PolicySummary,
    RiskScoreResponse,
    SimulateQueryRequest,
    SimulateQueryResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()
_sql_rewriter = SQLRewriter()
_mongo_rewriter = MongoRewriter()


# ── Legacy rewrite-only endpoint ──────────────────────────────────────────────

@router.post("", response_model=QueryResponse)
def rewrite_query(
    req: QueryRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = user["tenant_id"]

    # 1. Load policy
    policy_rule = (
        db.query(PolicyRule)
        .filter(PolicyRule.resource == req.resource, PolicyRule.tenant_id == tenant_id)
        .first()
    )
    if not policy_rule:
        raise HTTPException(
            status_code=403,
            detail=f"No policy defined for resource '{req.resource}'. Ask an admin to create one.",
        )

    policy = {
        "columns": policy_rule.column_policies or {},
        "row_filters": policy_rule.row_filters or [],
        "classification": policy_rule.classification,
    }

    # 2. Resolve known columns for SELECT * expansion
    table = db.query(Table).filter(Table.name == req.resource, Table.tenant_id == tenant_id).first()
    known_columns = None
    if table:
        known_columns = [c.name for c in db.query(ColumnEntity).filter(ColumnEntity.table_id == table.id).all()]

    # 3. Rewrite
    rewritten: Any = None
    columns_denied: list[str] = []
    columns_masked: list[str] = []
    columns_tokenized: list[str] = []

    for col_name, col_pol in policy["columns"].items():
        action = col_pol.get("action", "allow")
        exempt = col_pol.get("roles_exempt", ["admin"])
        if user.get("role") not in exempt:
            if action == "deny":
                columns_denied.append(col_name)
            elif action == "mask":
                columns_masked.append(col_name)
            elif action == "tokenize":
                columns_tokenized.append(col_name)

    try:
        if req.source_type in ("postgres", "mysql", "mssql", "redshift"):
            if not isinstance(req.query, str):
                raise HTTPException(status_code=422, detail="SQL query must be a string")
            rewritten = _sql_rewriter.rewrite(
                req.query, policy, dict(user),
                known_columns=known_columns,
                dialect="postgres" if req.source_type == "postgres" else req.source_type,
            )
        elif req.source_type == "mongodb":
            if not isinstance(req.query, dict):
                raise HTTPException(status_code=422, detail="MongoDB query must be a JSON object")
            rewritten = _mongo_rewriter.rewrite(dict(req.query), policy, dict(user))
        else:
            rewritten = req.query
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # 4. Audit
    audit_svc = AuditService(db, tenant_id)
    audit_svc.log({
        "user_email": user.get("sub", ""),
        "role": user.get("role", ""),
        "resource": req.resource,
        "action": "query",
        "original_query": str(req.query),
        "rewritten_query": str(rewritten),
        "policy_applied": policy_rule.classification,
    })
    db.commit()

    return QueryResponse(
        resource=req.resource,
        source_type=req.source_type,
        original_query=req.query,
        rewritten_query=rewritten,
        policy_classification=policy_rule.classification,
        columns_denied=columns_denied,
        columns_masked=columns_masked,
        columns_tokenized=columns_tokenized,
    )


# ── Full execute endpoint ─────────────────────────────────────────────────────

def _risk_response(rs: RiskScore) -> RiskScoreResponse:
    return RiskScoreResponse(
        score=rs.score,
        level=rs.level,
        factors=rs.factors,
        recommendations=rs.recommendations,
    )


def _build_policy_summary(tables, table_policies, meta, primary_decision) -> PolicySummary:
    all_denied = list(meta.denied_columns)
    all_masked = list(meta.masked_columns.keys())
    all_tok = list(meta.tokenized_columns.keys())
    for dec in table_policies.values():
        for c in dec.denied_columns:
            if c not in all_denied:
                all_denied.append(c)
        for c in dec.masked_columns:
            if c not in all_masked:
                all_masked.append(c)
        for c in dec.tokenized_columns:
            if c not in all_tok:
                all_tok.append(c)
    return PolicySummary(
        resource=",".join(tables),
        classification=primary_decision.classification,
        auto_policy=primary_decision.auto_policy,
        masked_columns=all_masked,
        tokenized_columns=all_tok,
        denied_columns=all_denied,
        row_filter_applied=meta.row_filter_applied,
        is_admin_exempt=primary_decision.is_admin_exempt,
    ), all_denied, all_masked, all_tok


def _get_dialect(source_type: str) -> str:
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


def _resolve_table_policies(sql, source_id, source_type, tenant_id, user, db):
    """Extract tables from SQL and resolve PolicyDecision for each."""
    tables = _sql_rewriter.get_tables(sql)
    if not tables:
        raise HTTPException(status_code=422, detail="Could not extract table name from SQL.")
    engine_svc = PolicyEngine(db, tenant_id)
    table_policies: dict = {}
    warnings: list[str] = []
    for table_name in tables:
        try:
            decision = engine_svc.decide(table_name, dict(user), source_type=source_type, source_id=source_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except Exception as exc:
            logger.exception("PolicyEngine error for table '%s'", table_name)
            raise HTTPException(status_code=500, detail=f"Policy evaluation error: {exc}")
        if not decision.allowed:
            raise HTTPException(status_code=403, detail=f"Access denied to resource '{table_name}'.")
        if decision.auto_policy and not decision.masked_columns and not decision.denied_columns:
            warnings.append(f"No explicit policy for '{table_name}'. Allowing through with audit.")
        table_policies[table_name] = decision
    return tables, table_policies, warnings



@router.post("/execute", response_model=ExecuteQueryResponse)
def execute_query_endpoint(
    req: ExecuteQueryRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Full query gateway:
      1. Extract primary table name from SQL
      2. Run PolicyEngine.decide()
      3. Rewrite SQL with SQLRewriter
      4. Execute on target DB via query_engine
      5. Apply masking + tokenization to result rows
      6. Audit
      7. Return structured response
    """
    tenant_id = user["tenant_id"]
    warnings: list[str] = []
    audit_id: int | None = None
    user_role = user.get("role", "analyst")
    
    from app.services.settings_service import get_settings
    cfg = get_settings(tenant_id, db)
    role_levels = cfg.get("masking", {}).get("role_levels", None)
    mask_level = masking_level_for_role(user_role, role_levels)

    # ── 1. Load DataSource ────────────────────────────────────────────────────
    source: DataSource | None = db.get(DataSource, req.source_id)
    if source is None:
        raise HTTPException(status_code=404, detail=f"DataSource with id={req.source_id} not found.")
    source_type = source.type
    is_nosql = source_type in ("mongodb", "elasticsearch", "opensearch", "dynamodb", "redis")

    try:
        import json
        from app.rewriters.sql_rewriter import RewriteMeta
        meta = RewriteMeta()
        
        if is_nosql:
            try:
                mongo_query = json.loads(req.sql)
            except json.JSONDecodeError:
                raise HTTPException(status_code=422, detail="NoSQL query must be valid JSON")
            primary_table = mongo_query.get("collection", "default")
            tables = [primary_table]
            
            engine_svc = PolicyEngine(db, tenant_id)
            try:
                primary_decision = engine_svc.decide(primary_table, dict(user), source_type=source_type, source_id=req.source_id)
            except Exception as exc:
                if isinstance(exc, PermissionError): raise HTTPException(status_code=403, detail=str(exc))
                raise HTTPException(status_code=500, detail=str(exc))
                
            if not primary_decision.allowed:
                raise HTTPException(status_code=403, detail=f"Access denied to resource '{primary_table}'")
                
            table_policies = {primary_table: primary_decision}
            
            if source_type == "mongodb":
                col_dict = {}
                for c in primary_decision.denied_columns: col_dict[c] = {"action": "deny"}
                for c in primary_decision.masked_columns: col_dict[c] = {"action": "mask"}
                for c in primary_decision.tokenized_columns: col_dict[c] = {"action": "tokenize"}
                policy_dict = {"row_filters": primary_decision.row_filter_conditions, "columns": col_dict}
                rewritten_dict = _mongo_rewriter.rewrite(dict(mongo_query), policy_dict, dict(user))
                rewritten_sql = json.dumps(rewritten_dict, indent=2)
                for c in primary_decision.denied_columns: meta.denied_columns.append(c)
                for c in primary_decision.masked_columns: meta.masked_columns[c] = primary_decision.column_pii_map.get(c)
                for c in primary_decision.tokenized_columns: meta.tokenized_columns[c] = c
            else:
                rewritten_sql = req.sql
        else:
            # SQL logic
            try:
                _guard_sql(req.sql)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))

            tables, table_policies, pol_warnings = _resolve_table_policies(
                req.sql, req.source_id, source_type, tenant_id, user, db
            )
            warnings.extend(pol_warnings)
            primary_table = tables[0]
            primary_decision = table_policies[primary_table]

            try:
                rewritten_sql, meta = _sql_rewriter.rewrite_with_meta(
                    req.sql, table_policies, dialect=_get_dialect(source_type)
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))

            if meta.warnings:
                warnings.extend(meta.warnings)

        logger.info("query/execute [%s] source_id=%d — rewritten SQL: %s", source_type, req.source_id, rewritten_sql)

        # ── 5. Risk score (pre-execution) + Approval gate ─────────────────────────
        risk = score_query(meta, table_policies, row_count=0)

        if risk.level == "CRITICAL":
            from app.api.approvals import create_approval_request, validate_approval_token
            if req.approval_token:
                # Validate and consume the approval token
                approval = validate_approval_token(db, tenant_id, req.sql, req.approval_token)
                if approval.requester_email != user.get("sub", ""):
                    raise HTTPException(
                        status_code=403,
                        detail="Only the original requester may execute this approved query.",
                    )
                warnings.append("Query executed under admin-approved token.")
            else:
                # Create approval request and block execution
                approval = create_approval_request(
                    db, tenant_id, user, req.source_id, req.sql,
                    risk.score, risk.level,
                )
                raise HTTPException(
                    status_code=403,
                    detail={
                        "message": f"Query risk is CRITICAL (score={risk.score}). Admin approval required.",
                        "approval_request_id": approval.id,
                        "risk": {"score": risk.score, "level": risk.level, "factors": risk.factors},
                        "instructions": "Ask an admin to approve via POST /approvals/{id}/approve, then resubmit with approval_token.",
                    },
                )
    except HTTPException as he:
        if he.status_code in (403, 422):
            resources = "unknown"
            policy_applied = "DENY"
            try:
                if is_nosql:
                    try:
                        mongo_query = json.loads(req.sql)
                        resources = mongo_query.get("collection", "default")
                    except:
                        pass
                else:
                    tables = _sql_rewriter.get_tables(req.sql)
                    if tables:
                        resources = ",".join(tables)
            except:
                pass

            try:
                if 'primary_decision' in locals():
                    policy_applied = primary_decision.classification
            except:
                pass

            AuditService(db, tenant_id).log({
                "user_email": user.get("sub", ""),
                "role": user_role,
                "resource": resources,
                "action": "query_blocked",
                "original_query": req.sql,
                "rewritten_query": None,
                "policy_applied": policy_applied,
                "row_count": 0,
            })
            
            # Create a SecurityEvent representing the blocked query
            try:
                from app.models.models import AgentRegistration
                import secrets
                
                # Fetch a valid agent registration for this tenant
                agent = db.query(AgentRegistration).filter(
                    AgentRegistration.tenant_id == tenant_id
                ).first()
                if not agent:
                    agent = AgentRegistration(
                        tenant_id=tenant_id,
                        name="MetaSight Query Gateway",
                        db_type="postgres",
                        api_key="msa_gateway_" + secrets.token_urlsafe(16),
                    )
                    db.add(agent)
                    db.flush()
                agent_id = agent.id

                ds = locals().get("source")
                if not ds and hasattr(req, "source_id"):
                    ds = db.get(DataSource, req.source_id)
                db_type = ds.type if ds else "postgres"
                
                db_name = None
                if ds:
                    try:
                        cfg = {}
                        if ds.encrypted_config:
                            from app.core.encryption import aes_cipher
                            cfg = {
                                k: aes_cipher.decrypt(v) if isinstance(v, str) else v
                                for k, v in ds.encrypted_config.items()
                            }
                        db_name = (
                            cfg.get("database") or 
                            cfg.get("dbname") or 
                            cfg.get("catalog") or 
                            cfg.get("oracleServiceName") or 
                            cfg.get("serviceName") or 
                            cfg.get("service_name") or 
                            cfg.get("sid") or 
                            ds.name
                        )
                    except Exception:
                        db_name = ds.name

                client_ip = request.client.host if (locals().get("request") and request.client) else "127.0.0.1"
                
                event = SecurityEvent(
                    tenant_id   = tenant_id,
                    agent_id    = agent_id,
                    source_id   = req.source_id,
                    db_type     = db_type,
                    session_pid = None,
                    db_user     = user.get("sub", ""),
                    client_ip   = client_ip,
                    client_addr = None,
                    app_name    = "MetaSight Query Gateway",
                    database    = db_name,
                    current_sql = req.sql,
                    state       = "BLOCKED",
                    blocked     = 1,
                )
                db.add(event)
                db.flush()
                
                # Check for active PAM session for this user to trigger workstation screenshot
                # (Enterprise-only — best-effort, caught by the broad except below when
                # metasight_enterprise isn't installed, same as Community's degraded behavior
                # everywhere else this package is optionally consulted.)
                from metasight_enterprise.models.pam import PAMSession
                pam_sess = db.query(PAMSession).filter(
                    PAMSession.tenant_id == tenant_id,
                    PAMSession.user_id == user.get("user_id"),
                    PAMSession.status == "ACTIVE",
                ).first()
                
                session_id = pam_sess.id if pam_sess else None
                
                # Push trigger
                from metasight_enterprise.api.pam_agent_events import _push_trigger
                _push_trigger(tenant_id, session_id, "Query blocked on MetaSight Query Page", req.sql)
                
            except Exception as e:
                logger.exception("Error triggering screenshot for blocked query: %s", e)
                try:
                    db.rollback()
                except Exception:
                    pass

            try:
                db.commit()
            except Exception:
                pass
        raise he

    # ── 6. Execute query ──────────────────────────────────────────────────────
    from app.core.query_engine import execute_query as _execute_query
    from app.core.mongo_engine import execute_mongo_query

    try:
        if is_nosql and source_type == "mongodb":
            import json
            result = execute_mongo_query(source_id=req.source_id, query=json.loads(rewritten_sql), db=db, limit=req.limit)
        elif source_type in ("s3_storage", "s3_datalake"):
            result = execute_storage_query(source_id=req.source_id, sql=rewritten_sql, db=db, limit=req.limit)
        else:
            result = _execute_query(source_id=req.source_id, sql=rewritten_sql, db=db, limit=req.limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected query execution error")
        raise HTTPException(status_code=502, detail=f"Query execution failed: {exc}")

    # Update risk with actual row count
    risk = score_query(meta, table_policies, row_count=result.row_count)

    # ── 7. Masking + tokenization ─────────────────────────────────────────────
    columns = result.columns

    # Build effective PII map: start from scan-detected types, then apply any
    # explicit masking_type overrides from policy rules (policy wins over scan)
    combined_pii_map: dict[str, str | None] = {}
    for dec in table_policies.values():
        combined_pii_map.update(dec.column_pii_map)
    # Override with explicit masking types from policy column rules
    for dec in table_policies.values():
        for col, mtype in dec.column_masking_type_map.items():
            if mtype:
                combined_pii_map[col] = mtype

    token_svc = TokenizationService(db, tenant_id)
    processed_rows: list[list] = []

    masked_col_keys = list(meta.masked_columns.keys()) or [
        c for dec in table_policies.values() for c in dec.masked_columns
    ]
    tokenize_cols = list(meta.tokenized_columns.keys()) or [
        c for dec in table_policies.values() for c in dec.tokenized_columns
    ]
    # Server-side deny enforcement, independent of connector type.
    # For SQL sources the rewriter already NULLs these columns in the executed
    # query, but for NoSQL sources (Mongo) `denied_columns` is only ever fed
    # into the *client-supplied* projection (mongo_rewriter._apply_projection) —
    # if the caller simply omits "projection" (the common case), Mongo returns
    # every field and the deny policy is never enforced. Strip denied columns
    # from every returned row here, unconditionally, regardless of connector.
    denied_col_keys = list(meta.denied_columns) or [
        c for dec in table_policies.values() for c in dec.denied_columns
    ]

    # Dynamic Column Discovery: apply tag/field policies to unscanned results
    # (Especially important for MongoDB where known_columns might be empty)
    for col in columns:
        if col in masked_col_keys or col in tokenize_cols:
            continue
        
        # Check active field policies (Explicit field-level rules or Global rules)
        for dec in table_policies.values():
            action = dec.active_field_policies.get(col)
            if action == "mask":
                masked_col_keys.append(col)
                # Infer PII type for better masking format
                if col not in combined_pii_map:
                    combined_pii_map[col] = infer_pii_type(col)
                break
            elif action == "tokenize":
                tokenize_cols.append(col)
                break
        
        # Check active tag policies (Pii-aware rules)
        if col not in masked_col_keys and col not in tokenize_cols:
            inferred_tags = infer_tags(col)
            for dec in table_policies.values():
                for tag in inferred_tags:
                    action = dec.active_tag_policies.get(tag)
                    if action == "mask":
                        masked_col_keys.append(col)
                        # Explicitly set PII type for better masking
                        if col not in combined_pii_map:
                            combined_pii_map[col] = infer_pii_type(col)
                        break
                    elif action == "tokenize":
                        tokenize_cols.append(col)
                        break
                if col in masked_col_keys or col in tokenize_cols:
                    break

    for raw_row in result.rows:
        row_dict = dict(zip(columns, raw_row))

        # Deny is a stronger control than masking — enforce it unconditionally,
        # even when an admin has requested bypass_masking=True.
        for col in denied_col_keys:
            if col in row_dict:
                row_dict[col] = None

        # Only apply masking if bypass_masking is not requested by an admin
        should_mask = not (req.bypass_masking and user_role == "admin")

        if should_mask:
            if masked_col_keys:
                row_dict = mask_row(row_dict, masked_col_keys, combined_pii_map, level=mask_level)
            for col in tokenize_cols:
                if col in row_dict and row_dict[col] is not None:
                    row_dict[col] = token_svc.tokenize(str(row_dict[col]), column_name=col)
                    
        processed_rows.append([row_dict.get(col) for col in columns])

    # Flush all pending tokenization vault entries in one bulk insert
    token_svc.flush_batch()

    # ── 8. Audit ──────────────────────────────────────────────────────────────
    policy_summary, all_denied, all_masked_cols, all_tok_cols = _build_policy_summary(
        tables, table_policies, meta, primary_decision
    )

    AuditService(db, tenant_id).log({
        "user_email": user.get("sub", ""),
        "role": user_role,
        "resource": ",".join(tables),
        "action": "query",
        "original_query": req.sql,
        "rewritten_query": rewritten_sql,
        "policy_applied": primary_decision.classification,
        "row_count": result.row_count,
        "risk_level": risk.level,
        "risk_score": risk.score,
    })

    try:
        db.commit()
        last_audit = (
            db.query(AuditLog)
            .filter(AuditLog.user_email == user.get("sub", ""), AuditLog.tenant_id == tenant_id, AuditLog.action == "query")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        if last_audit:
            audit_id = last_audit.id
    except Exception:
        logger.warning("Failed to commit audit log")

    return ExecuteQueryResponse(
        columns=columns,
        rows=processed_rows,
        row_count=result.row_count,
        execution_time_ms=result.execution_time_ms,
        policy=policy_summary,
        rewritten_sql=rewritten_sql,
        audit_id=audit_id,
        warnings=warnings,
        risk=_risk_response(risk),
        masking_level=mask_level,
    )


# ── Simulate endpoint (preview policy + rewrite, no execution) ───────────────

@router.post("/simulate", response_model=SimulateQueryResponse)
def simulate_query(
    req: SimulateQueryRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Preview what the query gateway will do — without executing the query.

    Returns:
      - Rewritten SQL (with NULL placeholders, row filters injected)
      - Per-table policy summary (masked/denied/tokenized columns)
      - Risk score with breakdown and recommendations
      - Warnings (function leakage, auto-policy, etc.)
      - Masking level for the requesting user's role
    """
    tenant_id = user["tenant_id"]
    user_role = user.get("role", "analyst")

    from app.services.settings_service import get_settings
    cfg = get_settings(tenant_id, db)
    role_levels = cfg.get("masking", {}).get("role_levels", None)
    mask_level = masking_level_for_role(user_role, role_levels)
    
    warnings: list[str] = []

    # Guard
    try:
        _guard_sql(req.sql)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Load source
    source: DataSource | None = db.get(DataSource, req.source_id)
    if source is None:
        raise HTTPException(status_code=404, detail=f"DataSource {req.source_id} not found.")
    source_type = source.type

    # Resolve policies
    tables, table_policies, pol_warnings = _resolve_table_policies(
        req.sql, req.source_id, source_type, tenant_id, user, db
    )
    warnings.extend(pol_warnings)
    primary_decision = table_policies[tables[0]]

    # Rewrite (no execution)
    try:
        rewritten_sql, meta = _sql_rewriter.rewrite_with_meta(
            req.sql, table_policies, dialect=_get_dialect(source_type)
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    warnings.extend(meta.warnings)

    # Risk score (no row count — simulation only)
    risk = score_query(meta, table_policies, row_count=0)

    policy_summary, _, _, _ = _build_policy_summary(tables, table_policies, meta, primary_decision)

    return SimulateQueryResponse(
        rewritten_sql=rewritten_sql,
        policy=policy_summary,
        risk=_risk_response(risk),
        warnings=warnings,
        tables=tables,
        masking_level=mask_level,
    )


# ── Detokenize endpoint ───────────────────────────────────────────────────────

@router.post("/detokenize")
def detokenize_value(
    token: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Reverse a token back to its original value (admin only)."""
    svc = TokenizationService(db, user["tenant_id"])
    try:
        value = svc.detokenize(token, dict(user))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    AuditService(db, user["tenant_id"]).log({
        "user_email": user.get("sub", ""),
        "role": user.get("role", ""),
        "resource": "token_vault",
        "action": "detokenize",
        "original_query": token,
    })
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="detokenize_value",
        target_type="TokenVault",
        target_id=token[:16],
        description="Reversed a tokenized value back to its original form",
        risk_level="HIGH",
    )
    db.commit()
    return {"token": token, "value": value}
