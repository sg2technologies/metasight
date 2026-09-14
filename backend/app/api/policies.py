from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_admin, get_current_user
from app.models.models import PolicyRule, AuditLog, DataSource
from app.schemas.schemas import (
    PolicyRuleCreate, PolicyRuleUpdate, PolicyRuleResponse, PolicyRuleListResponse,
)

from app.services.policy_cache import invalidate_policy_cache
from app.services.governance_audit import record_data_change, record_privileged_activity

logger = logging.getLogger(__name__)

router = APIRouter()

_POSTGRES_FAMILY = frozenset({
    "postgres", "postgresql", "redshift", "greenplum",
    "cockroach", "cockroachdb", "yugabyte",
})


def _try_sync_rls(rule: PolicyRule, db: Session, tenant_id: int) -> None:
    """Fire-and-forget RLS sync for postgres-family sources. Never raises."""
    if rule.source_type.lower() not in _POSTGRES_FAMILY:
        return
    try:
        from app.services.pg_rls import sync_pg_rls
        from app.core.encryption import aes_cipher

        # Find a matching DataSource for this tenant and source_type
        data_source = (
            db.query(DataSource)
            .filter(
                DataSource.tenant_id == tenant_id,
                DataSource.type == rule.source_type,
            )
            .first()
        )
        if data_source is None:
            logger.warning(
                "policies: no DataSource found for tenant=%d type=%s — skipping RLS sync",
                tenant_id, rule.source_type,
            )
            return

        encrypted_cfg: dict = data_source.encrypted_config or {}
        db_config = {
            k: aes_cipher.decrypt(v) if isinstance(v, str) else v
            for k, v in encrypted_cfg.items()
        }

        result = sync_pg_rls(rule, data_source, db_config)
        if result.get("status") == "error":
            logger.warning("policies: RLS sync failed: %s", result.get("error"))
        else:
            logger.info("policies: RLS sync ok for '%s'", rule.resource)
    except Exception as exc:
        logger.warning("policies: RLS sync exception (non-fatal): %s", exc)


@router.get("", response_model=PolicyRuleListResponse)
def list_policies(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    query = db.query(PolicyRule).filter(PolicyRule.tenant_id == user["tenant_id"])
    
    user_role = user.get("role", "analyst")
    user_dept_id = user.get("department_id")
    
    if user_role not in ("admin", "superadmin"):
        if user_dept_id:
            from app.models.models import Table
            # Filter policies where the resource matches a table in the user's department
            # Also include global policies (*)
            query = query.outerjoin(Table, PolicyRule.resource == Table.name).filter(
                (Table.department_id == user_dept_id) | (PolicyRule.resource == "*")
            )
        else:
            # No department assigned -> only see global policies or nothing
            query = query.filter(PolicyRule.resource == "*")

    rules = query.all()
    return PolicyRuleListResponse(items=rules, total=len(rules))


@router.post("", response_model=PolicyRuleResponse, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyRuleCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    existing = db.query(PolicyRule).filter(
        PolicyRule.resource == payload.resource,
        PolicyRule.tenant_id == user["tenant_id"],
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Policy for '{payload.resource}' already exists. Use PATCH to update.")

    rule = PolicyRule(
        resource=payload.resource,
        database_name=payload.database_name,
        classification=payload.classification,
        source_type=payload.source_type,
        column_policies=payload.column_policies,
        row_filters=payload.row_filters,
        tenant_id=user["tenant_id"],
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="PolicyRule",
        entity_id=str(rule.id),
        table_name="policy_rules",
        record_pk=str(rule.id),
        column_name="policy",
        old_value=None,
        new_value={
            "resource": rule.resource,
            "classification": rule.classification,
            "source_type": rule.source_type,
            "column_policies": rule.column_policies,
            "row_filters": rule.row_filters,
        },
        operation_type="INSERT",
        approval_status="not_required",
        details={"database_name": rule.database_name},
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="policy_create",
        target_type="PolicyRule",
        target_id=str(rule.id),
        description=f"Created policy for '{rule.resource}'",
        risk_level="HIGH",
        details={"resource": rule.resource, "source_type": rule.source_type},
    )
    db.commit()
    _audit(db, user, "policy_change", payload.resource, f"created policy {rule.id}")
    invalidate_policy_cache(user["tenant_id"], payload.resource)

    # Fire-and-forget RLS sync
    _try_sync_rls(rule, db, user["tenant_id"])

    return rule


@router.get("/{policy_id}", response_model=PolicyRuleResponse)
def get_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    rule = _get_or_404(db, policy_id, user["tenant_id"])
    return rule


@router.patch("/{policy_id}", response_model=PolicyRuleResponse)
def update_policy(
    policy_id: int,
    payload: PolicyRuleUpdate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    rule = _get_or_404(db, policy_id, user["tenant_id"])
    old_values = {
        "classification": rule.classification,
        "source_type": rule.source_type,
        "column_policies": rule.column_policies,
        "row_filters": rule.row_filters,
    }
    if payload.classification is not None:
        rule.classification = payload.classification
    if payload.source_type is not None:
        rule.source_type = payload.source_type
    if payload.column_policies is not None:
        rule.column_policies = payload.column_policies
    if payload.row_filters is not None:
        rule.row_filters = payload.row_filters
    db.commit()
    db.refresh(rule)
    new_values = {
        "classification": rule.classification,
        "source_type": rule.source_type,
        "column_policies": rule.column_policies,
        "row_filters": rule.row_filters,
    }
    changed_columns = [
        name for name in old_values
        if old_values[name] != new_values[name]
    ]
    for column_name in changed_columns:
        record_data_change(
            db,
            tenant_id=user["tenant_id"],
            user=user,
            entity="PolicyRule",
            entity_id=str(rule.id),
            table_name="policy_rules",
            record_pk=str(rule.id),
            column_name=column_name,
            old_value=old_values[column_name],
            new_value=new_values[column_name],
            operation_type="UPDATE",
            approval_status="not_required",
            details={"resource": rule.resource, "database_name": rule.database_name},
        )
    if changed_columns:
        record_privileged_activity(
            db,
            tenant_id=user["tenant_id"],
            user=user,
            action="policy_update",
            target_type="PolicyRule",
            target_id=str(rule.id),
            description=f"Updated policy for '{rule.resource}'",
            risk_level="HIGH",
            details={"columns": changed_columns, "resource": rule.resource},
        )
        db.commit()
    _audit(db, user, "policy_change", rule.resource, f"updated policy {rule.id}")
    invalidate_policy_cache(user["tenant_id"], rule.resource)

    # Fire-and-forget RLS sync
    _try_sync_rls(rule, db, user["tenant_id"])

    return rule


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    rule = _get_or_404(db, policy_id, user["tenant_id"])
    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="PolicyRule",
        entity_id=str(rule.id),
        table_name="policy_rules",
        record_pk=str(rule.id),
        column_name="policy",
        old_value={
            "resource": rule.resource,
            "classification": rule.classification,
            "source_type": rule.source_type,
            "column_policies": rule.column_policies,
            "row_filters": rule.row_filters,
        },
        new_value=None,
        operation_type="DELETE",
        approval_status="not_required",
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="policy_delete",
        target_type="PolicyRule",
        target_id=str(rule.id),
        description=f"Deleted policy for '{rule.resource}'",
        risk_level="HIGH",
        details={"resource": rule.resource, "source_type": rule.source_type},
    )
    _audit(db, user, "policy_change", rule.resource, f"deleted policy {rule.id}")
    db.delete(rule)
    db.commit()


def _get_or_404(db, policy_id, tenant_id):
    rule = db.query(PolicyRule).filter(
        PolicyRule.id == policy_id, PolicyRule.tenant_id == tenant_id
    ).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Policy not found")
    return rule


def _audit(db, user, action, resource, note):
    db.add(AuditLog(
        user_email=user.get("sub", ""),
        role=user.get("role", ""),
        resource=resource,
        action=action,
        original_query=note,
        tenant_id=user["tenant_id"],
    ))
    db.commit()
