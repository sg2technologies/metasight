"""
Catalog API — browse the metadata hierarchy with PII classifications,
and allow admins to classify individual columns.

Performance design for large environments (10K+ tables, TB-scale):
  - /catalog/tables returns lightweight paginated list (no columns loaded)
  - Columns are fetched on demand per table via /catalog/tables/{id}
  - Server-side search and schema/source filters pushed to SQL
  - Column counts computed via aggregate subquery, not row hydration
"""
from math import ceil
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload
import json

from app.core.deps import get_db, get_current_user, require_admin
from app.models.models import (
    Database as DBModel, Schema as SchemaModel,
    Table, ColumnEntity, AuditLog, Department, DataSource,
)
from app.schemas.schemas import (
    CatalogTableResponse, CatalogTableListItem, CatalogTablePageResponse,
    ColumnClassifyRequest, ColumnResponse,
    DepartmentCreate, DepartmentResponse, TableVisibilityUpdate, ColumnVisibilityUpdate,
)
from app.services.governance_audit import record_data_change, record_privileged_activity

router = APIRouter()


# ── Column-count subqueries (evaluated once per request, not per row) ──────────

def _col_count_subq(tenant_id: int):
    """Returns a subquery: table_id → total column count."""
    return (
        select(ColumnEntity.table_id, func.count(ColumnEntity.id).label("cnt"))
        .where(ColumnEntity.tenant_id == tenant_id)
        .group_by(ColumnEntity.table_id)
        .subquery()
    )


def _pii_count_subq(tenant_id: int):
    """Returns a subquery: table_id → PII column count."""
    return (
        select(ColumnEntity.table_id, func.count(ColumnEntity.id).label("cnt"))
        .where(ColumnEntity.tenant_id == tenant_id, ColumnEntity.pii_type.isnot(None))
        .group_by(ColumnEntity.table_id)
        .subquery()
    )



@router.get("/tables", response_model=CatalogTablePageResponse)
def list_catalog_tables(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None, description="Filter by table name (case-insensitive)"),
    source_id: Optional[int] = Query(None, description="Filter by DataSource id"),
    schema_id: Optional[int] = Query(None, description="Filter by Schema id"),
    pii_only: bool = Query(False, description="Return only tables that have PII columns"),
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Paginated, lightweight table list — columns are NOT loaded here.
    Use GET /catalog/tables/{id} to load a specific table with its columns.
    """
    tenant_id = user["tenant_id"]
    user_role = user.get("role", "analyst")
    user_dept_id = user.get("department_id")

    col_sq = _col_count_subq(tenant_id)
    pii_sq = _pii_count_subq(tenant_id)

    q = (
        db.query(
            Table,
            func.coalesce(col_sq.c.cnt, 0).label("column_count"),
            func.coalesce(pii_sq.c.cnt, 0).label("pii_column_count"),
        )
        .outerjoin(col_sq, col_sq.c.table_id == Table.id)
        .outerjoin(pii_sq, pii_sq.c.table_id == Table.id)
        .join(SchemaModel, SchemaModel.id == Table.schema_id)
        .join(DBModel, DBModel.id == SchemaModel.database_id)
        .join(DataSource, DataSource.id == DBModel.data_source_id)
        .outerjoin(Department, Department.id == Table.department_id)
        .filter(Table.tenant_id == tenant_id)
    )

    # ── Role / department filter ────────────────────────────────────────────────
    if user_role not in ("admin", "superadmin"):
        if user_dept_id:
            q = q.filter(Table.department_id == user_dept_id)
        else:
            q = q.filter(Table.id == -1)

    # ── Search / source / schema filters (pushed to SQL) ───────────────────────
    if search:
        q = q.filter(Table.name.ilike(f"%{search}%"))
    if source_id is not None:
        q = q.filter(DataSource.id == source_id)
    if schema_id is not None:
        q = q.filter(Table.schema_id == schema_id)
    if pii_only:
        q = q.filter(pii_sq.c.cnt > 0)

    total = q.count()
    offset = (page - 1) * page_size
    rows = q.order_by(Table.name).offset(offset).limit(page_size).all()

    items: List[CatalogTableListItem] = []
    for row in rows:
        t, col_cnt, pii_cnt = row

        t_roles = t.allowed_roles
        if isinstance(t_roles, str):
            try:
                t_roles = json.loads(t_roles)
            except Exception:
                t_roles = ["admin", "analyst"]
        elif not t_roles:
            t_roles = ["admin", "analyst"]

        if user_role not in ("admin", "superadmin") and user_role not in t_roles:
            continue

        ds = t.schema.database.data_source if t.schema and t.schema.database else None
        items.append(CatalogTableListItem(
            id=t.id,
            name=t.name,
            schema_id=t.schema_id,
            schema_name=t.schema.name if t.schema else "",
            database_name=t.schema.database.name if t.schema and t.schema.database else "",
            source_id=ds.id if ds else None,
            source_name=ds.name if ds else "",
            source_type=ds.type if ds else "postgres",
            tenant_id=t.tenant_id,
            department_id=t.department_id,
            department_name=t.department.name if t.department else None,
            allowed_roles=t_roles,
            column_count=int(col_cnt),
            pii_column_count=int(pii_cnt),
            row_count=t.row_count if hasattr(t, "row_count") else None,
        ))

    return CatalogTablePageResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, ceil(total / page_size)),
    )


@router.get("/tables/{table_id}", response_model=CatalogTableResponse)
def get_catalog_table(
    table_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Load a single table with all its columns (called on demand when user expands a row)."""
    user_role = user.get("role", "analyst")

    table = (
        db.query(Table)
        .filter(Table.id == table_id, Table.tenant_id == user["tenant_id"])
        .options(
            joinedload(Table.columns),
            joinedload(Table.schema).joinedload(SchemaModel.database).joinedload(DBModel.data_source),
            joinedload(Table.department),
        )
        .first()
    )
    if not table:
        raise HTTPException(status_code=404, detail="Table not found")

    db_name = table.schema.database.name if table.schema and table.schema.database else "N/A"
    src_name = table.schema.database.data_source.name if table.schema and table.schema.database and table.schema.database.data_source else "N/A"
    src_type = table.schema.database.data_source.type if table.schema and table.schema.database and table.schema.database.data_source else "postgres"

    t_roles = table.allowed_roles
    if isinstance(t_roles, str):
        try:
            t_roles = json.loads(t_roles)
        except Exception:
            t_roles = ["admin", "analyst"]
    t_roles = t_roles or ["admin", "analyst"]

    mapped_columns = []
    for c in table.columns:
        c_roles = c.allowed_roles
        if isinstance(c_roles, str):
            try:
                c_roles = json.loads(c_roles)
            except Exception:
                c_roles = ["admin", "analyst"]
        elif not c_roles:
            c_roles = ["admin", "analyst"]

        if user_role == "admin" or user_role in c_roles:
            mapped_columns.append(ColumnResponse(
                id=c.id,
                name=c.name,
                type=c.type,
                pii_type=c.pii_type,
                suggested_pii_type=c.suggested_pii_type,
                classification=c.classification,
                action=c.action,
                allowed_roles=c_roles,
                table_id=c.table_id,
            ))

    return CatalogTableResponse(
        id=table.id,
        name=table.name,
        schema_id=table.schema_id,
        database_name=db_name,
        source_name=src_name,
        source_type=src_type,
        tenant_id=table.tenant_id,
        department_id=table.department_id,
        department_name=table.department.name if table.department else None,
        allowed_roles=t_roles,
        columns=mapped_columns,
    )


@router.patch("/columns/{column_id}", response_model=ColumnResponse)
def classify_column(
    column_id: int,
    payload: ColumnClassifyRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """Set PII type, classification, and default action for a column."""
    col = (
        db.query(ColumnEntity)
        .filter(ColumnEntity.id == column_id, ColumnEntity.tenant_id == user["tenant_id"])
        .first()
    )
    if not col:
        raise HTTPException(status_code=404, detail="Column not found")

    old_values = {
        "pii_type": col.pii_type,
        "classification": col.classification,
        "action": col.action,
    }
    col.pii_type = payload.pii_type
    col.classification = payload.classification
    col.action = payload.action

    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="ColumnEntity",
        entity_id=str(col.id),
        table_name="columns",
        record_pk=str(col.id),
        column_name="pii_type,classification,action",
        old_value=old_values,
        new_value={"pii_type": payload.pii_type, "classification": payload.classification, "action": payload.action},
        operation_type="UPDATE",
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="classify_column",
        target_type="ColumnEntity",
        target_id=str(col.id),
        description=f"Classified column {col.name} as {payload.pii_type}/{payload.classification}",
        risk_level="MEDIUM",
    )

    db.add(AuditLog(
        user_email=user.get("sub", ""),
        role=user.get("role", ""),
        resource=f"column:{column_id}",
        action="classify",
        original_query=f"pii_type={payload.pii_type} classification={payload.classification} action={payload.action}",
        tenant_id=user["tenant_id"],
    ))
    db.commit()
    db.refresh(col)
    return col


# ── Department Management ─────────────────────────────────────────────────────

@router.get("/departments", response_model=List[DepartmentResponse])
def list_departments(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    return db.query(Department).filter(Department.tenant_id == user["tenant_id"]).all()


@router.post("/departments", response_model=DepartmentResponse)
def create_department(
    payload: DepartmentCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    dept = Department(name=payload.name, tenant_id=user["tenant_id"])
    db.add(dept)
    try:
        db.commit()
        db.refresh(dept)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Department already exists")
    return dept


# ── Table & Column Visibility ─────────────────────────────────────────────────

@router.patch("/tables/{table_id}/visibility", response_model=CatalogTableResponse)
def update_table_visibility(
    table_id: int,
    payload: TableVisibilityUpdate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    table = db.query(Table).filter(Table.id == table_id, Table.tenant_id == user["tenant_id"]).first()
    if not table:
        raise HTTPException(status_code=404, detail="Table not found")

    old_values = {"department_id": table.department_id, "allowed_roles": table.allowed_roles}
    if payload.department_id is not None:
        table.department_id = payload.department_id
    if payload.allowed_roles is not None:
        table.allowed_roles = payload.allowed_roles

    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="Table",
        entity_id=str(table.id),
        table_name="tables",
        record_pk=str(table.id),
        column_name="department_id,allowed_roles",
        old_value=old_values,
        new_value={"department_id": table.department_id, "allowed_roles": table.allowed_roles},
        operation_type="UPDATE",
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="update_table_visibility",
        target_type="Table",
        target_id=str(table.id),
        description=f"Updated visibility for table {table.name}",
        risk_level="MEDIUM",
    )

    db.commit()
    db.refresh(table)
    return get_catalog_table(table_id, db, user)


@router.patch("/columns/{column_id}/visibility", response_model=ColumnResponse)
def update_column_visibility(
    column_id: int,
    payload: ColumnVisibilityUpdate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    col = db.query(ColumnEntity).filter(ColumnEntity.id == column_id, ColumnEntity.tenant_id == user["tenant_id"]).first()
    if not col:
        raise HTTPException(status_code=404, detail="Column not found")

    old_roles = col.allowed_roles
    col.allowed_roles = payload.allowed_roles

    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="ColumnEntity",
        entity_id=str(col.id),
        table_name="columns",
        record_pk=str(col.id),
        column_name="allowed_roles",
        old_value=old_roles,
        new_value=payload.allowed_roles,
        operation_type="UPDATE",
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="update_column_visibility",
        target_type="ColumnEntity",
        target_id=str(col.id),
        description=f"Updated visibility for column {col.name}",
        risk_level="MEDIUM",
    )

    db.commit()
    db.refresh(col)
    return col
