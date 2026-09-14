"""
Standalone /catalog/schemas router.
Kept separate from the main catalog router to avoid route-ordering issues with
FastAPI's path-matching when large routers are included at the same prefix.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_user
from app.models.models import (
    Database as DBModel,
    Schema as SchemaModel,
    Table,
    ColumnEntity,
    DataSource,
)

router = APIRouter()


@router.get("/schemas")
def list_catalog_schemas(
    source_id: Optional[int] = Query(None, description="Filter by DataSource id"),
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Returns all schemas (with table count and PII column count) for the tenant,
    optionally filtered by source.  Used to build the tree browser in the UI.
    """
    tenant_id = user["tenant_id"]

    tbl_sq = (
        select(Table.schema_id, func.count(Table.id).label("cnt"))
        .where(Table.tenant_id == tenant_id)
        .group_by(Table.schema_id)
        .subquery()
    )
    pii_sq = (
        select(Table.schema_id, func.count(ColumnEntity.id).label("cnt"))
        .join(Table, Table.id == ColumnEntity.table_id)
        .where(Table.tenant_id == tenant_id, ColumnEntity.pii_type.isnot(None))
        .group_by(Table.schema_id)
        .subquery()
    )

    q = (
        db.query(
            SchemaModel.id.label("schema_id"),
            SchemaModel.name.label("schema_name"),
            DBModel.id.label("database_id"),
            DBModel.name.label("database_name"),
            DataSource.id.label("source_id"),
            DataSource.name.label("source_name"),
            DataSource.type.label("source_type"),
            func.coalesce(tbl_sq.c.cnt, 0).label("table_count"),
            func.coalesce(pii_sq.c.cnt, 0).label("pii_count"),
        )
        .join(DBModel, DBModel.id == SchemaModel.database_id)
        .join(DataSource, DataSource.id == DBModel.data_source_id)
        .outerjoin(tbl_sq, tbl_sq.c.schema_id == SchemaModel.id)
        .outerjoin(pii_sq, pii_sq.c.schema_id == SchemaModel.id)
        .filter(SchemaModel.tenant_id == tenant_id)
    )

    if source_id is not None:
        q = q.filter(DataSource.id == source_id)

    rows = q.order_by(DBModel.name, SchemaModel.name).all()

    return [
        {
            "id": r.schema_id,
            "name": r.schema_name,
            "database_id": r.database_id,
            "database_name": r.database_name,
            "source_id": r.source_id,
            "source_name": r.source_name,
            "source_type": r.source_type,
            "table_count": int(r.table_count),
            "pii_count": int(r.pii_count),
        }
        for r in rows
    ]
