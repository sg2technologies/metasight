"""
API Endpoints for Table Metadata.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import json

from app.core.deps import get_db, get_current_user
from app.models.models import Table, ColumnEntity
from app.schemas.schemas import TableListResponse, TableDetailResponse, ColumnResponse

router = APIRouter()


@router.get("", response_model=TableListResponse)
def list_tables(
    skip: int = 0,
    limit: int = 100,
    source_id: int = None,
    schema_name: str = None,
    search: str = None,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    from app.models.models import Schema, Database, DataSource
    tenant_id = user["tenant_id"]

    q = (
        db.query(Table)
        .join(Schema, Schema.id == Table.schema_id)
        .join(Database, Database.id == Schema.database_id)
        .outerjoin(DataSource, DataSource.id == Database.data_source_id)
        .filter(Table.tenant_id == tenant_id)
    )

    if source_id is not None:
        q = q.filter(DataSource.id == source_id)
    if schema_name is not None:
        q = q.filter(Schema.name.ilike(schema_name))
    if search:
        q = q.filter(Table.name.ilike(f"%{search}%"))

    total = q.count()
    tables = q.order_by(Table.name).offset(skip).limit(limit).all()

    items = []
    for t in tables:
        db_name = t.schema.database.name if t.schema and t.schema.database else "default"
        src_type = t.schema.database.data_source.type if t.schema and t.schema.database and t.schema.database.data_source else "postgres"
        src_id = t.schema.database.data_source.id if t.schema and t.schema.database and t.schema.database.data_source else None
        s_name = t.schema.name if t.schema else None

        items.append({
            "id": t.id,
            "name": t.name,
            "schema_id": t.schema_id,
            "tenant_id": t.tenant_id,
            "source_type": src_type,
            "database_name": db_name,
            "schema_name": s_name,
            "source_id": src_id,
        })

    return TableListResponse(items=items, total=total, skip=skip, limit=limit)


@router.get("/{table_id}")
def get_table(
    table_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    from app.models.models import Schema, Database
    table = (
        db.query(Table)
        .filter(Table.id == table_id, Table.tenant_id == user["tenant_id"])
        .first()
    )
    if not table:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Table not found")
    
    # Resolve source_id and source_type
    source_id = None
    source_type = "postgres"
    if table.schema and table.schema.database and table.schema.database.data_source:
        source_id = table.schema.database.data_source.id
        source_type = table.schema.database.data_source.type
        
    return {
        "id": table.id,
        "name": table.name,
        "schema_id": table.schema_id,
        "tenant_id": table.tenant_id,
        "source_id": source_id,
        "source_type": source_type,
        "database_name": table.schema.database.name if table.schema and table.schema.database else "default",
        "schema_name": table.schema.name if table.schema else None
    }



@router.get("/{table_id}/columns", response_model=list[ColumnResponse])
def list_columns(
    table_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    table = (
        db.query(Table)
        .filter(Table.id == table_id, Table.tenant_id == user["tenant_id"])
        .first()
    )
    if not table:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Table not found")
    cols = (
        db.query(ColumnEntity)
        .filter(ColumnEntity.table_id == table_id, ColumnEntity.tenant_id == user["tenant_id"])
        .all()
    )
    results = []
    for c in cols:
        roles = c.allowed_roles
        if isinstance(roles, str):
            try: roles = json.loads(roles)
            except: roles = ["admin", "analyst"]
        
        results.append(ColumnResponse(
            id=c.id,
            name=c.name,
            type=c.type,
            pii_type=c.pii_type,
            suggested_pii_type=c.suggested_pii_type,
            classification=c.classification,
            action=c.action,
            allowed_roles=roles or ["admin", "analyst"],
            table_id=c.table_id
        ))
    return results
