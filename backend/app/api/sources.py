from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.deps import get_db, get_current_user, require_admin
from app.models.models import DataSource
from app.core.encryption import aes_cipher
from app.core.connectors import get_connector, VALID_CATEGORIES
from app.services.governance_audit import record_data_change, record_privileged_activity
from app.schemas.schemas import (
    DataSourceCreate,
    DataSourceUpdate,
    DataSourceResponse,
    DataSourceListResponse,
)

router = APIRouter()


@router.get("", response_model=DataSourceListResponse)
def list_sources(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = user["tenant_id"]
    query = db.query(DataSource).filter(DataSource.tenant_id == tenant_id)
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return DataSourceListResponse(items=items, total=total, skip=skip, limit=limit)


@router.get("/{source_id}", response_model=DataSourceResponse)
def get_source(
    source_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    ds = (
        db.query(DataSource)
        .filter(DataSource.id == source_id, DataSource.tenant_id == user["tenant_id"])
        .first()
    )
    if not ds:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DataSource not found")
    return ds


@router.post("", response_model=DataSourceResponse, status_code=status.HTTP_201_CREATED)
def create_source(
    payload: DataSourceCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    connector = get_connector(payload.type)
    if not connector:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown connector type '{payload.type}'. See GET /connectors for valid types.",
        )
    # Use the catalog's canonical category; ignore whatever the client sent
    category = connector["category"]

    encrypted_config = {k: aes_cipher.encrypt(str(v)) for k, v in payload.config.items()}
    ds = DataSource(
        name=payload.name,
        type=payload.type,
        category=category,
        encrypted_config=encrypted_config,
        vault_path=payload.vault_path or None,
        tenant_id=user["tenant_id"],
    )
    db.add(ds)
    db.commit()
    db.refresh(ds)
    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="DataSource",
        entity_id=str(ds.id),
        table_name="data_sources",
        record_pk=str(ds.id),
        column_name="source",
        old_value=None,
        new_value={"name": ds.name, "type": ds.type, "category": ds.category},
        operation_type="INSERT",
        source_type=ds.type,
        source_id=ds.id,
        details={"config_keys": sorted((payload.config or {}).keys())},
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="data_source_create",
        target_type="DataSource",
        target_id=str(ds.id),
        description=f"Created data source '{ds.name}'",
        risk_level="MEDIUM",
        details={"source_type": ds.type},
    )
    db.commit()
    return ds


@router.patch("/{source_id}", response_model=DataSourceResponse)
def update_source(
    source_id: int,
    payload: DataSourceUpdate,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    ds = (
        db.query(DataSource)
        .filter(DataSource.id == source_id, DataSource.tenant_id == user["tenant_id"])
        .first()
    )
    if not ds:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DataSource not found")

    old_name = ds.name
    old_config_keys = sorted((ds.encrypted_config or {}).keys())
    old_vault_path = ds.vault_path
    changed_columns: list[tuple[str, object, object]] = []

    if payload.name is not None:
        ds.name = payload.name
        changed_columns.append(("name", old_name, payload.name))
    if payload.config is not None:
        ds.encrypted_config = {k: aes_cipher.encrypt(str(v)) for k, v in payload.config.items()}
        changed_columns.append((
            "encrypted_config",
            {"config_keys": old_config_keys},
            {"config_keys": sorted(payload.config.keys())},
        ))
    if 'vault_path' in payload.model_fields_set:
        new_vault = payload.vault_path or None  # empty string → None
        ds.vault_path = new_vault
        changed_columns.append(("vault_path", old_vault_path, new_vault))

    db.commit()
    db.refresh(ds)
    for column_name, old_value, new_value in changed_columns:
        record_data_change(
            db,
            tenant_id=user["tenant_id"],
            user=user,
            entity="DataSource",
            entity_id=str(ds.id),
            table_name="data_sources",
            record_pk=str(ds.id),
            column_name=column_name,
            old_value=old_value,
            new_value=new_value,
            operation_type="UPDATE",
            source_type=ds.type,
            source_id=ds.id,
        )
    if changed_columns:
        record_privileged_activity(
            db,
            tenant_id=user["tenant_id"],
            user=user,
            action="data_source_update",
            target_type="DataSource",
            target_id=str(ds.id),
            description=f"Updated data source '{ds.name}'",
            risk_level="MEDIUM",
            details={"columns": [c[0] for c in changed_columns]},
        )
        db.commit()
    return ds


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_source(
    source_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    ds = (
        db.query(DataSource)
        .filter(DataSource.id == source_id, DataSource.tenant_id == user["tenant_id"])
        .first()
    )
    if not ds:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DataSource not found")
    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="DataSource",
        entity_id=str(ds.id),
        table_name="data_sources",
        record_pk=str(ds.id),
        column_name="source",
        old_value={"name": ds.name, "type": ds.type, "category": ds.category},
        new_value=None,
        operation_type="DELETE",
        source_type=ds.type,
        source_id=ds.id,
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="data_source_delete",
        target_type="DataSource",
        target_id=str(ds.id),
        description=f"Deleted data source '{ds.name}'",
        risk_level="HIGH",
        details={"source_type": ds.type},
    )
    db.delete(ds)
    db.commit()
