import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_user, require_admin
from app.models.models import ScanRun, DataSource, ScanRunStatus
from app.workers.tasks import run_ingestion_task
from app.schemas.schemas import ScanTriggerResponse, ScanRunResponse, ScanListResponse
from app.services.governance_audit import record_privileged_activity

logger = logging.getLogger(__name__)

router = APIRouter()


class ScanSyncRequest(BaseModel):
    schemas: Optional[List[str]] = None  # None = scan all schemas


@router.post("/{source_id}/scan", response_model=ScanTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    source_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """Async scan — enqueues a Celery task. Requires Celery worker running."""
    ds = (
        db.query(DataSource)
        .filter(DataSource.id == source_id, DataSource.tenant_id == user["tenant_id"])
        .first()
    )
    if not ds:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DataSource not found")

    scan = ScanRun(
        data_source_id=source_id,
        status=ScanRunStatus.PENDING,
        tenant_id=user["tenant_id"],
    )
    db.add(scan)
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="trigger_scan",
        target_type="DataSource",
        target_id=str(source_id),
        description=f"Triggered async scan for data source {ds.name}",
        risk_level="MEDIUM",
    )
    db.commit()
    db.refresh(scan)

    try:
        run_ingestion_task.delay(scan.id)
    except Exception as exc:
        logger.error("Failed to enqueue scan %s: %s", scan.id, exc)
        scan.status = ScanRunStatus.FAILED
        scan.error = f"Failed to enqueue task: {exc}"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not enqueue scan — is the Celery worker / Redis running?",
        )
    return ScanTriggerResponse(scan_id=scan.id, status=scan.status.value)


@router.get("/{source_id}/schemas")
def list_schemas(
    source_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """
    Return available schemas with table-count and estimated row-count.
    Fast query — reads DB statistics, does NOT write anything.
    Supports Oracle, PostgreSQL, MySQL, SQL Server. Others get name-only list.
    """
    from app.core.encryption import aes_cipher
    from app.ingestion.native_scanner import list_schemas_with_stats

    ds = (
        db.query(DataSource)
        .filter(DataSource.id == source_id, DataSource.tenant_id == user["tenant_id"])
        .first()
    )
    if not ds:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DataSource not found")

    try:
        config = {k: aes_cipher.decrypt(v) for k, v in ds.encrypted_config.items()}
        return list_schemas_with_stats(ds.type, config)
    except Exception as exc:
        err = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Could not connect or list schemas: {err}")


@router.post("/{source_id}/scan/sync", response_model=ScanRunResponse)
def trigger_scan_sync(
    source_id: int,
    request_body: Optional[ScanSyncRequest] = Body(default=None),
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """
    Synchronous scan — runs directly in the request, no Celery required.
    Blocks until complete. Pass {"schemas": ["SCOTT","SALES"]} to scan specific
    schemas only (batch mode for large databases).
    """
    from app.core.encryption import aes_cipher
    from app.ingestion.native_scanner import run_native_scan

    ds = (
        db.query(DataSource)
        .filter(DataSource.id == source_id, DataSource.tenant_id == user["tenant_id"])
        .first()
    )
    if not ds:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DataSource not found")

    selected = request_body.schemas if request_body else None

    scan = ScanRun(
        data_source_id=source_id,
        status=ScanRunStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
        tenant_id=user["tenant_id"],
    )
    db.add(scan)
    schema_desc = f" (schemas: {', '.join(selected)})" if selected else ""
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="trigger_scan_sync",
        target_type="DataSource",
        target_id=str(source_id),
        description=f"Triggered synchronous scan for data source {ds.name}{schema_desc}",
        risk_level="MEDIUM",
    )
    db.commit()
    db.refresh(scan)

    try:
        config = {k: aes_cipher.decrypt(v) for k, v in ds.encrypted_config.items()}
        counts = run_native_scan(ds.type, config, ds.id, user["tenant_id"], db,
                                 selected_schemas=selected, scan_id=scan.id)
        scan.status = ScanRunStatus.COMPLETED
        suffix = f" [{len(selected)} schemas]" if selected else ""
        scan.error = (
            f"Discovered: {counts['schemas']} schemas, "
            f"{counts['tables']} tables, "
            f"{counts['columns']} columns{suffix}"
        )
        logger.info("Sync scan %s completed: %s", scan.id, counts)
    except Exception as exc:
        scan.status = ScanRunStatus.FAILED
        err_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        scan.error = err_msg
        logger.exception("Sync scan %s failed", scan.id)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Connection or Scan failed: {err_msg}",
        )
    finally:
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)

    return scan


@router.get("/runs/{scan_id}", response_model=ScanRunResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scan = (
        db.query(ScanRun)
        .filter(ScanRun.id == scan_id, ScanRun.tenant_id == user["tenant_id"])
        .first()
    )
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.get("/{source_id}/history", response_model=ScanListResponse)
def list_scans(
    source_id: int,
    skip: int = 0,
    limit: int = 50,
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

    query = (
        db.query(ScanRun)
        .filter(ScanRun.data_source_id == source_id, ScanRun.tenant_id == user["tenant_id"])
        .order_by(ScanRun.id.desc())
    )
    total = query.count()
    items = query.offset(skip).limit(limit).all()
    return ScanListResponse(items=items, total=total, skip=skip, limit=limit)


@router.post("/{source_id}/cancel")
def cancel_scan(
    source_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """Cancel any active scans (RUNNING or PENDING) for the given data source."""
    runs = (
        db.query(ScanRun)
        .filter(
            ScanRun.data_source_id == source_id,
            ScanRun.tenant_id == user["tenant_id"],
            ScanRun.status.in_([ScanRunStatus.PENDING, ScanRunStatus.RUNNING]),
        )
        .all()
    )
    if not runs:
        return {"message": "No active scans to cancel"}

    for run in runs:
        run.status = ScanRunStatus.FAILED
        run.error = "Scan stopped by user"
        run.finished_at = datetime.now(timezone.utc)

    db.commit()
    return {"message": f"Cancelled {len(runs)} scan(s)"}
