from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from typing import Optional

from app.core.deps import get_db, require_admin, get_current_user
from app.models.models import AuditLog, DataChangeAudit, PrivilegedActivity, SessionRecording
from app.schemas.schemas import (
    AuditLogListResponse,
    DataChangeAuditCreate,
    DataChangeAuditListResponse,
    DataChangeAuditResponse,
    GovernanceAuditSummaryResponse,
    PrivilegedActivityCreate,
    PrivilegedActivityListResponse,
    PrivilegedActivityResponse,
    SessionRecordingCreate,
    SessionRecordingListResponse,
    SessionRecordingResponse,
)
from app.services.governance_audit import (
    record_data_change,
    record_privileged_activity,
    upsert_session_recording,
)

router = APIRouter()


@router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    resource: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    q = db.query(AuditLog).filter(AuditLog.tenant_id == user["tenant_id"])
    if resource:
        q = q.filter(AuditLog.resource == resource)
    if action:
        q = q.filter(AuditLog.action == action)
    total = q.count()
    items = q.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return AuditLogListResponse(items=items, total=total, skip=skip, limit=limit)


@router.get("/governance/summary", response_model=GovernanceAuditSummaryResponse)
def governance_summary(
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    tenant_id = user["tenant_id"]
    return GovernanceAuditSummaryResponse(
        change_count=db.query(DataChangeAudit).filter(DataChangeAudit.tenant_id == tenant_id).count(),
        privileged_activity_count=db.query(PrivilegedActivity).filter(PrivilegedActivity.tenant_id == tenant_id).count(),
        active_session_count=db.query(SessionRecording).filter(
            SessionRecording.tenant_id == tenant_id,
            SessionRecording.status == "active",
        ).count(),
        replay_available_count=db.query(SessionRecording).filter(
            SessionRecording.tenant_id == tenant_id,
            SessionRecording.recording_url.isnot(None),
        ).count(),
    )


@router.get("/governance/changes", response_model=DataChangeAuditListResponse)
def list_data_change_audits(
    entity: Optional[str] = Query(None),
    changed_by: Optional[str] = Query(None),
    operation_type: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    q = db.query(DataChangeAudit).filter(DataChangeAudit.tenant_id == user["tenant_id"])
    if entity:
        q = q.filter(DataChangeAudit.entity.ilike(f"%{entity}%"))
    if changed_by:
        q = q.filter(DataChangeAudit.changed_by.ilike(f"%{changed_by}%"))
    if operation_type:
        q = q.filter(DataChangeAudit.operation_type == operation_type.upper())
    if session_id:
        q = q.filter(DataChangeAudit.session_id == session_id)
    total = q.count()
    items = q.order_by(DataChangeAudit.changed_at.desc()).offset(skip).limit(limit).all()
    return DataChangeAuditListResponse(items=items, total=total, skip=skip, limit=limit)


@router.post("/governance/changes", response_model=DataChangeAuditResponse)
def create_data_change_audit(
    payload: DataChangeAuditCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    event = record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity=payload.entity,
        entity_id=payload.entity_id,
        table_name=payload.table_name,
        record_pk=payload.record_pk,
        column_name=payload.column_name,
        old_value=payload.old_value,
        new_value=payload.new_value,
        changed_by=payload.changed_by,
        changed_role=payload.changed_role,
        changed_at=payload.changed_at,
        operation_type=payload.operation_type,
        approval_status=payload.approval_status,
        approval_id=payload.approval_id,
        source_type=payload.source_type,
        source_id=payload.source_id,
        session_id=payload.session_id,
        request_id=payload.request_id,
        details=payload.details,
    )
    db.commit()
    db.refresh(event)
    return event


@router.get("/governance/activities", response_model=PrivilegedActivityListResponse)
def list_privileged_activities(
    actor_email: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    q = db.query(PrivilegedActivity).filter(PrivilegedActivity.tenant_id == user["tenant_id"])
    if actor_email:
        q = q.filter(PrivilegedActivity.actor_email.ilike(f"%{actor_email}%"))
    if action:
        q = q.filter(PrivilegedActivity.action == action)
    if risk_level:
        q = q.filter(PrivilegedActivity.risk_level == risk_level.upper())
    if session_id:
        q = q.filter(PrivilegedActivity.session_id == session_id)
    total = q.count()
    items = q.order_by(PrivilegedActivity.occurred_at.desc()).offset(skip).limit(limit).all()
    return PrivilegedActivityListResponse(items=items, total=total, skip=skip, limit=limit)


@router.post("/governance/activities", response_model=PrivilegedActivityResponse)
def create_privileged_activity(
    payload: PrivilegedActivityCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    event = record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action=payload.action,
        target_type=payload.target_type,
        target_id=payload.target_id,
        description=payload.description,
        risk_level=payload.risk_level,
        session_id=payload.session_id,
        ip_address=payload.ip_address or (request.client.host if request.client else None),
        user_agent=payload.user_agent or request.headers.get("user-agent"),
        actor_email=payload.actor_email,
        actor_role=payload.actor_role,
        occurred_at=payload.occurred_at,
        details=payload.details,
    )
    db.commit()
    db.refresh(event)
    return event


@router.get("/governance/sessions", response_model=SessionRecordingListResponse)
def list_session_recordings(
    user_email: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    q = db.query(SessionRecording).filter(SessionRecording.tenant_id == user["tenant_id"])
    if user_email:
        q = q.filter(SessionRecording.user_email.ilike(f"%{user_email}%"))
    if status:
        q = q.filter(SessionRecording.status == status)
    total = q.count()
    items = q.order_by(SessionRecording.started_at.desc()).offset(skip).limit(limit).all()
    return SessionRecordingListResponse(items=items, total=total, skip=skip, limit=limit)


@router.post("/governance/sessions", response_model=SessionRecordingResponse)
def create_or_update_session_recording(
    payload: SessionRecordingCreate,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    recording = upsert_session_recording(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        session_id=payload.session_id,
        user_email=payload.user_email,
        role=payload.role,
        replay_provider=payload.replay_provider,
        recording_url=payload.recording_url,
        started_at=payload.started_at,
        ended_at=payload.ended_at,
        status=payload.status,
        details=payload.details,
    )
    db.commit()
    db.refresh(recording)
    return recording
