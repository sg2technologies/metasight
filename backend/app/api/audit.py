import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from typing import Optional

from app.core.deps import get_db, require_admin, get_current_user
from app.models.models import (
    AuditLog, DataChangeAudit, PrivilegedActivity, SessionRecording, SecurityEvent,
)
from app.schemas.schemas import (
    AuditLogListResponse,
    ComplianceSummaryResponse,
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


@router.get("/compliance/summary/export")
def compliance_summary_export(
    start_date: Optional[datetime] = Query(None, description="Inclusive lower bound (ISO 8601)"),
    end_date: Optional[datetime] = Query(None, description="Inclusive upper bound (ISO 8601)"),
    format: str = Query("json", pattern="^(json|csv)$"),
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """
    Community's "basic" compliance report: a rollup of counts/breakdowns over
    already-collected audit data (query log, data-change history, privileged
    activity, security bypass events) for a date range — no framework-specific
    control mapping (SOX/PCI/GDPR/...). That stays Enterprise's
    metasight_enterprise/api/pam_compliance.py, so there's no overlap between
    the two: this is "what happened," that is "what happened, mapped to which
    controls in which framework."
    """
    tenant_id = user["tenant_id"]

    def _range(q, col):
        if start_date:
            q = q.filter(col >= start_date)
        if end_date:
            q = q.filter(col <= end_date)
        return q

    al_base = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    query_log_total = _range(al_base, AuditLog.timestamp).count()
    query_log_by_action = dict(
        _range(
            db.query(AuditLog.action, func.count(AuditLog.id)).filter(AuditLog.tenant_id == tenant_id),
            AuditLog.timestamp,
        ).group_by(AuditLog.action).all()
    )
    query_log_distinct_users = _range(
        db.query(func.count(func.distinct(AuditLog.user_email))).filter(AuditLog.tenant_id == tenant_id),
        AuditLog.timestamp,
    ).scalar() or 0
    query_log_total_rows = _range(
        db.query(func.coalesce(func.sum(AuditLog.row_count), 0)).filter(AuditLog.tenant_id == tenant_id),
        AuditLog.timestamp,
    ).scalar() or 0

    dc_base = db.query(DataChangeAudit).filter(DataChangeAudit.tenant_id == tenant_id)
    data_change_total = _range(dc_base, DataChangeAudit.changed_at).count()
    data_change_by_op = dict(
        _range(
            db.query(DataChangeAudit.operation_type, func.count(DataChangeAudit.id)).filter(DataChangeAudit.tenant_id == tenant_id),
            DataChangeAudit.changed_at,
        ).group_by(DataChangeAudit.operation_type).all()
    )

    pa_base = db.query(PrivilegedActivity).filter(PrivilegedActivity.tenant_id == tenant_id)
    privileged_total = _range(pa_base, PrivilegedActivity.occurred_at).count()
    privileged_by_risk = dict(
        _range(
            db.query(PrivilegedActivity.risk_level, func.count(PrivilegedActivity.id)).filter(PrivilegedActivity.tenant_id == tenant_id),
            PrivilegedActivity.occurred_at,
        ).group_by(PrivilegedActivity.risk_level).all()
    )

    se_base = _range(db.query(SecurityEvent).filter(SecurityEvent.tenant_id == tenant_id), SecurityEvent.timestamp)
    security_total = se_base.count()
    security_blocked = se_base.filter(SecurityEvent.blocked == 1).count()
    security_distinct_ips = _range(
        db.query(func.count(func.distinct(SecurityEvent.client_ip))).filter(SecurityEvent.tenant_id == tenant_id),
        SecurityEvent.timestamp,
    ).scalar() or 0

    result = ComplianceSummaryResponse(
        period_start=start_date.isoformat() if start_date else None,
        period_end=end_date.isoformat() if end_date else None,
        generated_at=datetime.now(timezone.utc).isoformat(),
        query_log_total=query_log_total,
        query_log_by_action=query_log_by_action,
        query_log_distinct_users=query_log_distinct_users,
        query_log_total_rows_returned=int(query_log_total_rows),
        data_change_total=data_change_total,
        data_change_by_operation=data_change_by_op,
        privileged_activity_total=privileged_total,
        privileged_activity_by_risk_level=privileged_by_risk,
        security_bypass_total=security_total,
        security_bypass_blocked=security_blocked,
        security_bypass_detected=security_total - security_blocked,
        security_bypass_distinct_ips=security_distinct_ips,
    )

    if format == "json":
        return result

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["metric", "value"])
    for key, val in result.model_dump().items():
        if isinstance(val, dict):
            for subkey, subval in val.items():
                writer.writerow([f"{key}.{subkey}", subval])
        else:
            writer.writerow([key, val])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=metasight_compliance_summary.csv"},
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
