from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.models import DataChangeAudit, PrivilegedActivity, SessionRecording


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stringify(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def record_data_change(
    db: Session,
    *,
    tenant_id: int,
    user: Optional[dict] = None,
    entity: str,
    column_name: str,
    old_value: Any = None,
    new_value: Any = None,
    entity_id: Optional[str] = None,
    table_name: Optional[str] = None,
    record_pk: Optional[str] = None,
    operation_type: str = "UPDATE",
    approval_status: Optional[str] = "not_required",
    approval_id: Optional[int] = None,
    source_type: Optional[str] = None,
    source_id: Optional[int] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    changed_by: Optional[str] = None,
    changed_role: Optional[str] = None,
    changed_at: Optional[datetime] = None,
    details: Optional[dict] = None,
) -> DataChangeAudit:
    actor = changed_by or (user or {}).get("sub") or "system"
    role = changed_role or (user or {}).get("role")
    event = DataChangeAudit(
        entity=entity,
        entity_id=entity_id,
        table_name=table_name,
        record_pk=record_pk,
        column_name=column_name,
        old_value=_stringify(old_value),
        new_value=_stringify(new_value),
        changed_by=actor,
        changed_role=role,
        changed_at=changed_at or _now(),
        operation_type=operation_type.upper(),
        approval_status=approval_status,
        approval_id=approval_id,
        source_type=source_type,
        source_id=source_id,
        session_id=session_id,
        request_id=request_id,
        details=details or {},
        tenant_id=tenant_id,
    )
    db.add(event)
    return event


def record_privileged_activity(
    db: Session,
    *,
    tenant_id: int,
    user: Optional[dict] = None,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    description: Optional[str] = None,
    risk_level: str = "LOW",
    session_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    actor_email: Optional[str] = None,
    actor_role: Optional[str] = None,
    occurred_at: Optional[datetime] = None,
    details: Optional[dict] = None,
) -> PrivilegedActivity:
    event = PrivilegedActivity(
        actor_email=actor_email or (user or {}).get("sub") or "system",
        actor_role=actor_role or (user or {}).get("role") or "system",
        action=action,
        target_type=target_type,
        target_id=target_id,
        description=description,
        risk_level=risk_level.upper(),
        occurred_at=occurred_at or _now(),
        session_id=session_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details or {},
        tenant_id=tenant_id,
    )
    db.add(event)
    return event


def upsert_session_recording(
    db: Session,
    *,
    tenant_id: int,
    session_id: str,
    user: Optional[dict] = None,
    user_email: Optional[str] = None,
    role: Optional[str] = None,
    replay_provider: str = "manual",
    recording_url: Optional[str] = None,
    started_at: Optional[datetime] = None,
    ended_at: Optional[datetime] = None,
    status: str = "active",
    details: Optional[dict] = None,
) -> SessionRecording:
    recording = (
        db.query(SessionRecording)
        .filter(
            SessionRecording.tenant_id == tenant_id,
            SessionRecording.session_id == session_id,
        )
        .first()
    )
    if recording is None:
        recording = SessionRecording(
            tenant_id=tenant_id,
            session_id=session_id,
            user_email=user_email or (user or {}).get("sub") or "system",
            role=role or (user or {}).get("role") or "system",
        )
        db.add(recording)

    recording.replay_provider = replay_provider or recording.replay_provider
    recording.recording_url = recording_url or recording.recording_url
    recording.started_at = started_at or recording.started_at or _now()
    recording.ended_at = ended_at
    recording.status = status
    recording.details = details or recording.details or {}
    return recording
