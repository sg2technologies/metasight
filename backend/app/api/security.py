"""
Security Posture API
  GET  /security/posture                  — privilege check on all sources
  POST /security/sources/{id}/check       — re-check one source
  GET  /security/hardening/{type}         — hardening guide for a connector
  POST /security/sources/{id}/harden      — apply DB hardening in-database

Agent management (called by MetaSight UI):
  POST /security/agents                   — register a new agent (admin)
  GET  /security/agents                   — list agents (admin)
  DELETE /security/agents/{id}            — remove agent (admin)

Agent callbacks (called by Go binary using X-Agent-Key header):
  POST /security/agents/heartbeat         — agent liveness ping
  POST /security/activity                 — report unauthorized session (bypass flow)

Bypass flow:
  GET  /security/bypass-flow/stats        — bypass attempt statistics

Storage security:
  POST /security/storage/check            — check S3 / Azure Blob / GCS security

Events (UI):
  GET  /security/events                   — list events for tenant
  POST /security/events/{id}/acknowledge  — mark event seen
  DELETE /security/events                 — clear all acknowledged
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_user, require_admin
from app.core.encryption import aes_cipher
from app.models.models import AgentRegistration, DataSource, SecurityEvent
from app.services.security_checker import (
    check_source_security,
    check_source_security_storage,
    is_storage_source,
    get_hardening_guide,
    apply_db_hardening,
    SecurityCheckResult,
)
from app.services.storage_scanner import check_storage, serialize_storage_result
from app.services.governance_audit import record_data_change, record_privileged_activity

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Agent-key auth helper ─────────────────────────────────────────────────────

_KEY_PREFIX_LEN = 12


def _resolve_agent(x_agent_key: str, db: Session) -> AgentRegistration:
    """Narrow by the indexed key_prefix, then decrypt-and-compare the full
    key (api_key is encrypted, not directly queryable by value — see
    AgentRegistration's model docstring for why it's encryption, not a hash,
    unlike GatewayCredential/SDKCredential)."""
    if not x_agent_key or len(x_agent_key) < _KEY_PREFIX_LEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid agent API key")
    agent = db.query(AgentRegistration).filter(
        AgentRegistration.key_prefix == x_agent_key[:_KEY_PREFIX_LEN]
    ).first()
    if not agent or not secrets.compare_digest(aes_cipher.decrypt(agent.encrypted_api_key), x_agent_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid agent API key")
    return agent


def _serialize(r: SecurityCheckResult) -> dict:
    return {
        "source_id":      r.source_id,
        "source_name":    r.source_name,
        "connector_type": r.connector_type,
        "reachable":      r.reachable,
        "score":          r.score,
        "grade":          r.grade,
        "error":          r.error,
        "checks": [
            {"name": c.name, "status": c.status, "detail": c.detail}
            for c in r.checks
        ],
    }


@router.get("/posture")
def security_posture(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Run security checks on all data sources for the current tenant.
    Returns a per-source report and an overall posture score.
    """
    sources = (
        db.query(DataSource)
        .filter(DataSource.tenant_id == user["tenant_id"])
        .all()
    )

    reports = []
    for src in sources:
        result = check_source_security(src, db)
        reports.append(_serialize(result))

    # Compute overall posture
    scored = [r for r in reports if r["grade"] not in ("?",)]
    overall = int(sum(r["score"] for r in scored) / len(scored)) if scored else 0
    if overall >= 90:   overall_grade = "A"
    elif overall >= 75: overall_grade = "B"
    elif overall >= 50: overall_grade = "C"
    elif overall >= 25: overall_grade = "D"
    else:               overall_grade = "F"

    critical_issues = sum(
        1 for r in reports for c in r["checks"] if c["status"] == "fail"
    )

    return {
        "overall_score":  overall,
        "overall_grade":  overall_grade,
        "critical_issues": critical_issues,
        "source_count":   len(reports),
        "sources":        reports,
    }


@router.post("/sources/{source_id}/check")
def check_source(
    source_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Re-run security checks on a single data source (DB or cloud storage)."""
    src = db.query(DataSource).filter(
        DataSource.id == source_id,
        DataSource.tenant_id == user["tenant_id"],
    ).first()

    if not src:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Data source not found")

    if is_storage_source(src.type):
        result = check_source_security_storage(src, db)
    else:
        result = check_source_security(src, db)
    return _serialize(result)


@router.get("/hardening/{connector_type}")
def hardening_guide(
    connector_type: str,
    user: dict = Depends(get_current_user),
):
    """Return SQL hardening steps for a specific connector type."""
    return get_hardening_guide(connector_type)


# ── Agent management (admin UI) ───────────────────────────────────────────────

class AgentCreate(BaseModel):
    name: str
    db_type: str
    source_id: Optional[int] = None


@router.post("/agents", status_code=status.HTTP_201_CREATED)
def create_agent(
    payload: AgentCreate,
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Register a new agent and return its API key (shown only once)."""
    api_key = "msa_" + secrets.token_urlsafe(32)
    agent = AgentRegistration(
        tenant_id=user["tenant_id"],
        name=payload.name,
        db_type=payload.db_type,
        source_id=payload.source_id,
        key_prefix=api_key[:_KEY_PREFIX_LEN],
        encrypted_api_key=aes_cipher.encrypt(api_key),
    )
    db.add(agent)
    db.flush()
    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="AgentRegistration",
        entity_id=str(agent.id),
        table_name="agent_registrations",
        record_pk=str(agent.id),
        column_name="*",
        old_value=None,
        new_value={"name": agent.name, "db_type": agent.db_type, "source_id": agent.source_id},
        operation_type="CREATE",
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="create_agent",
        target_type="AgentRegistration",
        target_id=str(agent.id),
        description=f"Registered monitoring agent {agent.name} ({agent.db_type})",
        risk_level="MEDIUM",
    )
    db.commit()
    db.refresh(agent)
    return {
        "id": agent.id,
        "name": agent.name,
        "db_type": agent.db_type,
        "source_id": agent.source_id,
        "api_key": api_key,   # only time the raw key is returned
        "created_at": agent.created_at,
    }


@router.get("/agents")
def list_agents(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all registered agents for this tenant."""
    agents = db.query(AgentRegistration).filter(
        AgentRegistration.tenant_id == user["tenant_id"]
    ).all()
    return [
        {
            "id":               a.id,
            "name":             a.name,
            "db_type":          a.db_type,
            "source_id":        a.source_id,
            "last_seen":        a.last_seen,
            "active_sessions":  a.active_sessions,
            "created_at":       a.created_at,
        }
        for a in agents
    ]


@router.delete("/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_agent(
    agent_id: int,
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.query(AgentRegistration).filter(
        AgentRegistration.id == agent_id,
        AgentRegistration.tenant_id == user["tenant_id"],
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="AgentRegistration",
        entity_id=str(agent.id),
        table_name="agent_registrations",
        record_pk=str(agent.id),
        column_name="*",
        old_value={"name": agent.name, "db_type": agent.db_type, "source_id": agent.source_id},
        new_value=None,
        operation_type="DELETE",
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="delete_agent",
        target_type="AgentRegistration",
        target_id=str(agent.id),
        description=f"Removed monitoring agent {agent.name} ({agent.db_type})",
        risk_level="HIGH",
    )
    db.delete(agent)
    db.commit()


# ── Agent callbacks (called by Go binary) ────────────────────────────────────

class HeartbeatPayload(BaseModel):
    agent_name: str
    db_type: str
    source_id: Optional[int] = None
    active_sessions: int = 0
    timestamp: Optional[str] = None


class ActivityPayload(BaseModel):
    agent_name: str
    db_type: str
    source_id: Optional[int] = None
    session_pid: Optional[str] = None
    db_user: Optional[str] = None
    client_ip: Optional[str] = None
    client_addr: Optional[str] = None
    app_name: Optional[str] = None
    database: Optional[str] = None
    current_sql: Optional[str] = None
    state: Optional[str] = None
    blocked: bool = False
    timestamp: Optional[str] = None


@router.post("/agents/heartbeat", status_code=status.HTTP_200_OK)
def agent_heartbeat(
    payload: HeartbeatPayload,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
    db: Session = Depends(get_db),
):
    """Agent liveness ping — updates last_seen and active_sessions."""
    agent = _resolve_agent(x_agent_key, db)
    agent.last_seen = datetime.now(timezone.utc)
    agent.active_sessions = payload.active_sessions
    db.commit()
    return {"status": "ok"}


@router.post("/activity", status_code=status.HTTP_201_CREATED)
def receive_activity(
    payload: ActivityPayload,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
    db: Session = Depends(get_db),
):
    """
    Bypass Attempt Flow — Step 2 & 3.
    Receive an unauthorized direct-DB-access event from the Go agent.

    Flow:
      01 Direct DB connection detected by agent
      02 Agent POSTs here → event recorded
      03 Threshold check: ≥3 events same IP in 5 min → auto-block flag set
      04 Webhook alert fired (Slack / Teams) if configured
      05 DB hardening fail-safe is documented in the hardening guide
    """
    agent = _resolve_agent(x_agent_key, db)
    agent.last_seen = datetime.now(timezone.utc)

    # Deduplicate: same session_pid within the last 5 minutes → skip
    if payload.session_pid:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        existing = db.query(SecurityEvent).filter(
            SecurityEvent.agent_id    == agent.id,
            SecurityEvent.session_pid == payload.session_pid,
            SecurityEvent.timestamp   >= cutoff,
        ).first()
        if existing:
            db.commit()
            return {"status": "deduplicated"}

    # Auto-block threshold: ≥3 events from the same client_ip in 5 min
    auto_blocked = False
    if payload.client_ip:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        recent_count = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.agent_id  == agent.id,
            SecurityEvent.client_ip == payload.client_ip,
            SecurityEvent.timestamp >= cutoff,
        ).scalar() or 0
        if recent_count >= 2:   # 2 existing + this one = threshold of 3
            auto_blocked = True

    event = SecurityEvent(
        tenant_id   = agent.tenant_id,
        agent_id    = agent.id,
        source_id   = payload.source_id,
        db_type     = payload.db_type,
        session_pid = payload.session_pid,
        db_user     = payload.db_user,
        client_ip   = payload.client_ip,
        client_addr = payload.client_addr,
        app_name    = payload.app_name,
        database    = payload.database,
        current_sql = payload.current_sql,
        state       = payload.state,
        blocked     = 1 if (payload.blocked or auto_blocked) else 0,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # Fire webhook alert (non-blocking best-effort)
    _fire_bypass_alert(agent.tenant_id, payload, auto_blocked, db)

    return {
        "status":       "recorded",
        "event_id":     event.id,
        "auto_blocked": auto_blocked,
    }


def _fire_bypass_alert(
    tenant_id: int,
    payload: "ActivityPayload",
    auto_blocked: bool,
    db: Session,
) -> None:
    """Send Slack / Teams / generic SIEM webhook if configured. Non-blocking —
    swallows all errors."""
    try:
        from app.services.settings_service import get_settings
        cfg = get_settings(tenant_id, db)
        notif = cfg.get("notifications", {})

        label = "BLOCKED" if auto_blocked else "DETECTED"
        text_msg = (
            f"[MetaSight] Bypass Attempt *{label}*\n"
            f"• Source: `{payload.db_type}` | DB: `{payload.database}`\n"
            f"• User: `{payload.db_user}` | IP: `{payload.client_ip}`\n"
            f"• App: `{payload.app_name}` | PID: `{payload.session_pid}`\n"
            f"• SQL: `{(payload.current_sql or '')[:200]}`"
        )

        for webhook_url in [
            notif.get("slack_webhook_url"),
            notif.get("teams_webhook_url"),
        ]:
            if not webhook_url:
                continue
            try:
                body: dict[str, Any]
                if "hooks.slack.com" in webhook_url:
                    body = {"text": text_msg}
                else:
                    # Microsoft Teams adaptive card
                    body = {
                        "@type":    "MessageCard",
                        "@context": "http://schema.org/extensions",
                        "summary":  f"Bypass attempt {label}",
                        "text":     text_msg,
                    }
                httpx.post(webhook_url, json=body, timeout=5)
            except Exception:
                pass

        generic_url = notif.get("generic_webhook_url")
        if generic_url:
            try:
                # Structured JSON, not the Slack/Teams markdown text above —
                # any SIEM ingestion endpoint (Splunk HEC-style) can consume
                # this shape directly, no chat-formatting to parse back out.
                httpx.post(generic_url, json={
                    "event":         "bypass_attempt",
                    "severity":      label,
                    "tenant_id":     tenant_id,
                    "auto_blocked":  auto_blocked,
                    "db_type":       payload.db_type,
                    "database":      payload.database,
                    "db_user":       payload.db_user,
                    "client_ip":     payload.client_ip,
                    "app_name":      payload.app_name,
                    "session_pid":   payload.session_pid,
                    "sql":           (payload.current_sql or "")[:200],
                    "timestamp":     payload.timestamp,
                }, timeout=5)
            except Exception:
                pass
    except Exception:
        pass


# ── Events (UI) ───────────────────────────────────────────────────────────────

@router.get("/events")
def list_events(
    limit: int = Query(100, le=500),
    unacknowledged_only: bool = Query(False),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List security events for the current tenant, newest first."""
    q = db.query(SecurityEvent).filter(SecurityEvent.tenant_id == user["tenant_id"])
    if unacknowledged_only:
        q = q.filter(SecurityEvent.acknowledged == 0)
    events = q.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

    return [
        {
            "id":           e.id,
            "agent_id":     e.agent_id,
            "source_id":    e.source_id,
            "db_type":      e.db_type,
            "session_pid":  e.session_pid,
            "db_user":      e.db_user,
            "client_ip":    e.client_ip,
            "app_name":     e.app_name,
            "database":     e.database,
            "current_sql":  e.current_sql,
            "state":        e.state,
            "blocked":      bool(e.blocked),
            "acknowledged": bool(e.acknowledged),
            "timestamp":    e.timestamp,
        }
        for e in events
    ]


@router.post("/events/{event_id}/acknowledge")
def acknowledge_event(
    event_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    evt = db.query(SecurityEvent).filter(
        SecurityEvent.id == event_id,
        SecurityEvent.tenant_id == user["tenant_id"],
    ).first()
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")
    evt.acknowledged = 1
    db.commit()
    return {"status": "acknowledged"}


@router.delete("/events", status_code=status.HTTP_204_NO_CONTENT)
def clear_acknowledged_events(
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Delete all acknowledged events for this tenant."""
    deleted_count = db.query(SecurityEvent).filter(
        SecurityEvent.tenant_id == user["tenant_id"],
        SecurityEvent.acknowledged == 1,
    ).count()
    db.query(SecurityEvent).filter(
        SecurityEvent.tenant_id == user["tenant_id"],
        SecurityEvent.acknowledged == 1,
    ).delete()
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="clear_acknowledged_security_events",
        target_type="SecurityEvent",
        description=f"Bulk-deleted {deleted_count} acknowledged security event(s)",
        risk_level="MEDIUM",
    )
    db.commit()


# ── Bypass Flow Statistics ────────────────────────────────────────────────────

@router.get("/bypass-flow/stats")
def bypass_flow_stats(
    days: int = Query(7, ge=1, le=90),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Bypass Attempt Flow statistics for the current tenant.
    Returns counts, top offenders, and per-day breakdown.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.tenant_id == user["tenant_id"],
            SecurityEvent.timestamp  >= cutoff,
        )
        .all()
    )

    total     = len(events)
    blocked   = sum(1 for e in events if e.blocked)
    detected  = total - blocked

    # Top 10 offending IPs
    ip_counts: dict[str, int] = {}
    for e in events:
        ip = e.client_ip or "unknown"
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Top 10 offending DB users
    user_counts: dict[str, int] = {}
    for e in events:
        u = e.db_user or "unknown"
        user_counts[u] = user_counts.get(u, 0) + 1
    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Per-day breakdown
    day_counts: dict[str, dict] = {}
    for e in events:
        day = e.timestamp.strftime("%Y-%m-%d") if e.timestamp else "unknown"
        if day not in day_counts:
            day_counts[day] = {"date": day, "total": 0, "blocked": 0}
        day_counts[day]["total"]   += 1
        day_counts[day]["blocked"] += 1 if e.blocked else 0
    timeline = sorted(day_counts.values(), key=lambda x: x["date"])

    return {
        "period_days": days,
        "total":       total,
        "blocked":     blocked,
        "detected":    detected,
        "top_ips":     [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        "top_users":   [{"db_user": u, "count": cnt} for u, cnt in top_users],
        "timeline":    timeline,
    }


# ── Active DB Hardening Enforcement ──────────────────────────────────────────

class HardenRequest(BaseModel):
    gateway_ip: str = ""


@router.post("/sources/{source_id}/harden")
def harden_source(
    source_id: int,
    payload: HardenRequest,
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    DB Hardening — Layer 3 (Fail-safe).
    Apply in-database hardening to the specified data source:
      - Create a read-only gateway user
      - Revoke write privileges
      - Enforce SSL where possible
      - Return manual steps that require server-side config changes

    Admin-only. Requires the gateway IP to restrict connections.
    """
    src = db.query(DataSource).filter(
        DataSource.id        == source_id,
        DataSource.tenant_id == user["tenant_id"],
    ).first()
    if not src:
        raise HTTPException(status_code=404, detail="Data source not found")

    if is_storage_source(src.type):
        raise HTTPException(
            status_code=400,
            detail="DB hardening is for database sources only. "
                   "Use GET /security/hardening/{type} for cloud storage guidance.",
        )

    result = apply_db_hardening(src, payload.gateway_ip, db)

    return {
        "source_id":       result.source_id,
        "source_name":     result.source_name,
        "connector_type":  result.connector_type,
        "error":           result.error,
        "steps": [
            {"title": s.title, "status": s.status, "detail": s.detail}
            for s in result.steps
        ],
    }


# ── Cloud Storage Security Check ──────────────────────────────────────────────

class StorageCheckRequest(BaseModel):
    source_type: str
    config: dict[str, Any]


@router.post("/storage/check")
def check_storage_security(
    payload: StorageCheckRequest,
    user: dict = Depends(get_current_user),
):
    """
    Run security checks on an S3 bucket, Azure Blob container, or GCS bucket.
    Credentials are passed inline (not stored). Use this for ad-hoc checks.

    source_type: "s3_storage" | "azure_blob" | "gcs_storage" | "gcs_datalake"
    config: connector-specific credential fields (see storage_scanner.py docs)
    """
    result = check_storage(payload.source_type, payload.config)
    return serialize_storage_result(result)


@router.post("/sources/{source_id}/storage-check")
def check_registered_storage(
    source_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Run storage security checks on a registered storage data source
    using its stored (encrypted) credentials.
    """
    src = db.query(DataSource).filter(
        DataSource.id        == source_id,
        DataSource.tenant_id == user["tenant_id"],
    ).first()
    if not src:
        raise HTTPException(status_code=404, detail="Data source not found")

    if not is_storage_source(src.type):
        raise HTTPException(
            status_code=400,
            detail=f"'{src.type}' is not a cloud storage source. "
                   "Use POST /security/sources/{id}/check for database sources.",
        )

    result = check_source_security_storage(src, db)
    return _serialize(result)
