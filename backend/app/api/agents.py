"""
DB-mode agent registration, config management, and heartbeat API (Community).

Key concepts
────────────
• allowed_ips   — CIDR list of client IPs that are "trusted" in the DB
• allowed_users — DB usernames that are allowed to connect directly
• blocked_ops   — SQL operations that are flagged/blocked even from trusted IPs
• block_mode    — agent kills unauthorised sessions (vs alert-only)
• agent_ip      — agent's own IP, reported on heartbeat
• config_pulled_at — timestamp the agent last fetched its config

Agents poll GET /agents/config (X-Agent-Key auth) every 30 s so policy
changes take effect without restarting the agent binary.

This table (AgentRegistration) is also used by the Enterprise PAM-endpoint
agent (metasight_enterprise.api.pam_agents, mounted at /pam/agents) for a
different agent mode, marked by a "pam:" db_type prefix — every query here
filters those rows out, and vice versa in the Enterprise router.
"""
from __future__ import annotations

import ipaddress
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import func, not_

from app.core.deps import get_db, get_current_user, require_admin
from app.models.models import AgentRegistration, SecurityEvent

router = APIRouter()

ONLINE_THRESHOLD = timedelta(minutes=2)
_NOT_PAM = not_(AgentRegistration.db_type.like("pam%"))

VALID_OPS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
             "ALTER", "CREATE", "GRANT", "REVOKE", "EXEC", "CALL"}


# ── Schemas ───────────────────────────────────────────────────────────────────

class AgentCreate(BaseModel):
    name:      str
    db_type:   str = "postgres"
    source_id: Optional[int] = None


class AgentConfigPatch(BaseModel):
    """Fields an admin can update live (agent polls and applies without restart)."""
    allowed_ips:     Optional[List[str]] = None   # CIDR notation or bare IP
    allowed_users:   Optional[List[str]] = None
    blocked_ops:     Optional[List[str]] = None   # e.g. ["DROP","GRANT"]
    block_mode:      Optional[bool]      = None
    alert_on_bypass: Optional[bool]      = None

    @field_validator("allowed_ips", mode="before")
    @classmethod
    def _validate_cidrs(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        out = []
        for entry in v:
            entry = entry.strip()
            try:
                # Accept bare IP — normalise to /32 or /128
                if "/" not in entry:
                    ipaddress.ip_address(entry)
                else:
                    ipaddress.ip_network(entry, strict=False)
                out.append(entry)
            except ValueError:
                raise ValueError(f"'{entry}' is not a valid IP address or CIDR")
        return out

    @field_validator("blocked_ops", mode="before")
    @classmethod
    def _validate_ops(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        bad = [op.upper() for op in v if op.upper() not in VALID_OPS]
        if bad:
            raise ValueError(f"Unknown operations: {bad}. Valid: {sorted(VALID_OPS)}")
        return [op.upper() for op in v]


class AgentHeartbeatIn(BaseModel):
    agent_name:      str
    agent_ip:        Optional[str] = None   # agent's own outbound IP
    active_sessions: int = 0
    db_type:         Optional[str] = None
    source_id:       Optional[int] = None


class AgentOut(BaseModel):
    id:               int
    name:             str
    db_type:          str
    mode:             str = "db"
    source_id:        Optional[int]
    api_key:          Optional[str] = None
    last_seen:        Optional[datetime]
    active_sessions:  int
    created_at:       datetime
    online:           bool
    events_today:     int
    agent_ip:         Optional[str] = None
    config_pulled_at: Optional[datetime] = None
    allowed_ips:      List[str] = []
    allowed_users:    List[str] = []
    blocked_ops:      List[str] = []
    block_mode:       bool = False
    alert_on_bypass:  bool = True
    running:          bool = False

    class Config:
        from_attributes = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _enrich(a: AgentRegistration, tenant_id: int, db: Session,
            reveal_key: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    last = a.last_seen
    if last and last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    online = bool(last and (now - last) < ONLINE_THRESHOLD)

    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    events_today = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.tenant_id == tenant_id,
        SecurityEvent.agent_id  == a.id,
        SecurityEvent.timestamp >= today_start,
    ).scalar() or 0

    from app.core.agent_runner import is_agent_running
    running = is_agent_running(("db", str(a.id)))

    return {
        "id":               a.id,
        "name":             a.name,
        "db_type":          a.db_type,
        "mode":             "db",
        "source_id":        a.source_id,
        "api_key":          a.api_key if reveal_key else None,
        "last_seen":        a.last_seen,
        "active_sessions":  a.active_sessions or 0,
        "created_at":       a.created_at,
        "online":           online,
        "events_today":     events_today,
        "agent_ip":         a.agent_ip,
        "config_pulled_at": a.config_pulled_at,
        "allowed_ips":      a.allowed_ips  or [],
        "allowed_users":    a.allowed_users or [],
        "blocked_ops":      a.blocked_ops  or [],
        "block_mode":       bool(a.block_mode),
        "alert_on_bypass":  a.alert_on_bypass if a.alert_on_bypass is not None else True,
        "running":          running,
    }


def _resolve_agent(api_key: Optional[str], db: Session) -> AgentRegistration:
    """Resolve an agent from X-Agent-Key header (used by agent-facing endpoints)."""
    if not api_key:
        raise HTTPException(401, "X-Agent-Key header required")
    agent = db.query(AgentRegistration).filter(
        AgentRegistration.api_key == api_key,
        _NOT_PAM,
    ).first()
    if not agent:
        raise HTTPException(401, "Invalid agent key")
    return agent


# ── Admin CRUD ────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[AgentOut])
def list_agents(
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    agents = (
        db.query(AgentRegistration)
        .filter(AgentRegistration.tenant_id == tid, _NOT_PAM)
        .order_by(AgentRegistration.created_at.desc())
        .all()
    )
    return [_enrich(a, tid, db) for a in agents]


@router.post("/", response_model=AgentOut, status_code=201)
def register_agent(
    body:         AgentCreate,
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    if db.query(AgentRegistration).filter(
        AgentRegistration.tenant_id == tid,
        AgentRegistration.name      == body.name,
    ).first():
        raise HTTPException(400, f"Agent '{body.name}' already registered")

    api_key = secrets.token_hex(32)

    agent = AgentRegistration(
        tenant_id       = tid,
        name            = body.name,
        db_type         = body.db_type,
        source_id       = body.source_id,
        api_key         = api_key,
        active_sessions = 0,
        created_at      = datetime.now(timezone.utc),
        allowed_ips     = [],
        allowed_users   = ["metasight_gateway"],   # safe default
        blocked_ops     = ["DROP", "TRUNCATE", "DELETE", "GRANT", "REVOKE"],
        block_mode      = False,
        alert_on_bypass = True,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return _enrich(agent, tid, db, reveal_key=True)


# ── Agent-facing endpoints (auth via X-Agent-Key) ─────────────────────────────

@router.get("/config")
def pull_config(
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    db:          Session        = Depends(get_db),
):
    """
    Called by the agent every 30 s to pick up live policy changes.
    Returns only the authorisation config (not credentials).
    """
    a = _resolve_agent(x_agent_key, db)

    # Record that the agent pulled its config
    a.last_seen       = datetime.now(timezone.utc)
    a.config_pulled_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "allowed_ips":     a.allowed_ips  or [],
        "allowed_users":   a.allowed_users or [],
        "blocked_ops":     a.blocked_ops  or [],
        "block_mode":      bool(a.block_mode),
        "alert_on_bypass": a.alert_on_bypass if a.alert_on_bypass is not None else True,
    }


@router.post("/heartbeat")
def agent_heartbeat(
    body:        AgentHeartbeatIn,
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    db:          Session        = Depends(get_db),
):
    """
    Heartbeat from the agent — updates last_seen, active_sessions, agent_ip.
    The agent sends this every 60 s.
    """
    a = _resolve_agent(x_agent_key, db)
    a.last_seen       = datetime.now(timezone.utc)
    a.active_sessions = body.active_sessions
    if body.agent_ip:
        a.agent_ip = body.agent_ip
    db.commit()
    return {"ok": True}


@router.get("/blocked-commands")
def list_blocked_commands(
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve direct DB activities/commands that were flagged or blocked.

    Correlates with user-workstation screenshots when the Enterprise PAM
    endpoint agent captured one nearby in time — that enrichment is
    best-effort and simply omitted (screenshot: None) if metasight_enterprise
    isn't installed.
    """
    from datetime import timedelta

    try:
        from metasight_enterprise.models.pam import Screenshot
    except ImportError:
        Screenshot = None

    tenant_id = current_user["tenant_id"]

    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.tenant_id == tenant_id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
        .all()
    )

    results = []
    for e in events:
        shot = None
        if Screenshot is not None:
            # Correlate screenshot by timestamp
            shot = (
                db.query(Screenshot)
                .filter(
                    Screenshot.tenant_id == tenant_id,
                    Screenshot.captured_at >= e.timestamp - timedelta(seconds=15),
                    Screenshot.captured_at <= e.timestamp + timedelta(seconds=90),
                )
                .order_by(Screenshot.captured_at.asc())
                .first()
            )

        results.append({
            "id":              e.id,
            "agent_id":        e.agent_id,
            "source_id":       e.source_id,
            "db_type":         e.db_type,
            "session_pid":     e.session_pid,
            "db_user":         e.db_user,
            "client_ip":       e.client_ip,
            "app_name":        e.app_name,
            "database":        e.database,
            "current_sql":     e.current_sql,
            "state":           e.state,
            "blocked":         bool(e.blocked),
            "acknowledged":    bool(e.acknowledged),
            "timestamp":       e.timestamp,
            "screenshot": {
                "id":            shot.id,
                "session_id":    shot.session_id or "unlinked",
                "captured_at":   shot.captured_at,
                "active_window": shot.active_window,
                "active_app":    shot.active_app,
                "file_size":     shot.file_size,
                "checksum":      shot.checksum,
                "risk_flag":     shot.risk_flag,
            } if shot else None
        })

    return results


@router.get("/{agent_id}", response_model=AgentOut)
def get_agent(
    agent_id:     int,
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    a = db.query(AgentRegistration).filter(
        AgentRegistration.id        == agent_id,
        AgentRegistration.tenant_id == tid,
        _NOT_PAM,
    ).first()
    if not a:
        raise HTTPException(404, "Agent not found")
    return _enrich(a, tid, db)


@router.delete("/{agent_id}", status_code=204)
def delete_agent(
    agent_id:     int,
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    a = db.query(AgentRegistration).filter(
        AgentRegistration.id        == agent_id,
        AgentRegistration.tenant_id == tid,
        _NOT_PAM,
    ).first()
    if not a:
        raise HTTPException(404, "Agent not found")
    db.delete(a)
    db.commit()


@router.post("/{agent_id}/rotate-key", response_model=AgentOut)
def rotate_key(
    agent_id:     int,
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    a = db.query(AgentRegistration).filter(
        AgentRegistration.id        == agent_id,
        AgentRegistration.tenant_id == tid,
        _NOT_PAM,
    ).first()
    if not a:
        raise HTTPException(404, "Agent not found")
    a.api_key = secrets.token_hex(32)
    db.commit()
    db.refresh(a)
    return _enrich(a, tid, db, reveal_key=True)


# ── Policy / Config management ────────────────────────────────────────────────

@router.patch("/{agent_id}/config", response_model=AgentOut)
def update_agent_config(
    agent_id:     int,
    body:         AgentConfigPatch,
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    """
    Update the agent's access-control policy from the UI.
    Changes are picked up by the agent within 30 s (next config-poll cycle).
    """
    tid = current_user["tenant_id"]
    a = db.query(AgentRegistration).filter(
        AgentRegistration.id        == agent_id,
        AgentRegistration.tenant_id == tid,
        _NOT_PAM,
    ).first()
    if not a:
        raise HTTPException(404, "Agent not found")

    if body.allowed_ips     is not None: a.allowed_ips     = body.allowed_ips
    if body.allowed_users   is not None: a.allowed_users   = body.allowed_users
    if body.blocked_ops     is not None: a.blocked_ops     = body.blocked_ops
    if body.block_mode      is not None: a.block_mode      = body.block_mode
    if body.alert_on_bypass is not None: a.alert_on_bypass = body.alert_on_bypass

    db.commit()
    db.refresh(a)
    return _enrich(a, tid, db)


# ── Events + Stats ────────────────────────────────────────────

@router.get("/{agent_id}/events")
def agent_events(
    agent_id:   int,
    limit:      int            = Query(100, le=500),
    event_type: Optional[str]  = Query(None),
    db:         Session        = Depends(get_db),
    current_user: dict         = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    a = db.query(AgentRegistration).filter(
        AgentRegistration.id        == agent_id,
        AgentRegistration.tenant_id == tid,
        _NOT_PAM,
    ).first()
    if not a:
        raise HTTPException(404, "Agent not found")

    q = db.query(SecurityEvent).filter(
        SecurityEvent.tenant_id == tid,
        SecurityEvent.agent_id  == a.id,
    )
    return [
        {
            "id":          e.id,
            "session_id":  e.session_pid,
            "event_type":  "APP_BLOCKED" if e.blocked else "UNAUTHORIZED",
            "occurred_at": e.timestamp.isoformat(),
            "risk_flag":   True,
            "payload":     {
                "db_user": e.db_user,
                "client_ip": e.client_ip,
                "client_addr": e.client_addr,
                "app_name": e.app_name,
                "database": e.database,
                "current_sql": e.current_sql,
                "state": e.state,
                "blocked": bool(e.blocked),
            },
        }
        for e in q.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    ]


@router.get("/{agent_id}/stats")
def agent_stats(
    agent_id:     int,
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    a = db.query(AgentRegistration).filter(
        AgentRegistration.id        == agent_id,
        AgentRegistration.tenant_id == tid,
        _NOT_PAM,
    ).first()
    if not a:
        raise HTTPException(404, "Agent not found")

    now   = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    base = db.query(SecurityEvent).filter(
        SecurityEvent.tenant_id == tid,
        SecurityEvent.agent_id  == a.id,
    )
    total_count = base.count()
    today_count = base.filter(SecurityEvent.timestamp >= today).count()
    return {
        "total_events":  total_count,
        "events_today":  today_count,
        "risk_events":   total_count,
        "risk_today":    today_count,
        "by_type_today": {
            "APP_BLOCKED": base.filter(SecurityEvent.timestamp >= today, SecurityEvent.blocked == 1).count(),
            "UNAUTHORIZED": base.filter(SecurityEvent.timestamp >= today, SecurityEvent.blocked == 0).count(),
        },
    }


@router.post("/{agent_id}/start", response_model=AgentOut)
def start_agent_endpoint(
    agent_id:     int,
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    a = db.query(AgentRegistration).filter(
        AgentRegistration.id        == agent_id,
        AgentRegistration.tenant_id == tid,
        _NOT_PAM,
    ).first()
    if not a:
        raise HTTPException(404, "Agent not found")

    from app.core.agent_runner import start_db_agent
    if not start_db_agent(agent_id, db):
        raise HTTPException(500, "Failed to start DB Agent")

    db.refresh(a)
    return _enrich(a, tid, db)


@router.post("/{agent_id}/stop", response_model=AgentOut)
def stop_agent_endpoint(
    agent_id:     int,
    db:           Session = Depends(get_db),
    current_user: dict    = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    a = db.query(AgentRegistration).filter(
        AgentRegistration.id        == agent_id,
        AgentRegistration.tenant_id == tid,
        _NOT_PAM,
    ).first()
    if not a:
        raise HTTPException(404, "Agent not found")

    from app.core.agent_runner import stop_db_agent, is_agent_running
    if is_agent_running(("db", str(agent_id))):
        if not stop_db_agent(agent_id):
            raise HTTPException(500, "Failed to stop DB Agent")

    db.refresh(a)
    return _enrich(a, tid, db)
