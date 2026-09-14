"""
Database Activity Monitoring — Community-edition SQLAlchemy ORM models.

These are the tables behind native/agentless DAM polling (see
app/services/dam_native_poller.py): per-query activity capture and a
sensitive-object registry. Full PAM (access requests, session policy, JIT,
session recording, evidence, correlation, risk analytics, compliance
reporting) lives in app/enterprise/models/pam.py and is not part of this
edition.

DBActivity.session_id intentionally has no ForeignKey to pam_sessions and no
ORM relationship back to PAMSession — that table only exists when the
Enterprise package is installed, and Community must be able to create/query
this table on its own. Code that needs to join the two (Enterprise-side)
resolves session_id manually.
"""
from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, BigInteger, String, Text, Float, DateTime, ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import relationship
from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


# ── Database Activity Monitoring ──────────────────────────────────────────────

class DBActivity(Base):
    __tablename__ = "pam_db_activities"

    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id       = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    session_id      = Column(String(128), nullable=True)  # PAMSession.id when Enterprise is installed — no FK, see module docstring
    data_source_id  = Column(Integer, ForeignKey("data_sources.id"), nullable=True)
    agent_name      = Column(String(256), nullable=False)
    db_type         = Column(String(64),  nullable=False)
    db_user         = Column(String(256), nullable=False)
    os_user         = Column(String(256), nullable=True)
    client_ip       = Column(String(64),  nullable=True)
    client_host     = Column(String(256), nullable=True)
    client_app      = Column(String(256), nullable=True)
    db_name         = Column(String(256), nullable=True)
    schema_name     = Column(String(256), nullable=True)
    object_name     = Column(String(256), nullable=True)
    operation       = Column(String(32),  nullable=False)
    sql_text        = Column(Text, nullable=True)
    sql_hash        = Column(String(64),  nullable=True)
    rows_affected   = Column(BigInteger, nullable=True)
    exec_time_ms    = Column(Integer, nullable=True)
    status          = Column(String(32), default="SUCCESS")
    error_msg       = Column(Text, nullable=True)
    occurred_at     = Column(DateTime(timezone=True), default=_utcnow)
    risk_score      = Column(Float, default=0.0)
    risk_flags      = Column(ARRAY(String), default=list)
    sensitivity     = Column(String(32), nullable=True)
    session_pid     = Column(String(64),  nullable=True)


class SensitiveObject(Base):
    __tablename__ = "pam_sensitive_objects"

    id          = Column(Integer, primary_key=True)
    tenant_id   = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    db_type     = Column(String(64), nullable=False)
    schema_name = Column(String(256), nullable=True)
    object_name = Column(String(256), nullable=False)
    sensitivity = Column(String(32), default="CONFIDENTIAL")
    tags        = Column(ARRAY(String), default=list)
    created_at  = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        UniqueConstraint("tenant_id", "db_type", "schema_name", "object_name",
                         name="_sensitive_obj_uc"),
    )


# ── DAM Poll Watermarks ────────────────────────────────────────────────────────

class DamPollWatermark(Base):
    """Tracks the last-polled timestamp per data source for native DAM polling."""
    __tablename__ = "pam_dam_poll_watermarks"

    id             = Column(Integer, primary_key=True)
    data_source_id = Column(Integer, ForeignKey("data_sources.id"), unique=True, nullable=False)
    last_polled_at = Column(DateTime(timezone=True), default=_utcnow)
    last_event_key = Column(String(256), nullable=True)  # DB-specific cursor (e.g. Oracle audit ID)

    data_source = relationship("DataSource")
