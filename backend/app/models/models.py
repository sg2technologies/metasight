from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, Enum,
    UniqueConstraint, JSON, Boolean, Index
)
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)


class UserRole(enum.Enum):
    admin = "admin"
    analyst = "analyst"


class ScanRunStatus(enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# ── Department ────────────────────────────────────────────────────────────────

class Department(Base):
    __tablename__ = "departments"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (UniqueConstraint("name", "tenant_id", name="_dept_name_tenant_uc"),)


# ── Tenant / User ─────────────────────────────────────────────────────────────

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    users = relationship("User", back_populates="tenant")
    data_sources = relationship("DataSource", back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.analyst)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)

    tenant = relationship("Tenant", back_populates="users")
    department = relationship("Department")


# ── DataSource ────────────────────────────────────────────────────────────────

class DataSource(Base):
    __tablename__ = "data_sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    category = Column(String, nullable=False, server_default="database")
    encrypted_config = Column(JSON, nullable=False)
    vault_path = Column(String, nullable=True)  # e.g. "secret/data/datasources/42"; overrides encrypted_config when set
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    tenant = relationship("Tenant", back_populates="data_sources")
    scan_runs = relationship("ScanRun", back_populates="data_source", cascade="all, delete-orphan")
    databases = relationship("Database", back_populates="data_source", cascade="all, delete-orphan")


# ── ScanRun ───────────────────────────────────────────────────────────────────

class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    data_source_id = Column(Integer, ForeignKey("data_sources.id"), nullable=False)
    status = Column(Enum(ScanRunStatus), default=ScanRunStatus.PENDING)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    error = Column(String)
    # Live progress written by the scanner on every intermediate commit:
    # {"current_schema": "HR", "schemas_done": 2, "schemas_total": 10,
    #  "tables_done": 5000, "columns_done": 150000}
    progress = Column(JSON, nullable=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)

    data_source = relationship("DataSource", back_populates="scan_runs")


# ── Metadata hierarchy ────────────────────────────────────────────────────────

class Database(Base):
    __tablename__ = "databases"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    data_source_id = Column(Integer, ForeignKey("data_sources.id"), nullable=True)

    __table_args__ = (UniqueConstraint("name", "tenant_id", name="_db_tenant_uc"),)

    data_source = relationship("DataSource", back_populates="databases")
    schemas = relationship("Schema", back_populates="database", cascade="all, delete-orphan")


class Schema(Base):
    __tablename__ = "schemas"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    database_id = Column(Integer, ForeignKey("databases.id"), nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)

    __table_args__ = (
        UniqueConstraint("name", "database_id", "tenant_id", name="_schema_db_tenant_uc"),
        Index("ix_schemas_database_id", "database_id"),
        Index("ix_schemas_tenant_id", "tenant_id"),
    )

    database = relationship("Database", back_populates="schemas")
    tables = relationship("Table", back_populates="schema", cascade="all, delete-orphan")


class Table(Base):
    __tablename__ = "tables"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    schema_id = Column(Integer, ForeignKey("schemas.id"), nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)

    __table_args__ = (
        UniqueConstraint("name", "schema_id", "tenant_id", name="_table_schema_tenant_uc"),
        Index("ix_tables_tenant_id", "tenant_id"),
        Index("ix_tables_schema_id", "schema_id"),
        Index("ix_tables_department_id", "department_id"),
        Index("ix_tables_tenant_name", "tenant_id", "name"),
    )

    schema = relationship("Schema", back_populates="tables")
    columns = relationship("ColumnEntity", back_populates="table", cascade="all, delete-orphan")

    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)
    allowed_roles = Column(JSON, nullable=False, server_default='["admin", "analyst"]')

    department = relationship("Department")


class ColumnEntity(Base):
    __tablename__ = "columns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    pii_type = Column(String, nullable=True)          # EMAIL|SSN|PHONE|CREDIT_CARD|NAME|ADDRESS|IP_ADDRESS
    suggested_pii_type = Column(String, nullable=True) # AI/Regex suggested PII type
    classification = Column(String, nullable=True)     # PII|FINANCIAL|PUBLIC
    action = Column(String, nullable=True)             # allow|mask|tokenize|deny
    allowed_roles = Column(JSON, nullable=False, server_default='["admin", "analyst"]')
    table_id = Column(Integer, ForeignKey("tables.id"), nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)

    __table_args__ = (
        UniqueConstraint("name", "table_id", "tenant_id", name="_col_table_tenant_uc"),
        Index("ix_columns_table_id", "table_id"),
        Index("ix_columns_tenant_id", "tenant_id"),
        Index("ix_columns_pii_type", "pii_type"),
    )

    table = relationship("Table", back_populates="columns")


# ── Governance models ─────────────────────────────────────────────────────────

class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True, index=True)
    resource = Column(String, nullable=False)           # table name
    database_name = Column(String, nullable=True, default="")
    classification = Column(String, nullable=False, default="PUBLIC")
    source_type = Column(String, nullable=False, default="postgres")
    column_policies = Column(JSON, nullable=False, default=dict)
    # {"email": {"action": "mask", "roles_exempt": ["admin"]}, ...}
    row_filters = Column(JSON, nullable=False, default=list)
    # [{"column": "region", "value": "{user.region}"}]
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (UniqueConstraint("resource", "tenant_id", name="_policy_resource_tenant_uc"),)


class TokenVault(Base):
    __tablename__ = "token_vault"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False, index=True)
    encrypted_value = Column(String, nullable=False)
    column_name = Column(String, nullable=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, nullable=False)
    role = Column(String, nullable=False)
    resource = Column(String, nullable=False)
    action = Column(String, nullable=False, default="query")  # query|policy_change|detokenize|classify
    original_query = Column(String, nullable=True)
    rewritten_query = Column(String, nullable=True)
    policy_applied = Column(String, nullable=True)
    row_count = Column(Integer, nullable=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=_utcnow)


class DataChangeAudit(Base):
    """
    Old/new value history for governed data and platform master data.
    External CDC/trigger collectors can write into this table through the API.
    """
    __tablename__ = "data_change_audits"

    id = Column(Integer, primary_key=True, index=True)
    entity = Column(String, nullable=False, index=True)
    entity_id = Column(String, nullable=True, index=True)
    table_name = Column(String, nullable=True, index=True)
    record_pk = Column(String, nullable=True, index=True)
    column_name = Column(String, nullable=False, index=True)
    old_value = Column(String, nullable=True)
    new_value = Column(String, nullable=True)
    changed_by = Column(String, nullable=False, index=True)
    changed_role = Column(String, nullable=True)
    changed_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    operation_type = Column(String, nullable=False, default="UPDATE", index=True)
    approval_status = Column(String, nullable=True, default="not_required")
    approval_id = Column(Integer, nullable=True)
    source_type = Column(String, nullable=True)
    source_id = Column(Integer, nullable=True)
    session_id = Column(String, nullable=True, index=True)
    request_id = Column(String, nullable=True)
    details = Column("metadata", JSON, nullable=False, default=dict)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)


class PrivilegedActivity(Base):
    """
    Searchable record of privileged/admin/steward actions.
    This is intentionally action-level evidence, not raw browser video.
    """
    __tablename__ = "privileged_activities"

    id = Column(Integer, primary_key=True, index=True)
    actor_email = Column(String, nullable=False, index=True)
    actor_role = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False, index=True)
    target_type = Column(String, nullable=True, index=True)
    target_id = Column(String, nullable=True, index=True)
    description = Column(String, nullable=True)
    risk_level = Column(String, nullable=False, default="LOW", index=True)
    occurred_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    session_id = Column(String, nullable=True, index=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    details = Column("metadata", JSON, nullable=False, default=dict)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)


class SessionRecording(Base):
    """
    Stores references to session replay/video evidence.
    The actual recording is kept in OpenReplay/PostHog/FullStory/object storage.
    """
    __tablename__ = "session_recordings"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, nullable=False, index=True)
    user_email = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False, index=True)
    replay_provider = Column(String, nullable=False, default="manual")
    recording_url = Column(String, nullable=True)
    started_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, nullable=False, default="active", index=True)
    details = Column("metadata", JSON, nullable=False, default=dict)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("session_id", "tenant_id", name="_session_recording_tenant_uc"),
    )


class AgentRegistration(Base):
    """
    A MetaSight DB-side agent registered to a tenant.
    The agent authenticates every request using api_key.
    """
    __tablename__ = "agent_registrations"

    id              = Column(Integer, primary_key=True, index=True)
    tenant_id       = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    name            = Column(String, nullable=False)          # hostname / label
    db_type         = Column(String, nullable=False)
    source_id       = Column(Integer, nullable=True)          # linked DataSource (optional)
    api_key         = Column(String, unique=True, nullable=False, index=True)
    last_seen       = Column(DateTime(timezone=True), nullable=True)
    active_sessions = Column(Integer, nullable=False, default=0)
    created_at      = Column(DateTime(timezone=True), default=_utcnow)

    # ── Per-agent access-control policy (managed from UI, polled by agent) ──
    # IP CIDRs that are "authorised" — e.g. ["10.0.0.0/8","192.168.1.50"]
    allowed_ips     = Column(JSON, nullable=False, default=list)
    # DB users that are "authorised" — e.g. ["metasight_gateway","app_readonly"]
    allowed_users   = Column(JSON, nullable=False, default=list)
    # SQL ops to flag/block even from allowed IPs — e.g. ["DROP","GRANT","TRUNCATE"]
    blocked_ops     = Column(JSON, nullable=False, default=list)
    # If True: agent auto-kills unauthorised sessions; False = alert only
    block_mode      = Column(Boolean, nullable=False, default=False)
    # Send alert when bypass is detected (connection not matching any allow rule)
    alert_on_bypass = Column(Boolean, nullable=False, default=True)
    # Agent's own reported IP (written on each heartbeat)
    agent_ip        = Column(String, nullable=True)
    # Timestamp the agent last pulled its config from the server
    config_pulled_at = Column(DateTime(timezone=True), nullable=True)


class SecurityEvent(Base):
    """
    Unauthorized direct-access event reported by a registered agent.
    """
    __tablename__ = "security_events"

    id          = Column(Integer, primary_key=True, index=True)
    tenant_id   = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    agent_id    = Column(Integer, ForeignKey("agent_registrations.id"), nullable=False)
    source_id   = Column(Integer, nullable=True)
    db_type     = Column(String, nullable=False)
    session_pid = Column(String, nullable=True)
    db_user     = Column(String, nullable=True)
    client_ip   = Column(String, nullable=True)
    client_addr = Column(String, nullable=True)
    app_name    = Column(String, nullable=True)
    database    = Column(String, nullable=True)
    current_sql = Column(String, nullable=True)
    state       = Column(String, nullable=True)
    blocked     = Column(Integer, nullable=False, default=0)   # 0=detected, 1=killed
    acknowledged = Column(Integer, nullable=False, default=0)  # 0=new, 1=ack'd
    timestamp   = Column(DateTime(timezone=True), default=_utcnow)


class SystemSettings(Base):
    """
    Per-tenant configuration store. One row per tenant.
    All configurable parameters live in the `config` JSONB column.
    """
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, unique=True)
    config = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    updated_by = Column(String, nullable=True)


class LoginAttempt(Base):
    """Tracks failed login attempts for account lockout."""
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    success = Column(Integer, nullable=False, default=0)  # 0=fail, 1=success
    attempted_at = Column(DateTime(timezone=True), default=_utcnow)


class QueryApproval(Base):
    """
    Approval request for high-risk queries (CRITICAL risk level).
    Workflow:
      1. User submits query → risk = CRITICAL → 403 with approval_id
      2. Admin approves → status = 'approved', approval_token set
      3. User re-submits with approval_token → executes
    """
    __tablename__ = "query_approvals"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    requester_email = Column(String, nullable=False)
    requester_role = Column(String, nullable=False)
    source_id = Column(Integer, nullable=False)
    sql = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)
    status = Column(String, nullable=False, default="pending")  # pending|approved|rejected|used
    approval_token = Column(String, nullable=True, unique=True)  # set on approval
    approver_email = Column(String, nullable=True)
    approver_note = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # approval TTL


class DepartmentManagement(Base):
    """
    Explicit tracking of which tables are managed under which departments.
    This version stores multiple tables in a single record per assignment.
    """
    __tablename__ = "department_management"

    id = Column(Integer, primary_key=True, index=True)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=False)
    
    # Context
    source_name = Column(String, nullable=False)
    database_name = Column(String, nullable=False)
    
    # List of tables: [{"id": 12, "name": "users"}, {"id": 13, "name": "orders"}]
    tables = Column(JSON, nullable=False, default=list)
    
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    department = relationship("Department")
