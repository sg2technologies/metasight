"""
Pydantic schemas for the MetaSight API.
"""
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum


def _validate_password(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters.")
    return v


# ── Auth ──────────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class LoginResponse(BaseModel):
    """POST /auth/login's actual response shape: either a real token (MFA
    not enabled / already satisfied) or an mfa_token the client must pass to
    POST /auth/mfa/challenge along with a TOTP code to get the real token."""
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class MFAChallengeRequest(BaseModel):
    mfa_token: str
    code: str


class MFAEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_png_base64: str


class MFAEnrollConfirmRequest(BaseModel):
    code: str


class MFADisableRequest(BaseModel):
    password: str


# ── Compliance summary export (Community's own rollup — Enterprise's
# framework-mapped reports live separately in pam_compliance.py) ─────────────

class ComplianceSummaryResponse(BaseModel):
    period_start: Optional[str] = None
    period_end: Optional[str] = None
    generated_at: str

    query_log_total: int
    query_log_by_action: dict[str, int]
    query_log_distinct_users: int
    query_log_total_rows_returned: int

    data_change_total: int
    data_change_by_operation: dict[str, int]

    privileged_activity_total: int
    privileged_activity_by_risk_level: dict[str, int]

    security_bypass_total: int
    security_bypass_blocked: int
    security_bypass_detected: int
    security_bypass_distinct_ips: int


class SetupRequest(BaseModel):
    # Community is single-tenant (see community_single_tenant_guard migration)
    # — the tenant name is fixed at setup time, not chosen by the installer.
    admin_email: EmailStr
    admin_password: str

    @field_validator("admin_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)


# ── User ──────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "analyst"  # "admin" or "analyst"
    department_id: Optional[int] = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str
    tenant_id: int
    department_id: Optional[int] = None


# ── DataSource ────────────────────────────────────────────────────────────────

class DataSourceCreate(BaseModel):
    name: str
    type: str
    category: Optional[str] = None  # ignored — derived server-side from connector catalog
    config: dict  # raw credentials; encrypted before storage
    vault_path: Optional[str] = None  # e.g. "secret/data/datasources/prod-pg"


class DataSourceUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None  # if provided, replaces encrypted_config entirely
    vault_path: Optional[str] = None  # send "" to clear, omit to leave unchanged


class DataSourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    category: str
    tenant_id: int
    created_at: datetime
    vault_path: Optional[str] = None


# ── Connector Catalog ─────────────────────────────────────────────────────────

class ConnectorEntry(BaseModel):
    type: str
    display_name: str
    category: str


class ConnectorCatalogResponse(BaseModel):
    categories: List[str]
    connectors: List[ConnectorEntry]


class DataSourceListResponse(BaseModel):
    items: List[DataSourceResponse]
    total: int
    skip: int
    limit: int


# ── ScanRun ───────────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanTriggerResponse(BaseModel):
    scan_id: int
    status: str


class ScanRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    data_source_id: int
    status: ScanStatus
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    # Live progress snapshot written by scanner on each intermediate commit
    progress: Optional[dict] = None
    tenant_id: int


class ScanListResponse(BaseModel):
    items: List[ScanRunResponse]
    total: int
    skip: int
    limit: int


# ── Metadata ──────────────────────────────────────────────────────────────────

class ColumnResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    pii_type: Optional[str] = None
    suggested_pii_type: Optional[str] = None
    classification: Optional[str] = None
    action: Optional[str] = None
    allowed_roles: List[str] = ["admin", "analyst"]
    table_id: int


class TableResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    schema_id: int
    tenant_id: int
    source_type: str = "postgres"
    database_name: str = ""
    schema_name: Optional[str] = None
    source_id: Optional[int] = None


class TableDetailResponse(TableResponse):
    columns: List[ColumnResponse] = []


class TableListResponse(BaseModel):
    items: List[TableResponse]
    total: int
    skip: int
    limit: int


class SchemaResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    database_id: int
    tenant_id: int


class DatabaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    tenant_id: int
    data_source_id: Optional[int] = None


# ── Policy ────────────────────────────────────────────────────────────────────

class PolicyRuleCreate(BaseModel):
    resource: str
    database_name: Optional[str] = ""
    classification: str = "PUBLIC"
    source_type: str = "postgres"
    column_policies: dict = {}
    # e.g. {"email": {"action": "mask", "roles_exempt": ["admin"]}}
    row_filters: list = []
    # e.g. [{"column": "region", "value": "{user.region}"}]


class PolicyRuleUpdate(BaseModel):
    classification: Optional[str] = None
    source_type: Optional[str] = None
    column_policies: Optional[dict] = None
    row_filters: Optional[list] = None


class PolicyRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    resource: str
    database_name: str
    classification: str
    source_type: str
    column_policies: dict
    row_filters: list
    tenant_id: int
    created_at: datetime
    updated_at: datetime


class PolicyRuleListResponse(BaseModel):
    items: List[PolicyRuleResponse]
    total: int


# ── Catalog ───────────────────────────────────────────────────────────────────

class ColumnClassifyRequest(BaseModel):
    pii_type: Optional[str] = None      # EMAIL|SSN|PHONE|CREDIT_CARD|NAME|ADDRESS|IP_ADDRESS
    classification: Optional[str] = None # PII|FINANCIAL|PUBLIC
    action: Optional[str] = None         # allow|mask|tokenize|deny


class CatalogTableResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    schema_id: int
    database_name: str = ""
    source_name: str = ""
    source_type: str = "postgres"
    tenant_id: int
    department_id: Optional[int] = None
    department_name: Optional[str] = None
    allowed_roles: List[str] = ["admin", "analyst"]
    columns: List[ColumnResponse] = []


class CatalogTableListItem(BaseModel):
    """Lightweight table record for paginated catalog list — no columns loaded."""
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    schema_id: int
    schema_name: str = ""
    database_name: str = ""
    source_id: Optional[int] = None
    source_name: str = ""
    source_type: str = "postgres"
    tenant_id: int
    department_id: Optional[int] = None
    department_name: Optional[str] = None
    allowed_roles: List[str] = ["admin", "analyst"]
    column_count: int = 0
    pii_column_count: int = 0
    row_count: Optional[int] = None


class CatalogTablePageResponse(BaseModel):
    items: List[CatalogTableListItem]
    total: int
    page: int
    page_size: int
    pages: int


# ── Department Management ─────────────────────────────────────────────────────

class DepartmentCreate(BaseModel):
    name: str

class DepartmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    tenant_id: int
    created_at: datetime

class TableVisibilityUpdate(BaseModel):
    department_id: Optional[int] = None
    allowed_roles: Optional[List[str]] = None

class ColumnVisibilityUpdate(BaseModel):
    allowed_roles: List[str]


# ── Query Proxy ───────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    source_type: str           # postgres | mysql | mongodb | snowflake …
    resource: str              # table / collection name
    query: str | dict          # SQL string OR Mongo filter dict


class QueryResponse(BaseModel):
    resource: str
    source_type: str
    original_query: str | dict
    rewritten_query: str | dict
    policy_classification: str
    columns_denied: List[str] = []
    columns_masked: List[str] = []
    columns_tokenized: List[str] = []


# ── Audit ─────────────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_email: str
    role: str
    resource: str
    action: str
    original_query: Optional[str] = None
    rewritten_query: Optional[str] = None
    policy_applied: Optional[str] = None
    row_count: Optional[int] = None
    tenant_id: int
    timestamp: datetime


class AuditLogListResponse(BaseModel):
    items: List[AuditLogResponse]
    total: int
    skip: int
    limit: int


class DataChangeAuditCreate(BaseModel):
    entity: str
    entity_id: Optional[str] = None
    table_name: Optional[str] = None
    record_pk: Optional[str] = None
    column_name: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    changed_by: Optional[str] = None
    changed_role: Optional[str] = None
    changed_at: Optional[datetime] = None
    operation_type: str = "UPDATE"
    approval_status: Optional[str] = "not_required"
    approval_id: Optional[int] = None
    source_type: Optional[str] = None
    source_id: Optional[int] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    details: dict = {}


class DataChangeAuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    entity: str
    entity_id: Optional[str] = None
    table_name: Optional[str] = None
    record_pk: Optional[str] = None
    column_name: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    changed_by: str
    changed_role: Optional[str] = None
    changed_at: datetime
    operation_type: str
    approval_status: Optional[str] = None
    approval_id: Optional[int] = None
    source_type: Optional[str] = None
    source_id: Optional[int] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    details: dict = {}
    tenant_id: int


class DataChangeAuditListResponse(BaseModel):
    items: List[DataChangeAuditResponse]
    total: int
    skip: int
    limit: int


class PrivilegedActivityCreate(BaseModel):
    actor_email: Optional[str] = None
    actor_role: Optional[str] = None
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    description: Optional[str] = None
    risk_level: str = "LOW"
    occurred_at: Optional[datetime] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: dict = {}


class PrivilegedActivityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    actor_email: str
    actor_role: str
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    description: Optional[str] = None
    risk_level: str
    occurred_at: datetime
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: dict = {}
    tenant_id: int


class PrivilegedActivityListResponse(BaseModel):
    items: List[PrivilegedActivityResponse]
    total: int
    skip: int
    limit: int


class SessionRecordingCreate(BaseModel):
    session_id: str
    user_email: Optional[str] = None
    role: Optional[str] = None
    replay_provider: str = "manual"
    recording_url: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    status: str = "active"
    details: dict = {}


class SessionRecordingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    session_id: str
    user_email: str
    role: str
    replay_provider: str
    recording_url: Optional[str] = None
    started_at: datetime
    ended_at: Optional[datetime] = None
    status: str
    details: dict = {}
    tenant_id: int


class SessionRecordingListResponse(BaseModel):
    items: List[SessionRecordingResponse]
    total: int
    skip: int
    limit: int


class GovernanceAuditSummaryResponse(BaseModel):
    change_count: int
    privileged_activity_count: int
    active_session_count: int
    replay_available_count: int


# ── Query Execute ──────────────────────────────────────────────────────────────

class PolicySummary(BaseModel):
    resource: str
    classification: str
    auto_policy: bool
    masked_columns: List[str]
    tokenized_columns: List[str]
    denied_columns: List[str]
    row_filter_applied: bool
    is_admin_exempt: bool


class RiskScoreResponse(BaseModel):
    score: float
    level: str                  # LOW | MEDIUM | HIGH | CRITICAL
    factors: dict
    recommendations: List[str]


class ExecuteQueryResponse(BaseModel):
    columns: List[str]
    rows: List[list]
    row_count: int
    execution_time_ms: float
    policy: PolicySummary
    rewritten_sql: str
    audit_id: Optional[int]
    warnings: List[str]
    risk: Optional[RiskScoreResponse] = None
    masking_level: str = "full"


class ExecuteQueryRequest(BaseModel):
    source_id: int
    sql: str
    limit: int = 1000
    approval_token: Optional[str] = None  # required for CRITICAL-risk queries
    bypass_masking: bool = False  # Allows admins to view original unmasked data

    @field_validator("limit")
    @classmethod
    def cap_limit(cls, v: int) -> int:
        return min(v, 10000)


class SimulateQueryRequest(BaseModel):
    source_id: int
    sql: str
    limit: int = 1000

    @field_validator("limit")
    @classmethod
    def cap_limit(cls, v: int) -> int:
        return min(v, 10000)


# ── Settings ──────────────────────────────────────────────────────────────────

class PublicSettingsResponse(BaseModel):
    platform_name: str
    tagline: str
    logo_url: Optional[str] = None
    primary_color: str
    accent_color: str
    support_email: Optional[str] = None
    docs_url: Optional[str] = None
    password_min_length: int
    password_require_uppercase: bool
    password_require_number: bool
    password_require_special: bool


class SimulateQueryResponse(BaseModel):
    """Preview of what will happen — no actual execution."""
    rewritten_sql: str
    policy: PolicySummary
    risk: RiskScoreResponse
    warnings: List[str]
    tables: List[str]
    masking_level: str
