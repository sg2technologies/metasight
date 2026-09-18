"""
MetaSight Gateway — admin GatewayCredential CRUD, the gateway-facing
authenticate/prepare/audit endpoints the Go protocol adapters
(backend/gateway/) call, and an internal-only backend-credentials
endpoint the gateway uses to resolve the real DataSource connection it
brokers on the client's behalf.

Auth model differs from Enterprise's /sdk/*: a wire-protocol client
authenticates once per connection (username + secret, mirroring e.g.
Postgres's own StartupMessage + PasswordMessage split) via
POST /gateway/authenticate, then subsequent POST /gateway/prepare calls for
that connection's queries pass the resolved credential_id only (no need to
resend the secret) — but /gateway/prepare re-checks status/expiry fresh on
every call, so a revoked credential stops working on the very next query
even on an already-open connection, not just on the next new connection.
"""
from __future__ import annotations

import os
import secrets as secrets_module
from datetime import datetime, timezone
from typing import Any, Optional, List

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_admin
from app.core.security import hash_password, verify_password
from app.models.models import DataSource, User, Department
from app.models.gateway_credential import GatewayCredential
from app.services.audit import AuditService
from app.services.gateway_prepare import prepare as prepare_query_decision, PrepareResponse

router = APIRouter()

_KEY_PREFIX_LEN = 12  # not used for lookup here (gateway_username itself is the lookup key),
                       # kept only for parity/documentation with the SDK's key-prefix convention


# ── Schemas ──────────────────────────────────────────────────────────────────

class GatewayCredentialCreate(BaseModel):
    data_source_id: int
    display_name: str
    gateway_username: str
    user_id: Optional[int] = None
    role_override: Optional[str] = None
    department_id_override: Optional[int] = None
    region_override: Optional[str] = None
    expires_at: Optional[datetime] = None


class GatewayCredentialPatch(BaseModel):
    status: Optional[str] = None  # ACTIVE|REVOKED|DISABLED
    role_override: Optional[str] = None
    department_id_override: Optional[int] = None
    region_override: Optional[str] = None
    expires_at: Optional[datetime] = None


class GatewayCredentialOut(BaseModel):
    id: int
    data_source_id: int
    user_id: Optional[int]
    gateway_username: str
    display_name: str
    role_override: Optional[str]
    department_id_override: Optional[int]
    region_override: Optional[str]
    status: str
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]
    secret: Optional[str] = None  # populated only on create/rotate

    class Config:
        from_attributes = True


class AuthenticateRequest(BaseModel):
    gateway_username: str
    secret: str


class AuthenticateResponse(BaseModel):
    credential_id: int
    data_source_id: int
    role: str


class GatewayPrepareRequest(BaseModel):
    credential_id: int
    query: Any
    application_name: Optional[str] = None
    client_ip: Optional[str] = None


class GatewayAuditReport(BaseModel):
    credential_id: int
    resource: str
    action: str = "gateway_query"
    original_query: Optional[str] = None
    rewritten_query: Optional[str] = None
    policy_applied: Optional[str] = None
    row_count: int = 0
    application_name: Optional[str] = None
    client_ip: Optional[str] = None


class BackendCredentialsResponse(BaseModel):
    db_type: str
    host: str
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    database: Optional[str] = None


# ── Helpers ──────────────────────────────────────────────────────────────────

_VALID_STATUSES = {"ACTIVE", "REVOKED", "DISABLED"}


def _out(cred: GatewayCredential, secret: Optional[str] = None) -> GatewayCredentialOut:
    data = GatewayCredentialOut.model_validate(cred, from_attributes=True)
    data.secret = secret
    return data


def _get_owned(cred_id: int, tenant_id: int, db: Session) -> GatewayCredential:
    cred = db.query(GatewayCredential).filter(
        GatewayCredential.id == cred_id,
        GatewayCredential.tenant_id == tenant_id,
    ).first()
    if not cred:
        raise HTTPException(404, "Gateway credential not found")
    return cred


def _generate_secret() -> str:
    return secrets_module.token_urlsafe(24)


def _check_active(cred: GatewayCredential) -> None:
    if cred.status != "ACTIVE":
        raise HTTPException(401, "Gateway credential is not active")
    if cred.expires_at is not None:
        expires_at = cred.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(401, "Gateway credential has expired")


def _effective_user(cred: GatewayCredential) -> dict:
    role = cred.role_override or (cred.user.role.value if cred.user_id and cred.user else "viewer")
    department_id = cred.department_id_override or (
        cred.user.department_id if cred.user_id and cred.user else None
    )
    sub = cred.user.email if cred.user_id and cred.user else cred.display_name
    return {
        "sub": sub,
        "role": role,
        "tenant_id": cred.tenant_id,
        "department_id": department_id,
        "region": cred.region_override,
    }


def _check_internal_key(x_internal_key: Optional[str]) -> None:
    """Auth for the backend-credentials endpoint — a separate process-level
    shared secret (GATEWAY_INTERNAL_API_KEY env var), never a per-client
    GatewayCredential. Deliberately not part of app.core.config.Settings —
    this is gateway-specific, not core config surface every deployment
    needs. Must only ever be reachable from the gateway process's own
    host/network segment; see DEPLOYMENT.md."""
    expected = os.environ.get("GATEWAY_INTERNAL_API_KEY")
    if not expected:
        raise HTTPException(503, "GATEWAY_INTERNAL_API_KEY is not configured on this server")
    if not x_internal_key or not secrets_module.compare_digest(x_internal_key.encode(), expected.encode()):
        raise HTTPException(403, "Invalid internal key")


# ── Admin CRUD ───────────────────────────────────────────────────────────────

@router.get("/credentials", response_model=List[GatewayCredentialOut])
def list_gateway_credentials(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    tid = current_user["tenant_id"]
    creds = (
        db.query(GatewayCredential)
        .filter(GatewayCredential.tenant_id == tid)
        .order_by(GatewayCredential.created_at.desc())
        .all()
    )
    return [_out(c) for c in creds]


@router.get("/credentials/{cred_id}", response_model=GatewayCredentialOut)
def get_gateway_credential(
    cred_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    return _out(_get_owned(cred_id, current_user["tenant_id"], db))


@router.post("/credentials", response_model=GatewayCredentialOut, status_code=201)
def create_gateway_credential(
    body: GatewayCredentialCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    tid = current_user["tenant_id"]

    ds = db.query(DataSource).filter(
        DataSource.id == body.data_source_id, DataSource.tenant_id == tid,
    ).first()
    if not ds:
        raise HTTPException(404, "Data source not found")

    if db.query(GatewayCredential).filter(
        GatewayCredential.gateway_username == body.gateway_username
    ).first():
        raise HTTPException(400, f"Gateway username '{body.gateway_username}' already in use")

    if body.user_id is not None:
        user = db.query(User).filter(User.id == body.user_id, User.tenant_id == tid).first()
        if not user:
            raise HTTPException(404, "User not found")
    elif not body.role_override:
        raise HTTPException(400, "role_override is required when user_id is not set")

    if body.department_id_override is not None:
        dept = db.query(Department).filter(
            Department.id == body.department_id_override, Department.tenant_id == tid,
        ).first()
        if not dept:
            raise HTTPException(404, "Department not found")

    secret = _generate_secret()
    cred = GatewayCredential(
        tenant_id=tid,
        data_source_id=body.data_source_id,
        user_id=body.user_id,
        gateway_username=body.gateway_username,
        secret_hash=hash_password(secret),
        display_name=body.display_name,
        role_override=body.role_override,
        department_id_override=body.department_id_override,
        region_override=body.region_override,
        status="ACTIVE",
        created_by_id=current_user.get("user_id"),
        created_at=datetime.now(timezone.utc),
        expires_at=body.expires_at,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return _out(cred, secret=secret)


@router.patch("/credentials/{cred_id}", response_model=GatewayCredentialOut)
def update_gateway_credential(
    cred_id: int,
    body: GatewayCredentialPatch,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    cred = _get_owned(cred_id, current_user["tenant_id"], db)

    if body.status is not None:
        if body.status not in _VALID_STATUSES:
            raise HTTPException(400, f"status must be one of {sorted(_VALID_STATUSES)}")
        cred.status = body.status
        if body.status == "REVOKED":
            cred.revoked_at = datetime.now(timezone.utc)
    if body.role_override is not None:
        cred.role_override = body.role_override
    if body.department_id_override is not None:
        cred.department_id_override = body.department_id_override
    if body.region_override is not None:
        cred.region_override = body.region_override
    if body.expires_at is not None:
        cred.expires_at = body.expires_at

    db.commit()
    db.refresh(cred)
    return _out(cred)


@router.post("/credentials/{cred_id}/revoke", response_model=GatewayCredentialOut)
def revoke_gateway_credential(
    cred_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    cred = _get_owned(cred_id, current_user["tenant_id"], db)
    cred.status = "REVOKED"
    cred.revoked_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(cred)
    return _out(cred)


@router.post("/credentials/{cred_id}/rotate-secret", response_model=GatewayCredentialOut)
def rotate_gateway_credential(
    cred_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    cred = _get_owned(cred_id, current_user["tenant_id"], db)
    secret = _generate_secret()
    cred.secret_hash = hash_password(secret)
    db.commit()
    db.refresh(cred)
    return _out(cred, secret=secret)


@router.delete("/credentials/{cred_id}", status_code=204)
def delete_gateway_credential(
    cred_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    cred = _get_owned(cred_id, current_user["tenant_id"], db)
    db.delete(cred)
    db.commit()


# ── Gateway-facing endpoints (called by the Go protocol adapters) ────────────

@router.post("/authenticate", response_model=AuthenticateResponse)
def authenticate(
    body: AuthenticateRequest,
    db: Session = Depends(get_db),
):
    """Called once per new client connection, mirroring the wire protocol's
    own StartupMessage + PasswordMessage split — the gateway then reuses
    credential_id for every /gateway/prepare call on that connection instead
    of resending the secret per query."""
    cred = db.query(GatewayCredential).filter(
        GatewayCredential.gateway_username == body.gateway_username
    ).first()
    if not cred or not verify_password(body.secret, cred.secret_hash):
        raise HTTPException(401, f'password authentication failed for user "{body.gateway_username}"')
    _check_active(cred)

    cred.last_used_at = datetime.now(timezone.utc)
    db.commit()

    return AuthenticateResponse(
        credential_id=cred.id,
        data_source_id=cred.data_source_id,
        role=_effective_user(cred)["role"],
    )


@router.post("/prepare", response_model=PrepareResponse)
def prepare_query(
    body: GatewayPrepareRequest,
    db: Session = Depends(get_db),
):
    cred = db.get(GatewayCredential, body.credential_id)
    if not cred:
        raise HTTPException(401, "Unknown credential_id")
    _check_active(cred)  # re-checked fresh on every query — a revocation mid-connection takes effect immediately

    effective_user = _effective_user(cred)
    return prepare_query_decision(db, cred.tenant_id, effective_user, cred.data_source_id, body.query)


@router.post("/audit")
def report_audit(
    body: GatewayAuditReport,
    db: Session = Depends(get_db),
):
    cred = db.get(GatewayCredential, body.credential_id)
    if not cred:
        raise HTTPException(401, "Unknown credential_id")

    effective_user = _effective_user(cred)
    AuditService(db, cred.tenant_id).log({
        "user_email": effective_user["sub"],
        "role": effective_user["role"],
        "resource": body.resource,
        "action": body.action,
        "original_query": body.original_query,
        "rewritten_query": body.rewritten_query,
        "policy_applied": body.policy_applied,
        "row_count": body.row_count,
    })
    db.commit()
    return {"ok": True}


# ── Internal-only: backend connection credentials ─────────────────────────────

@router.get("/backend-credentials", response_model=BackendCredentialsResponse)
def backend_credentials(
    source_id: int = Query(...),
    x_internal_key: Optional[str] = Header(None, alias="X-Internal-Key"),
    db: Session = Depends(get_db),
):
    """Resolves the REAL DataSource connection info (including the plaintext
    password) the gateway needs to open its own backend connection. This
    endpoint must NEVER be reachable from anywhere but the gateway process's
    own host/network segment — see DEPLOYMENT.md. Same Vault/encrypted_config
    precedence pam_jit.py's _resolve_connection already uses."""
    _check_internal_key(x_internal_key)

    from app.core.encryption import aes_cipher

    ds = db.query(DataSource).filter(DataSource.id == source_id).first()
    if not ds:
        raise HTTPException(404, f"DataSource {source_id} not found")

    cfg = {}
    if ds.vault_path:
        from app.core.vault_client import fetch_from_vault
        cfg = fetch_from_vault(ds.vault_path) or {}
    if not cfg:
        cfg = {k: aes_cipher.decrypt(v) for k, v in (ds.encrypted_config or {}).items()}

    def _cfg(*keys: str, default: str = "") -> str:
        for k in keys:
            if k in cfg and cfg[k] is not None and str(cfg[k]).strip():
                return str(cfg[k]).strip()
        return default

    port_raw = _cfg("port")
    return BackendCredentialsResponse(
        db_type=ds.type.lower().split("+")[0],
        host=_cfg("host", "hostPort", default="localhost"),
        port=int(port_raw) if port_raw else None,
        username=_cfg("username", "user"),
        password=_cfg("password"),
        database=_cfg("database", "dbname", "catalog"),
    )
