from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.deps import get_db, require_superadmin
from app.models.models import Tenant, User, UserRole
from app.core.security import hash_password
from app.services.governance_audit import record_data_change, record_privileged_activity

router = APIRouter()

class TenantCreationRequest(BaseModel):
    tenant_name: str
    admin_email: str
    admin_password: str

class TenantResponse(BaseModel):
    id: int
    name: str
    created_at: datetime
    admin_count: int
    user_count: int

@router.get("/tenants")
def get_all_tenants(
    db: Session = Depends(get_db),
    user: dict = Depends(require_superadmin)
):
    tenants = db.query(Tenant).all()
    results = []
    for t in tenants:
        admin_count = sum(1 for u in t.users if u.role == UserRole.admin)
        user_count = len(t.users)
        users = [{"id": u.id, "email": u.email, "role": u.role.value} for u in t.users]
        results.append({
            "id": t.id,
            "name": t.name,
            "created_at": t.created_at,
            "admin_count": admin_count,
            "user_count": user_count,
            "users": users
        })
    return {"items": results}

@router.post("/tenants", status_code=status.HTTP_201_CREATED)
def create_tenant(
    payload: TenantCreationRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_superadmin)
):
    existing_tenant = db.query(Tenant).filter(Tenant.name == payload.tenant_name).first()
    if existing_tenant:
        raise HTTPException(status_code=409, detail="Tenant name already exists")
    
    existing_user = db.query(User).filter(User.email == payload.admin_email.lower().strip()).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Admin email already exists globally")

    tenant = Tenant(name=payload.tenant_name)
    db.add(tenant)
    db.flush() # get tenant ID

    admin_user = User(
        email=payload.admin_email.lower().strip(),
        hashed_password=hash_password(payload.admin_password),
        role=UserRole.admin,
        tenant_id=tenant.id
    )
    db.add(admin_user)
    db.flush()
    record_data_change(
        db,
        tenant_id=tenant.id,
        user=user,
        entity="Tenant",
        entity_id=str(tenant.id),
        table_name="tenants",
        record_pk=str(tenant.id),
        column_name="*",
        old_value=None,
        new_value={"name": tenant.name, "admin_email": admin_user.email},
        operation_type="CREATE",
    )
    record_privileged_activity(
        db,
        tenant_id=tenant.id,
        user=user,
        action="create_tenant",
        target_type="Tenant",
        target_id=str(tenant.id),
        description=f"Superadmin created tenant {tenant.name} with admin {admin_user.email}",
        risk_level="HIGH",
    )
    db.commit()

    return {"message": "Tenant correctly created successfully", "tenant_id": tenant.id}
