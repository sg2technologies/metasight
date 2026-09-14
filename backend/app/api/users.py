from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_user, require_admin
from app.core.security import hash_password
from app.models.models import User, UserRole
from app.schemas.schemas import UserCreate, UserResponse
from app.services.governance_audit import record_data_change, record_privileged_activity

router = APIRouter()


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists.",
        )

    try:
        role = UserRole(payload.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{payload.role}'. Must be 'admin' or 'analyst'.",
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=role,
        tenant_id=admin["tenant_id"],
        department_id=payload.department_id,
    )
    db.add(user)
    db.flush()
    record_data_change(
        db,
        tenant_id=admin["tenant_id"],
        user=admin,
        entity="User",
        entity_id=str(user.id),
        table_name="users",
        record_pk=str(user.id),
        column_name="*",
        old_value=None,
        new_value={"email": user.email, "role": role.value, "department_id": user.department_id},
        operation_type="CREATE",
    )
    record_privileged_activity(
        db,
        tenant_id=admin["tenant_id"],
        user=admin,
        action="create_user",
        target_type="User",
        target_id=str(user.id),
        description=f"Created user {user.email} with role {role.value}",
        risk_level="HIGH",
    )
    db.commit()
    db.refresh(user)
    user.role = user.role.value
    return user


@router.get("", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    users = db.query(User).filter(User.tenant_id == admin["tenant_id"]).all()
    for u in users:
        u.role = u.role.value
    return users


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    user = (
        db.query(User)
        .filter(User.id == user_id, User.tenant_id == admin["tenant_id"])
        .first()
    )
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    record_data_change(
        db,
        tenant_id=admin["tenant_id"],
        user=admin,
        entity="User",
        entity_id=str(user.id),
        table_name="users",
        record_pk=str(user.id),
        column_name="*",
        old_value={"email": user.email, "role": user.role.value, "department_id": user.department_id},
        new_value=None,
        operation_type="DELETE",
    )
    record_privileged_activity(
        db,
        tenant_id=admin["tenant_id"],
        user=admin,
        action="delete_user",
        target_type="User",
        target_id=str(user.id),
        description=f"Deleted user {user.email}",
        risk_level="HIGH",
    )
    db.delete(user)
    db.commit()
