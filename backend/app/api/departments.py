from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from pydantic import BaseModel

from app.core.deps import get_db, get_current_user
from app.models.models import DepartmentManagement, Department, Table
from app.services.governance_audit import record_data_change, record_privileged_activity

router = APIRouter()

class DeptManagementRequest(BaseModel):
    department_id: int
    source_name: str
    database_name: str
    tables: List[Dict[str, Any]] # [{"id": 1, "name": "table_name"}, ...]

class DeptManagementResponse(BaseModel):
    id: int
    department_id: int
    department_name: str
    source_name: str
    database_name: str
    tables: List[Dict[str, Any]]

@router.post("/manage", status_code=status.HTTP_201_CREATED)
def manage_department_tables(
    req: DeptManagementRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user)
):
    """Assign multiple tables to a department in a SINGLE record."""
    dept = db.query(Department).filter(
        Department.id == req.department_id, 
        Department.tenant_id == user["tenant_id"]
    ).first()
    
    if not dept:
        raise HTTPException(status_code=404, detail="Department not found")

    # ── Synchronize individual Table objects ──
    table_ids = [t["id"] for t in req.tables]
    db.query(Table).filter(
        Table.id.in_(table_ids),
        Table.tenant_id == user["tenant_id"]
    ).update({"department_id": dept.id}, synchronize_session=False)

    # Check if a record already exists for this dept + source + db
    existing = db.query(DepartmentManagement).filter(
        DepartmentManagement.department_id == dept.id,
        DepartmentManagement.source_name == req.source_name,
        DepartmentManagement.database_name == req.database_name,
        DepartmentManagement.tenant_id == user["tenant_id"]
    ).first()

    if existing:
        # Update existing record (merge tables)
        current_tables = list(existing.tables)
        current_ids = {t["id"] for t in current_tables}
        for new_t in req.tables:
            if new_t["id"] not in current_ids:
                current_tables.append(new_t)
        existing.tables = current_tables
    else:
        # Create new record
        new_entry = DepartmentManagement(
            department_id=dept.id,
            source_name=req.source_name,
            database_name=req.database_name,
            tables=req.tables,
            tenant_id=user["tenant_id"]
        )
        db.add(new_entry)

    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="DepartmentManagement",
        entity_id=str(dept.id),
        table_name="department_management",
        record_pk=str(dept.id),
        column_name="tables",
        old_value=None,
        new_value=req.tables,
        operation_type="UPDATE" if existing else "CREATE",
        details={"department_name": dept.name, "source_name": req.source_name, "database_name": req.database_name},
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="assign_department_tables",
        target_type="Department",
        target_id=str(dept.id),
        description=f"Assigned {len(req.tables)} table(s) to department {dept.name}",
        risk_level="MEDIUM",
        details={"table_ids": table_ids},
    )
    db.commit()
    return {"message": "Department management updated and tables synchronized"}

@router.get("/manage", response_model=List[DeptManagementResponse])
def list_managed_resources(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user)
):
    """Fetch all records grouped by department/source/db."""
    items = (
        db.query(DepartmentManagement)
        .join(Department)
        .filter(DepartmentManagement.tenant_id == user["tenant_id"])
        .all()
    )
    
    return [
        DeptManagementResponse(
            id=item.id,
            department_id=item.department_id,
            department_name=item.department.name,
            source_name=item.source_name,
            database_name=item.database_name,
            tables=item.tables
        ) for item in items
    ]

@router.delete("/manage/{item_id}")
def remove_managed_resource(
    item_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user)
):
    """Delete a record from the department_management table."""
    item = db.query(DepartmentManagement).filter(
        DepartmentManagement.id == item_id,
        DepartmentManagement.tenant_id == user["tenant_id"]
    ).first()
    
    if not item:
        raise HTTPException(status_code=404, detail="Managed resource not found")
    
    # ── Clear individual Table assignments ──
    table_ids = [t["id"] for t in (item.tables or [])]
    db.query(Table).filter(
        Table.id.in_(table_ids),
        Table.tenant_id == user["tenant_id"]
    ).update({"department_id": None}, synchronize_session=False)

    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="DepartmentManagement",
        entity_id=str(item.id),
        table_name="department_management",
        record_pk=str(item.id),
        column_name="tables",
        old_value=item.tables,
        new_value=None,
        operation_type="DELETE",
        details={"department_id": item.department_id, "source_name": item.source_name, "database_name": item.database_name},
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="unassign_department_tables",
        target_type="Department",
        target_id=str(item.department_id),
        description=f"Removed managed resource {item.source_name}/{item.database_name} ({len(table_ids)} table(s) unassigned)",
        risk_level="MEDIUM",
        details={"table_ids": table_ids},
    )
    db.delete(item)
    db.commit()
    return {"message": "Resource removed from management and tables unassigned"}
