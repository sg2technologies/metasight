"""
Query approval workflow.

Flow:
  1. POST /query/execute → risk=CRITICAL → 403 + approval_request_id
  2. GET  /approvals                      → list pending (admin)
  3. POST /approvals/{id}/approve         → approve (admin), returns approval_token
  4. POST /approvals/{id}/reject          → reject (admin)
  5. POST /query/execute with approval_token field → executes (any user)
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List

from app.core.deps import get_db, get_current_user, require_admin
from app.models.models import QueryApproval
from app.services.governance_audit import record_data_change, record_privileged_activity

logger = logging.getLogger(__name__)
router = APIRouter()

_APPROVAL_TTL_HOURS = 24


# ── Schemas ───────────────────────────────────────────────────────────────────

class ApprovalResponse(BaseModel):
    id: int
    requester_email: str
    requester_role: str
    source_id: int
    sql: str
    risk_score: float
    risk_level: str
    status: str
    approver_email: Optional[str]
    approver_note: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    approval_token: Optional[str]  # only visible to requester after approval


class ApproveRequest(BaseModel):
    note: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=List[ApprovalResponse])
def list_approvals(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """List approval requests (admin only). Filter by status=pending|approved|rejected."""
    q = db.query(QueryApproval).filter(QueryApproval.tenant_id == user["tenant_id"])
    if status:
        q = q.filter(QueryApproval.status == status)
    approvals = q.order_by(QueryApproval.created_at.desc()).limit(200).all()
    return [_to_response(a, include_token=True) for a in approvals]


@router.get("/mine", response_model=List[ApprovalResponse])
def list_my_approvals(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """List the current user's own approval requests."""
    approvals = (
        db.query(QueryApproval)
        .filter(
            QueryApproval.tenant_id == user["tenant_id"],
            QueryApproval.requester_email == user.get("sub", ""),
        )
        .order_by(QueryApproval.created_at.desc())
        .limit(100)
        .all()
    )
    return [_to_response(a, include_token=(a.status == "approved")) for a in approvals]


@router.post("/{approval_id}/approve", response_model=ApprovalResponse)
def approve_request(
    approval_id: int,
    body: ApproveRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """Approve a pending query request (admin only)."""
    approval = _get_approval(approval_id, user["tenant_id"], db)

    if approval.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {approval.status}.")

    if approval.requester_email == user.get("sub", ""):
        raise HTTPException(status_code=403, detail="You cannot approve your own request.")

    old_status = approval.status
    approval.status = "approved"
    approval.approver_email = user.get("sub", "")
    approval.approver_note = body.note
    approval.approval_token = secrets.token_urlsafe(32)
    approval.expires_at = datetime.now(timezone.utc) + timedelta(hours=_APPROVAL_TTL_HOURS)
    approval.updated_at = datetime.now(timezone.utc)

    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="QueryApproval",
        entity_id=str(approval.id),
        table_name="query_approvals",
        record_pk=str(approval.id),
        column_name="status",
        old_value=old_status,
        new_value="approved",
        operation_type="UPDATE",
        approval_status="approved",
        approval_id=approval.id,
        details={"requester_email": approval.requester_email, "note": body.note},
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="approve_query_request",
        target_type="QueryApproval",
        target_id=str(approval.id),
        description=f"Approved query request {approval.id} from {approval.requester_email}",
        risk_level="HIGH",
    )
    db.commit()
    db.refresh(approval)
    logger.info(
        "Approvals: approved request %d by %s", approval_id, user.get("sub", "")
    )
    return _to_response(approval, include_token=True)


@router.post("/{approval_id}/reject", response_model=ApprovalResponse)
def reject_request(
    approval_id: int,
    body: ApproveRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """Reject a pending query request (admin only)."""
    approval = _get_approval(approval_id, user["tenant_id"], db)

    if approval.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {approval.status}.")

    if approval.requester_email == user.get("sub", ""):
        raise HTTPException(status_code=403, detail="You cannot reject your own request.")

    old_status = approval.status
    approval.status = "rejected"
    approval.approver_email = user.get("sub", "")
    approval.approver_note = body.note
    approval.updated_at = datetime.now(timezone.utc)

    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="QueryApproval",
        entity_id=str(approval.id),
        table_name="query_approvals",
        record_pk=str(approval.id),
        column_name="status",
        old_value=old_status,
        new_value="rejected",
        operation_type="UPDATE",
        approval_status="rejected",
        approval_id=approval.id,
        details={"requester_email": approval.requester_email, "note": body.note},
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="reject_query_request",
        target_type="QueryApproval",
        target_id=str(approval.id),
        description=f"Rejected query request {approval.id} from {approval.requester_email}",
        risk_level="HIGH",
    )
    db.commit()
    db.refresh(approval)
    logger.info(
        "Approvals: rejected request %d by %s", approval_id, user.get("sub", "")
    )
    return _to_response(approval, include_token=False)


# ── Internal helpers (used by query.py) ──────────────────────────────────────

def create_approval_request(
    db: Session,
    tenant_id: int,
    user: dict,
    source_id: int,
    sql: str,
    risk_score: float,
    risk_level: str,
) -> QueryApproval:
    """Create and persist an approval request. Called when risk=CRITICAL."""
    approval = QueryApproval(
        tenant_id=tenant_id,
        requester_email=user.get("sub", ""),
        requester_role=user.get("role", ""),
        source_id=source_id,
        sql=sql,
        risk_score=int(risk_score),
        risk_level=risk_level,
        status="pending",
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    logger.info(
        "Approvals: created request %d (risk=%s score=%.1f) by %s",
        approval.id, risk_level, risk_score, user.get("sub", "")
    )
    return approval


def validate_approval_token(
    db: Session,
    tenant_id: int,
    sql: str,
    token: str,
) -> QueryApproval:
    """
    Validate an approval token and mark it as used.
    Raises HTTPException on invalid/expired/used token.
    """
    approval = (
        db.query(QueryApproval)
        .filter(
            QueryApproval.tenant_id == tenant_id,
            QueryApproval.approval_token == token,
            QueryApproval.status == "approved",
        )
        .first()
    )
    if not approval:
        raise HTTPException(status_code=403, detail="Invalid or already-used approval token.")

    # Check expiry
    if approval.expires_at and approval.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Approval token has expired.")

    # Check SQL matches (prevent token reuse for different queries)
    if approval.sql.strip() != sql.strip():
        raise HTTPException(
            status_code=403,
            detail="Approval token was issued for a different SQL query.",
        )

    approval.status = "used"
    approval.updated_at = datetime.now(timezone.utc)
    db.commit()
    return approval


# ── Private ───────────────────────────────────────────────────────────────────

def _get_approval(approval_id: int, tenant_id: int, db: Session) -> QueryApproval:
    approval = (
        db.query(QueryApproval)
        .filter(QueryApproval.id == approval_id, QueryApproval.tenant_id == tenant_id)
        .first()
    )
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    return approval


def _to_response(approval: QueryApproval, include_token: bool = False) -> ApprovalResponse:
    return ApprovalResponse(
        id=approval.id,
        requester_email=approval.requester_email,
        requester_role=approval.requester_role,
        source_id=approval.source_id,
        sql=approval.sql,
        risk_score=approval.risk_score,
        risk_level=approval.risk_level,
        status=approval.status,
        approver_email=approval.approver_email,
        approver_note=approval.approver_note,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        approval_token=approval.approval_token if include_token else None,
    )
