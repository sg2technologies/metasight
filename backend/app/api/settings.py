"""
System Settings API
  GET  /settings/public          — unauthenticated, branding + password hints
  GET  /settings                 — authenticated, full settings for current tenant
  PUT  /settings                 — admin only, patch settings
  POST /settings/reset           — admin only, reset to defaults
  GET  /settings/smtp/test       — admin only, send a test email
  GET  /settings/vault/status    — admin only, HashiCorp Vault configured/reachable
"""
from __future__ import annotations

import smtplib
from email.mime.text import MIMEText
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_user, require_admin
from app.models.models import SystemSettings
from app.services.settings_service import (
    get_settings,
    get_public_settings,
    update_settings,
    DEFAULT_SETTINGS,
)
from app.services.governance_audit import record_data_change, record_privileged_activity

router = APIRouter()


@router.get("/vault/status")
def vault_status(current_user: dict = Depends(require_admin)):
    """
    Returns whether HashiCorp Vault is configured and reachable.

    Vault is a Community-wide credential-storage option (see
    app/core/vault_client.py, used by DataSource credential resolution and
    by native DAM polling) — not PAM-specific, so this lives here rather than
    under any Enterprise router, even though PAM JIT is the other consumer.
    """
    from app.core.config import settings
    configured = bool(settings.VAULT_ADDR and settings.VAULT_TOKEN)
    reachable = False
    if configured:
        try:
            import hvac
            client = hvac.Client(url=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)
            reachable = client.is_authenticated()
        except Exception:
            pass
    return {
        "configured": configured,
        "reachable": reachable,
        "vault_addr": settings.VAULT_ADDR or "",
    }


def _redact_patch(patch: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy a settings patch, redacting secret fields before audit logging."""
    import copy

    safe = copy.deepcopy(patch)
    if safe.get("notifications", {}).get("smtp_password"):
        safe["notifications"]["smtp_password"] = "••••••••"
    return safe


# ── Public (no auth) ──────────────────────────────────────────────────────────

@router.get("/public")
def public_settings(
    tenant_id: int = Query(1, description="Tenant ID (defaults to 1 for single-tenant deploys)"),
    db: Session = Depends(get_db),
):
    """Branding + password policy — served to the login page without auth."""
    return get_public_settings(tenant_id, db)


# ── Authenticated ─────────────────────────────────────────────────────────────

@router.get("")
def read_settings(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Full settings for the current tenant. Sensitive notification passwords are redacted."""
    cfg = get_settings(user["tenant_id"], db)
    # Redact SMTP password
    if cfg.get("notifications", {}).get("smtp_password"):
        cfg["notifications"]["smtp_password"] = "••••••••"
    return cfg


@router.put("")
def write_settings(
    patch: dict[str, Any],
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Deep-merge patch into tenant settings.
    Only changed keys need to be provided.
    Returns the fully-merged result (smtp_password redacted).
    """
    # Prevent overwriting smtp_password with the redacted placeholder
    notif = patch.get("notifications", {})
    if notif.get("smtp_password") == "••••••••":
        del patch["notifications"]["smtp_password"]

    old_cfg = get_settings(user["tenant_id"], db)
    cfg = update_settings(user["tenant_id"], patch, user["sub"], db)

    safe_patch = _redact_patch(patch)
    record_data_change(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        entity="SystemSettings",
        entity_id=str(user["tenant_id"]),
        table_name="system_settings",
        record_pk=str(user["tenant_id"]),
        column_name=",".join(patch.keys()),
        old_value={k: old_cfg.get(k) for k in patch.keys()},
        new_value=safe_patch,
        operation_type="UPDATE",
    )
    record_privileged_activity(
        db,
        tenant_id=user["tenant_id"],
        user=user,
        action="update_settings",
        target_type="SystemSettings",
        target_id=str(user["tenant_id"]),
        description=f"Updated settings sections: {', '.join(patch.keys())}",
        risk_level="MEDIUM",
    )
    db.commit()

    if cfg.get("notifications", {}).get("smtp_password"):
        cfg["notifications"]["smtp_password"] = "••••••••"
    return cfg


@router.post("/reset", status_code=status.HTTP_200_OK)
def reset_settings(
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Reset tenant settings to platform defaults."""
    row = db.query(SystemSettings).filter(
        SystemSettings.tenant_id == user["tenant_id"]
    ).first()
    if row:
        old_config = row.config
        row.config = {}
        row.updated_by = user["sub"]
        record_data_change(
            db,
            tenant_id=user["tenant_id"],
            user=user,
            entity="SystemSettings",
            entity_id=str(user["tenant_id"]),
            table_name="system_settings",
            record_pk=str(user["tenant_id"]),
            column_name="*",
            old_value=_redact_patch(old_config or {}),
            new_value={},
            operation_type="UPDATE",
        )
        record_privileged_activity(
            db,
            tenant_id=user["tenant_id"],
            user=user,
            action="reset_settings",
            target_type="SystemSettings",
            target_id=str(user["tenant_id"]),
            description="Reset tenant settings to platform defaults",
            risk_level="HIGH",
        )
        db.commit()
    return {"detail": "Settings reset to defaults.", "config": DEFAULT_SETTINGS}


@router.post("/smtp/test", status_code=status.HTTP_200_OK)
def test_smtp(
    user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Send a test email using the current SMTP configuration."""
    cfg = get_settings(user["tenant_id"], db)
    notif = cfg.get("notifications", {})

    host = notif.get("smtp_host")
    port = notif.get("smtp_port", 587)
    smtp_user = notif.get("smtp_user")
    smtp_pass = notif.get("smtp_password")
    from_addr = notif.get("smtp_from") or smtp_user
    tls = notif.get("smtp_tls", True)
    recipients = notif.get("alert_emails", [])

    if not host:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SMTP host is not configured. Update settings first.",
        )
    if not recipients:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No alert_emails configured.",
        )

    msg = MIMEText(
        "This is a test email from MetaSight Data Governance Platform.\n"
        "SMTP configuration is working correctly."
    )
    msg["Subject"] = "MetaSight — SMTP Test"
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)

    try:
        if tls:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(from_addr, recipients, msg.as_string())
        server.quit()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SMTP error: {exc}",
        )

    return {"detail": f"Test email sent to {recipients}."}
