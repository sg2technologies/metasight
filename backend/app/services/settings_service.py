"""
SystemSettings service — loads, merges, and caches per-tenant settings.
"""
from __future__ import annotations

import copy
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import SystemSettings

# ── Default configuration ──────────────────────────────────────────────────────

DEFAULT_SETTINGS: dict[str, Any] = {
    "branding": {
        "platform_name": "MetaSight",
        "tagline": "Database Governance Platform",
        "logo_url": None,         # URL or null (uses built-in SVG)
        "primary_color": "#818CF8",
        "accent_color": "#38BDF8",
        "support_email": None,
        "docs_url": None,
    },
    "security": {
        "session_timeout_minutes": 1440,         # 24 h
        "max_login_attempts": 5,                 # before lockout
        "lockout_duration_minutes": 30,
        "ip_allowlist": [],                       # [] = allow all
        "require_mfa": False,
        "password_min_length": 8,
        "password_require_uppercase": True,
        "password_require_number": True,
        "password_require_special": False,
        "jwt_expire_minutes": 1440,
    },
    "query_gateway": {
        "max_rows_per_query": 10_000,
        "default_limit": 1_000,
        "rate_limit_per_minute": 30,
        "risk_threshold_medium": 20,
        "risk_threshold_high": 50,
        "risk_threshold_critical": 80,
        "approval_ttl_hours": 24,
        "allow_ddl": False,
        "allow_dml": False,
        "require_table_policy": False,           # deny queries with no policy when True
    },
    "masking": {
        "global_masking_enabled": True,
        "role_levels": {
            "admin":    "raw",
            "manager":  "partial",
            "analyst":  "full",
            "viewer":   "full",
        },
        "partial_mask_char": "*",
        "partial_visible_chars": 4,
    },
    "audit": {
        "retention_days": 365,
        "log_successful_queries": True,
        "log_denied_queries": True,
        "log_policy_changes": True,
        "log_login_events": True,
    },
    "notifications": {
        "smtp_host": None,
        "smtp_port": 587,
        "smtp_user": None,
        "smtp_password": None,        # stored encrypted at rest
        "smtp_from": None,
        "smtp_tls": True,
        "alert_on_critical_risk": False,
        "alert_on_approval_request": True,
        "alert_emails": [],
        "slack_webhook_url": None,
        "teams_webhook_url": None,
        "generic_webhook_url": None,   # structured JSON, any SIEM ingestion endpoint
    },
    "sso": {
        "enabled": False,
        "provider_name": "SSO",          # shown on the "Continue with ..." login button
        "issuer_url": None,               # OIDC issuer — discovery doc at {issuer_url}/.well-known/openid-configuration
        "client_id": None,
        "client_secret": None,            # stored encrypted at rest, redacted on read (see app/api/settings.py)
        "redirect_uri": None,             # e.g. https://metasight.example.com/auth/sso/callback
        "scopes": ["openid", "email", "profile"],
        # Where to send the browser after a successful login, e.g.
        # https://metasight.example.com (no path). Only needed when the
        # frontend isn't served from the same origin as redirect_uri above
        # (e.g. separate dev ports) — defaults to redirect_uri's own origin.
        "frontend_redirect_url": None,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (non-destructive)."""
    result = copy.deepcopy(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def get_settings(tenant_id: int, db: Session) -> dict:
    """Return merged settings (defaults + tenant overrides) for a tenant."""
    row = db.query(SystemSettings).filter(SystemSettings.tenant_id == tenant_id).first()
    if row is None or not row.config:
        return copy.deepcopy(DEFAULT_SETTINGS)
    return _deep_merge(DEFAULT_SETTINGS, row.config)


def update_settings(tenant_id: int, patch: dict, updated_by: str, db: Session) -> dict:
    """
    Merge patch into existing tenant overrides and persist.
    Only stores the delta (overrides), not the full merged config.
    Returns the fully merged config.
    """
    row = db.query(SystemSettings).filter(SystemSettings.tenant_id == tenant_id).first()
    existing_overrides = row.config if (row and row.config) else {}
    new_overrides = _deep_merge(existing_overrides, patch)

    if row is None:
        row = SystemSettings(tenant_id=tenant_id, config=new_overrides, updated_by=updated_by)
        db.add(row)
    else:
        row.config = new_overrides
        row.updated_by = updated_by

    db.commit()
    db.refresh(row)
    return _deep_merge(DEFAULT_SETTINGS, row.config)


def get_public_settings(tenant_id: int, db: Session) -> dict:
    """Subset of settings safe to expose without authentication."""
    cfg = get_settings(tenant_id, db)
    branding = cfg.get("branding", {})
    return {
        "platform_name": branding.get("platform_name", "MetaSight"),
        "tagline":        branding.get("tagline", "Database Governance Platform"),
        "logo_url":       branding.get("logo_url"),
        "primary_color":  branding.get("primary_color", "#818CF8"),
        "accent_color":   branding.get("accent_color", "#38BDF8"),
        "support_email":  branding.get("support_email"),
        "docs_url":       branding.get("docs_url"),
        # password hints (no sensitive values)
        "password_min_length":         cfg["security"]["password_min_length"],
        "password_require_uppercase":  cfg["security"]["password_require_uppercase"],
        "password_require_number":     cfg["security"]["password_require_number"],
        "password_require_special":    cfg["security"]["password_require_special"],
        # SSO — enough for the login page to show/hide a "Continue with ..."
        # button; never client_id/client_secret/issuer_url here.
        "sso_enabled":       cfg["sso"]["enabled"],
        "sso_provider_name": cfg["sso"]["provider_name"],
    }
