"""
OIDC SSO — GET /auth/sso/login (redirect to the configured IdP) and
GET /auth/sso/callback (exchange code, validate ID token, upsert User, mint
a real MetaSight access token).

Deliberately stateless — no server-side session/cookie store (this app is
otherwise pure JWT/localStorage, see app/core/deps.py). The OAuth2 `state`
parameter round-trips through the IdP unchanged, so it's used to carry a
short-lived *signed* token (via the same create_access_token/
decode_access_token machinery as everything else) containing the nonce —
verifying its signature at the callback is what proves it wasn't tampered
with, standing in for a server-side session.

Uses httpx (already a dependency) for OIDC discovery/token-exchange/JWKS
fetch, and joserfc (an Authlib dependency, the modern replacement for the
deprecated authlib.jose) for ID token signature verification — the
crypto-sensitive part uses a mature library; the claim validation (iss/aud/
nonce/exp) around it is thin glue, the same "mature library for the hard
part" principle the Postgres/MySQL gateway wire-protocol code follows.
"""
from __future__ import annotations

import secrets
import time
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from joserfc import jwt as jose_jwt
from joserfc.jwk import KeySet
from sqlalchemy.orm import Session

from app.core.deps import get_db
from app.core.jwt import create_access_token, decode_access_token
from app.core.security import hash_password
from app.models.models import Tenant, User, UserRole
from app.services.settings_service import get_settings

router = APIRouter()

_STATE_EXPIRE_MINUTES = 10


def _sso_config(db: Session) -> dict[str, Any]:
    """Community is single-tenant — look up that one tenant's row rather
    than hardcode id=1, in case a restored/migrated DB ever has a different id."""
    tenant = db.query(Tenant).order_by(Tenant.id.asc()).first()
    if not tenant:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No tenant configured")
    cfg = get_settings(tenant.id, db).get("sso", {})
    if not cfg.get("enabled"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not enabled")
    for field in ("issuer_url", "client_id", "client_secret", "redirect_uri"):
        if not cfg.get(field):
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"SSO is enabled but '{field}' is not configured")
    cfg["_tenant_id"] = tenant.id
    return cfg


def _discover(issuer_url: str) -> dict[str, Any]:
    try:
        resp = httpx.get(f"{issuer_url.rstrip('/')}/.well-known/openid-configuration", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"OIDC discovery failed: {exc}")


@router.get("/login")
def sso_login(db: Session = Depends(get_db)):
    cfg = _sso_config(db)
    discovery = _discover(cfg["issuer_url"])

    nonce = secrets.token_urlsafe(24)
    state = create_access_token({"nonce": nonce, "sso": True}, expires_delta=timedelta(minutes=_STATE_EXPIRE_MINUTES))

    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "scope": " ".join(cfg.get("scopes") or ["openid", "email", "profile"]),
        "state": state,
        "nonce": nonce,
    }
    return RedirectResponse(f"{discovery['authorization_endpoint']}?{urlencode(params)}")


@router.get("/callback")
def sso_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db),
):
    cfg = _sso_config(db)
    discovery = _discover(cfg["issuer_url"])

    try:
        state_claims = decode_access_token(state)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired SSO state")
    if not state_claims.get("sso"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid SSO state")
    nonce = state_claims["nonce"]

    try:
        token_resp = httpx.post(discovery["token_endpoint"], data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg["redirect_uri"],
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
        }, timeout=10)
        token_resp.raise_for_status()
        tokens = token_resp.json()
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"SSO token exchange failed: {exc}")

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "IdP did not return an id_token")

    try:
        jwks_resp = httpx.get(discovery["jwks_uri"], timeout=10)
        jwks_resp.raise_for_status()
        key_set = KeySet.import_key_set(jwks_resp.json())
        decoded = jose_jwt.decode(id_token, key_set)
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid SSO id_token: {exc}")

    claims = decoded.claims
    aud = claims.get("aud")
    aud_ok = cfg["client_id"] in aud if isinstance(aud, list) else aud == cfg["client_id"]
    if claims.get("iss") != discovery.get("issuer", cfg["issuer_url"]) or not aud_ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SSO id_token issuer/audience mismatch")
    if claims.get("nonce") != nonce:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SSO id_token nonce mismatch")
    if claims.get("exp", 0) < time.time():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SSO id_token expired")

    subject = claims.get("sub")
    email = claims.get("email")
    if not subject:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SSO id_token missing 'sub' claim")

    user = db.query(User).filter(
        User.sso_issuer == cfg["issuer_url"], User.sso_subject == subject,
    ).first()
    if not user and email:
        # First-time SSO login for an account that already exists via
        # password login — link it rather than creating a duplicate.
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.sso_issuer = cfg["issuer_url"]
            user.sso_subject = subject
    if not user:
        if not email:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SSO id_token missing 'email' claim, required to auto-provision a new user")
        # Auto-provisioned users default to the least-privileged role —
        # never trust an IdP claim to grant admin; an existing admin
        # promotes manually via Users.tsx if that's warranted.
        user = User(
            email=email,
            hashed_password=hash_password(secrets.token_urlsafe(32)),  # random, never used to log in
            role=UserRole.analyst,
            tenant_id=cfg["_tenant_id"],
            sso_issuer=cfg["issuer_url"],
            sso_subject=subject,
        )
        db.add(user)
    db.commit()
    db.refresh(user)

    from app.api.auth import _issue_token
    access_token = _issue_token(user, db)

    redirect_base = cfg.get("frontend_redirect_url")
    if not redirect_base:
        parsed = urlparse(cfg["redirect_uri"])
        redirect_base = f"{parsed.scheme}://{parsed.netloc}"
    return RedirectResponse(f"{redirect_base}/sso/callback#token={access_token}")
