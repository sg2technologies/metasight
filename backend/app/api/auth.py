import base64
import io
import secrets
from datetime import timedelta

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.deps import get_db, get_current_user
from app.core.security import verify_password, hash_password
from app.core.jwt import create_access_token, decode_access_token
from app.models.models import User, Tenant, UserRole, LoginAttempt
from app.schemas.schemas import (
    TokenResponse, SetupRequest, UserResponse, LoginResponse,
    MFAChallengeRequest, MFAEnrollResponse, MFAEnrollConfirmRequest, MFADisableRequest,
)
from app.services.settings_service import get_settings as _get_tenant_settings
from fastapi.security import OAuth2PasswordRequestForm
from app.core.utils import utcnow

_MFA_PENDING_EXPIRE_MINUTES = 5

router = APIRouter()
# storage_uri=Redis so the "10/minute" login limit is a real shared limit across
# all gunicorn worker processes — the slowapi default is in-memory per-process,
# which under N workers silently becomes an effective N*10/minute limit.
limiter = Limiter(key_func=get_remote_address, storage_uri=settings.REDIS_BROKER_URL)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _record_attempt(db: Session, email: str, ip: str | None, success: bool) -> None:
    db.add(LoginAttempt(
        email=email,
        ip_address=ip,
        success=1 if success else 0,
    ))
    db.commit()


def _issue_token(user: User, db: Session) -> str:
    """Mint the real access token — shared by the password-only login path
    and the post-MFA-challenge path, so both produce an identical claim
    shape (get_current_user/deps.py doesn't care how a token was issued)."""
    try:
        cfg = _get_tenant_settings(user.tenant_id, db)
        jwt_expire = cfg.get("security", {}).get("jwt_expire_minutes", settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    except Exception:
        jwt_expire = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    return create_access_token(
        {"sub": user.email, "role": user.role.value, "tenant_id": user.tenant_id,
         "user_id": user.id, "department_id": user.department_id},
        expires_delta=timedelta(minutes=jwt_expire),
    )


def _is_locked_out(db: Session, email: str, max_attempts: int, lockout_minutes: int) -> bool:
    """Return True if the account is currently locked out."""
    window_start = utcnow() - timedelta(minutes=lockout_minutes)
    # count consecutive failures since window_start (reset on success)
    recent = (
        db.query(LoginAttempt)
        .filter(
            LoginAttempt.email == email,
            LoginAttempt.attempted_at >= window_start,
        )
        .order_by(LoginAttempt.attempted_at.asc())
        .all()
    )
    # Walk backwards; count consecutive failures from the end
    consecutive = 0
    for attempt in reversed(recent):
        if attempt.success:
            break
        consecutive += 1
    return consecutive >= max_attempts


# ── Setup ─────────────────────────────────────────────────────────────────────

@router.get("/setup-status", include_in_schema=False)
def setup_status(db: Session = Depends(get_db)):
    """
    Public, unauthenticated: does any user exist yet? The frontend uses this
    to decide whether to show the one-time first-run setup screen instead of
    the login form. Deliberately returns nothing but a boolean — no tenant
    names, emails, or counts — this is reachable by anyone who can hit the
    API, same as /settings/public.
    """
    return {"needs_setup": db.query(User).first() is None}


@router.post(
    "/setup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
def setup(
    payload: SetupRequest,
    x_setup_secret: str = Header(..., alias="X-Setup-Secret"),
    db: Session = Depends(get_db),
):
    """
    One-time bootstrap: creates the first tenant and admin user.
    Requires the X-Setup-Secret header matching SETUP_SECRET in .env.
    """
    if not secrets.compare_digest(x_setup_secret.encode(), settings.SETUP_SECRET.encode()):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid setup secret")

    if db.query(User).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Setup already completed. Use POST /users to add more users.",
        )

    tenant = Tenant(name="Default Organization")
    db.add(tenant)
    db.flush()

    admin = User(
        email=payload.admin_email,
        hashed_password=hash_password(payload.admin_password),
        role=UserRole.admin,
        tenant_id=tenant.id,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    admin.role = admin.role.value
    return admin


# ── Login ─────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
@limiter.limit("10/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else None
    email = form_data.username.lower().strip()

    # ── Super Admin Intercept ───────────────────────────────────────────────
    # Constant-time comparisons (this used to be a plain `==`, a timing
    # side-channel on the break-glass super-admin password) and routed through
    # the same lockout/attempt-recording path as normal logins (this used to
    # bypass account lockout entirely, so it had no brute-force protection).
    is_super_admin_email = secrets.compare_digest(
        email.encode(), settings.SUPER_ADMIN_EMAIL.lower().encode()
    )
    if is_super_admin_email:
        if _is_locked_out(db, email, max_attempts=5, lockout_minutes=30):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account temporarily locked after too many failed attempts. Try again later.",
            )

        password_ok = secrets.compare_digest(
            form_data.password.encode(), settings.SUPER_ADMIN_PASSWORD.encode()
        )
        if not password_ok:
            _record_attempt(db, email, ip, success=False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )
        _record_attempt(db, email, ip, success=True)

        db_user = db.query(User).filter(User.email == email).first()
        if db_user:
            t_id = db_user.tenant_id
            user_id = db_user.id
            dept_id = db_user.department_id
        else:
            first_tenant = db.query(Tenant).order_by(Tenant.id.asc()).first()
            t_id = first_tenant.id if first_tenant else 0
            user_id = None
            dept_id = None

        # Break-glass path deliberately doesn't gate on MFA even if the
        # matching User row has totp_enabled — this is the account of last
        # resort; adding another failure mode to it (a lost authenticator
        # app) would defeat its purpose.
        access_token = create_access_token(
            {"sub": email, "role": "superadmin", "tenant_id": t_id, "user_id": user_id, "department_id": dept_id},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return LoginResponse(access_token=access_token, token_type="bearer")

    user = db.query(User).filter(User.email == email).first()

    # Load tenant-level security settings
    sec = {}
    if user:
        try:
            cfg = _get_tenant_settings(user.tenant_id, db)
            sec = cfg.get("security", {})
        except Exception:
            pass

    max_attempts = sec.get("max_login_attempts", 5)
    lockout_minutes = sec.get("lockout_duration_minutes", 30)
    jwt_expire = sec.get("jwt_expire_minutes", settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Lockout check
    if user and _is_locked_out(db, email, max_attempts, lockout_minutes):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Account temporarily locked after {max_attempts} failed attempts. "
                f"Try again in {lockout_minutes} minutes."
            ),
        )

    if not user or not verify_password(form_data.password, user.hashed_password):
        if user:
            _record_attempt(db, email, ip, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    _record_attempt(db, email, ip, success=True)

    if user.totp_enabled:
        # Password verified but MFA still required — issue a short-lived
        # pending token instead of a real one; the frontend must call
        # /auth/mfa/challenge with it plus a TOTP code before getting a
        # token deps.get_current_user will actually accept for anything else.
        mfa_token = create_access_token(
            {"sub": user.email, "user_id": user.id, "mfa_pending": True},
            expires_delta=timedelta(minutes=_MFA_PENDING_EXPIRE_MINUTES),
        )
        return LoginResponse(mfa_required=True, mfa_token=mfa_token)

    access_token = _issue_token(user, db)
    return LoginResponse(access_token=access_token, token_type="bearer")


# ── MFA (TOTP) ────────────────────────────────────────────────────────────────

@router.post("/mfa/challenge", response_model=TokenResponse)
@limiter.limit("10/minute")
def mfa_challenge(
    request: Request,
    body: MFAChallengeRequest,
    db: Session = Depends(get_db),
):
    """Second step of login when the account has MFA enabled — exchanges the
    mfa_token from POST /auth/login plus a TOTP code for a real access token."""
    try:
        claims = decode_access_token(body.mfa_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA session")
    if not claims.get("mfa_pending"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA session")

    user = db.query(User).filter(User.id == claims.get("user_id")).first()
    if not user or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA session")

    if not pyotp.TOTP(user.totp_secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")

    access_token = _issue_token(user, db)
    return TokenResponse(access_token=access_token, token_type="bearer")


@router.post("/mfa/enroll", response_model=MFAEnrollResponse)
def mfa_enroll(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Starts enrollment: generates a new secret (not yet active — totp_enabled
    stays False until /mfa/enroll/confirm verifies a real code) and returns a
    QR code for it. Calling this again before confirming replaces the pending
    secret, which is fine — nothing was gating login on it yet."""
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_secret = pyotp.random_base32()
    db_user.totp_secret = db_secret
    db.commit()

    uri = pyotp.totp.TOTP(db_secret).provisioning_uri(name=db_user.email, issuer_name="MetaSight")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_b64 = base64.b64encode(buf.getvalue()).decode()

    return MFAEnrollResponse(secret=db_secret, provisioning_uri=uri, qr_code_png_base64=png_b64)


@router.post("/mfa/enroll/confirm")
def mfa_enroll_confirm(
    body: MFAEnrollConfirmRequest,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Confirms enrollment with a real code from the authenticator app —
    only after this does totp_enabled flip True and login start requiring it."""
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user or not db_user.totp_secret:
        raise HTTPException(status_code=400, detail="No pending MFA enrollment — call /auth/mfa/enroll first")

    if not pyotp.TOTP(db_user.totp_secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid code")

    db_user.totp_enabled = True
    db.commit()
    return {"detail": "MFA enabled."}


@router.post("/mfa/disable")
def mfa_disable(
    body: MFADisableRequest,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Requires the account password (not just a valid session) to disable
    MFA — a stolen/left-open session alone shouldn't be enough to turn off
    the second factor protecting it."""
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user or not verify_password(body.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    db_user.totp_secret = None
    db_user.totp_enabled = False
    db.commit()
    return {"detail": "MFA disabled."}
