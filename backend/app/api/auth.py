import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.deps import get_db
from app.core.security import verify_password, hash_password
from app.core.jwt import create_access_token
from app.models.models import User, Tenant, UserRole, LoginAttempt
from app.schemas.schemas import TokenResponse, SetupRequest, UserResponse
from app.services.settings_service import get_settings as _get_tenant_settings
from fastapi.security import OAuth2PasswordRequestForm
from app.core.utils import utcnow

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

@router.post("/login", response_model=TokenResponse)
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

        access_token = create_access_token(
            {"sub": email, "role": "superadmin", "tenant_id": t_id, "user_id": user_id, "department_id": dept_id},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return TokenResponse(access_token=access_token, token_type="bearer")

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

    access_token = create_access_token(
        {"sub": user.email, "role": user.role.value, "tenant_id": user.tenant_id, "user_id": user.id, "department_id": user.department_id},
        expires_delta=timedelta(minutes=jwt_expire),
    )
    return TokenResponse(access_token=access_token, token_type="bearer")
