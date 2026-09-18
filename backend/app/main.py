from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request
from starlette.responses import Response


def _get_user_or_ip(request: Request) -> str:
    """Rate-limit key: JWT sub (user email) if authenticated, else IP address."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        try:
            from jose import jwt as _jwt
            from app.core.config import settings as _s
            payload = _jwt.decode(
                auth[7:], _s.JWT_SECRET_KEY, algorithms=[_s.JWT_ALGORITHM]
            )
            sub = payload.get("sub")
            if sub:
                return sub
        except Exception:
            pass
    return get_remote_address(request)

from app.core.config import settings
from app.core.exceptions import ExceptionMiddleware
from app.core.logging import setup_logging
from app.api import auth, sso, sources, scans, tables, users, connectors
from app.api import policies, catalog, query as query_router, audit as audit_router, catalog_schemas
from app.api import approvals as approvals_router
from app.api import settings as settings_router
from app.api import security as security_router
from app.api import departments as departments_router
from app.api import downloads as downloads_router
from app.api import agents as agents_router
from app.api import gateway as gateway_router

setup_logging()

import logging as _log
_logger = _log.getLogger(__name__)

_is_prod = settings.ENV.lower() == "production"

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    # Interactive API docs expose every route (including /pam/*, /superadmin/*)
    # and the full OpenAPI schema — off by default in production.
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
)


@app.on_event("startup")
def _startup_checks():
    """
    Schema is exclusively Alembic's responsibility — `alembic upgrade head` runs
    as an explicit deploy step (see deploy/systemd/metasight-api.service
    ExecStartPre), not here. This used to also call Base.metadata.create_all()
    and ad hoc `ALTER TABLE ... ADD COLUMN` on every process boot, which let the
    live schema drift out of sync with Alembic's migration history and raced
    concurrent DDL across multiple gunicorn workers on every restart.

    What's left here is startup-time posture warnings only — no schema changes,
    no side effects.
    """
    if settings.CORS_ORIGINS == ["*"]:
        _logger.warning(
            "CORS_ORIGINS is '*' with allow_credentials=True — Starlette treats "
            "this as 'any origin, with credentials'. Set CORS_ORIGINS to your "
            "actual frontend origin(s) in production."
        )
    if not _is_prod:
        _logger.warning(
            "ENV=%s — /docs, /redoc, /openapi.json are enabled. Set ENV=production "
            "to disable them.", settings.ENV,
        )

    # Community edition supports exactly one tenant per deployment. The DB-level
    # partial unique index (community_single_tenant_guard migration) is the real
    # enforcement; this is a defense-in-depth check that refuses to serve traffic
    # if that invariant was somehow violated (e.g. a restored backup from a
    # different install, or the guard index missing/dropped by mistake).
    if register_enterprise is None:
        from app.core.database import SessionLocal
        from app.models.models import Tenant
        _db = SessionLocal()
        try:
            _tenant_count = _db.query(Tenant).count()
            if _tenant_count > 1:
                raise RuntimeError(
                    f"Community edition supports exactly one tenant; found {_tenant_count}. "
                    "Install metasight_enterprise for multi-tenant support."
                )
        finally:
            _db.close()

# ── Middleware ────────────────────────────────────────────────────────────────

@app.middleware("http")
async def _disable_cache_middleware(request: Request, call_next):
    """Security hardening: Disable browser caching for all API responses."""
    response: Response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

app.add_middleware(ExceptionMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Rate limiting ─────────────────────────────────────────────────────────────

limiter = Limiter(key_func=_get_user_or_ip, storage_uri=settings.REDIS_BROKER_URL)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(auth.router,         prefix="/auth",       tags=["auth"])
app.include_router(sso.router,          prefix="/auth/sso",   tags=["sso"])
app.include_router(users.router,        prefix="/users",      tags=["users"])
app.include_router(sources.router,      prefix="/sources",    tags=["sources"])
app.include_router(scans.router,        prefix="/scans",      tags=["scans"])
app.include_router(tables.router,       prefix="/tables",     tags=["tables"])
app.include_router(connectors.router,   prefix="/connectors", tags=["connectors"])
app.include_router(policies.router,     prefix="/policies",   tags=["policies"])
app.include_router(catalog_schemas.router, prefix="/catalog", tags=["catalog"])
app.include_router(catalog.router,         prefix="/catalog", tags=["catalog"])
app.include_router(query_router.router, prefix="/query",      tags=["query"])
app.include_router(audit_router.router,    prefix="/audit",     tags=["audit"])
app.include_router(approvals_router.router, prefix="/approvals", tags=["approvals"])
app.include_router(settings_router.router, prefix="/settings",  tags=["settings"])
app.include_router(security_router.router, prefix="/security",  tags=["security"])
app.include_router(departments_router.router, prefix="/catalog/departments", tags=["catalog-departments"])
app.include_router(agents_router.router,      prefix="/agents",     tags=["agents"])
app.include_router(gateway_router.router,      prefix="/gateway",    tags=["gateway"])

# Tenant management (/superadmin/tenants) is Enterprise-only — see
# metasight_enterprise.superadmin_tenants, registered below by
# register_enterprise(). Community supports exactly one tenant per
# deployment (enforced by the community_single_tenant_guard migration),
# so there is no tenant-CRUD router here at all, not merely a hidden one.

# ── Enterprise Platform (full PAM: access requests, JIT, session recording, ────
# ── evidence, correlation, risk, compliance) — optional package ───────────────
#
# metasight_enterprise is a separate top-level distribution (../enterprise/)
# that depends on this backend, never the reverse. Community deployments that
# don't install it simply don't get these routes — no entitlement flag to
# bypass, the code isn't present.

try:
    from metasight_enterprise import register_enterprise
except ImportError:
    register_enterprise = None

if register_enterprise:
    register_enterprise(app)
else:
    _logger.info("metasight_enterprise not installed — PAM routes disabled (Community edition).")

app.include_router(downloads_router.router,    prefix="/downloads",           tags=["downloads"])

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
