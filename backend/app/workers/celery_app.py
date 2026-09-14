from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "workers",
    broker=settings.REDIS_BROKER_URL,
    backend=settings.REDIS_BROKER_URL,
    include=["app.workers.tasks"],
)

celery_app.conf.update(task_track_started=True)

_beat_schedule = {}

# PAM JIT auto-revoke — Enterprise-only (see app/workers/tasks.py:
# revoke_expired_pam_privileges). Scheduled only when the metasight_enterprise
# package is installed alongside this Community backend; Community itself has
# no ActivePrivilege table to sweep. This is the sole enforcement point for
# expiring elevated privileges (SUPERUSER/DBA/etc.) when Enterprise *is*
# installed; it must run somewhere durable — Celery beat rather than an
# in-process APScheduler.
try:
    import metasight_enterprise  # noqa: F401
    _beat_schedule["pam-auto-revoke"] = {
        "task":     "app.workers.tasks.revoke_expired_pam_privileges",
        "schedule": 60.0,
    }
except ImportError:
    pass

# Native DAM polling — only schedule if the interval is enabled (> 0)
if settings.DAM_POLL_INTERVAL_SECONDS > 0:
    _beat_schedule["dam-native-poll"] = {
        "task":     "app.workers.tasks.poll_native_dam_sources",
        "schedule": float(settings.DAM_POLL_INTERVAL_SECONDS),
    }

celery_app.conf.beat_schedule = _beat_schedule
