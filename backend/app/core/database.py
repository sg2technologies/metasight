import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

logger = logging.getLogger(__name__)

# NOTE: this used to silently fall back to a local `sqlite:///./metasight.db`
# file on ANY connection failure (Postgres down, DNS blip, restart race), at
# module-import time, in EVERY process (each gunicorn worker, celery worker,
# celery beat). In a multi-process production deployment that means different
# processes could silently start running against their own worker-local
# SQLite file instead of the shared Postgres, with only a log WARNING as
# evidence — a severe, hard-to-detect data-integrity footgun. Fail fast
# instead: let the process crash so systemd/the process supervisor restarts
# it and surfaces the failure, rather than quietly diverging application state.
engine_kwargs = {"pool_pre_ping": True}
if not settings.SQLALCHEMY_DATABASE_URI.startswith("sqlite"):
    engine_kwargs.update(
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=1800,  # recycle connections older than 30 min (avoids stale-conn errors)
    )
else:
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.SQLALCHEMY_DATABASE_URI, **engine_kwargs)

# create_engine() itself is lazy — it won't actually open a connection until
# first use, which would defer a misconfiguration (wrong host, DB down) to
# whenever the first request happens to hit the DB, rather than surfacing it
# at process startup. Test connectivity once, eagerly, at import time — with
# no except/fallback around it, so a failure here crashes the process and
# systemd (see deploy/systemd/metasight-api.service) reports it immediately.
with engine.connect():
    pass
logger.info("Connected to database (%s)", engine.url.drivername)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
