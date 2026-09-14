import logging
from datetime import datetime, timezone

from app.workers.celery_app import celery_app
from app.models.models import ScanRun, ScanRunStatus, DataSource
from app.core.database import SessionLocal
from app.core.encryption import aes_cipher

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.tasks.poll_native_dam_sources")
def poll_native_dam_sources():
    """Poll all database sources for native audit events and ingest to DAM."""
    from app.services.dam_native_poller import poll_all_sources
    db = SessionLocal()
    try:
        result = poll_all_sources(db)
        logger.info("Native DAM poll complete: %s", result)
        return result
    except Exception as exc:
        logger.exception("Native DAM poll task failed: %s", exc)
        raise
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.revoke_expired_pam_privileges")
def revoke_expired_pam_privileges():
    """
    Sweep ActivePrivilege records past their expiry and REVOKE on the target DB.

    Runs on Celery beat (always scheduled — see celery_app.py) rather than an
    in-process APScheduler started by the FastAPI app: an in-process scheduler
    dies with the web worker (crash/redeploy/OOM) and duplicates itself across
    every gunicorn worker, either of which can leave DBA-level JIT grants live
    past their expiry with nothing revoking them. Celery beat is a single,
    independently-supervised process (see deploy/systemd/metasight-beat.service).
    """
    from metasight_enterprise.services.pam_jit import revoke_expired
    db = SessionLocal()
    try:
        count = revoke_expired(db)
        if count:
            logger.info("Auto-revoke: %d PAM privilege(s) revoked", count)
        return count
    except Exception as exc:
        logger.error("PAM auto-revoke sweep failed: %s", exc, exc_info=True)
        raise
    finally:
        db.close()


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=120,
)
def run_ingestion_task(self, scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not scan:
            logger.warning("ScanRun %s not found — skipping", scan_id)
            return

        scan.status = ScanRunStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        ds = db.query(DataSource).filter(DataSource.id == scan.data_source_id).first()
        if not ds:
            scan.status = ScanRunStatus.FAILED
            scan.error = f"DataSource {scan.data_source_id} not found"
            db.commit()
            logger.error("DataSource %s missing for scan %s", scan.data_source_id, scan_id)
            return

        config = {k: aes_cipher.decrypt(v) for k, v in ds.encrypted_config.items()}

        try:
            from app.ingestion.native_scanner import run_native_scan
            counts = run_native_scan(ds.type, config, ds.id, scan.tenant_id, db, scan_id=scan.id)
            scan.status = ScanRunStatus.COMPLETED
            scan.error = f"Discovered: {counts['schemas']} schemas, {counts['tables']} tables, {counts['columns']} columns"
            logger.info("Scan %s completed: %s", scan_id, counts)
        except NotImplementedError as exc:
            # Unsupported connector — fall back to OpenMetadata workflow
            logger.warning("Native scanner unavailable (%s), trying OpenMetadata workflow", exc)
            try:
                from app.ingestion.openmetadata import run_metadata_workflow
                run_metadata_workflow(ds.type, config, scan.tenant_id, db)
                scan.status = ScanRunStatus.COMPLETED
            except Exception as om_exc:
                scan.status = ScanRunStatus.FAILED
                scan.error = str(om_exc)
                logger.exception("OpenMetadata workflow failed for scan %s", scan_id)
                raise
        except Exception as exc:
            scan.status = ScanRunStatus.FAILED
            scan.error = str(exc)
            logger.exception("Native scan failed for scan %s", scan_id)
            raise  # let Celery autoretry handle it
        finally:
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
