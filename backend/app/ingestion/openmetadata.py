import logging

logger = logging.getLogger(__name__)


def run_metadata_workflow(source_type: str, config: dict, tenant_id: int, db):
    try:
        from openmetadata.ingestion.api.workflow import Workflow
    except ImportError as exc:
        raise RuntimeError(
            "openmetadata-ingestion is not installed. "
            "Add it to requirements.txt and run: pip install openmetadata-ingestion"
        ) from exc

    from app.ingestion.sink import CustomSink

    workflow_config = {
        "source": {
            "type": source_type,
            "serviceName": config["serviceName"],
            "config": config,
        },
        "sink": {"type": "custom-sink", "config": {"tenant_id": tenant_id}},
        "workflowConfig": {"loggerLevel": "INFO"},
    }
    workflow = Workflow.create(workflow_config)
    workflow.set_sink(CustomSink(db, tenant_id))
    try:
        workflow.execute()
        workflow.raise_from_status()
    except Exception:
        logger.exception("Metadata workflow failed for source_type=%s", source_type)
        raise
    finally:
        workflow.stop()
