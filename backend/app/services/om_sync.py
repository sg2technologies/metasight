"""
Sync OpenMetadata tag classifications back into our policy_rules table.
Called after a successful scan when openmetadata-ingestion is available.
"""
import logging
from sqlalchemy.orm import Session
from app.models.models import PolicyRule, ColumnEntity, Table

logger = logging.getLogger(__name__)

# Map OpenMetadata tag FQNs → default governance action
TAG_ACTION_MAP: dict[str, dict] = {
    "PII.Email":       {"action": "mask",     "pii_type": "EMAIL"},
    "PII.Phone":       {"action": "tokenize", "pii_type": "PHONE"},
    "PII.SSN":         {"action": "deny",     "pii_type": "SSN"},
    "PII.Name":        {"action": "mask",     "pii_type": "NAME"},
    "PII.Address":     {"action": "mask",     "pii_type": "ADDRESS"},
    "PII.CreditCard":  {"action": "tokenize", "pii_type": "CREDIT_CARD"},
    "PII.IPAddress":   {"action": "mask",     "pii_type": "IP_ADDRESS"},
    "Financial":       {"action": "mask",     "pii_type": None},
    "Public":          {"action": "allow",    "pii_type": None},
}


def sync_table_classifications(table_id: int, om_columns: list[dict], db: Session, tenant_id: int) -> None:
    """
    Given OpenMetadata column metadata (list of {name, tags:[{tagFQN}]}),
    update ColumnEntity classifications and upsert a PolicyRule for the table.

    om_columns example:
        [{"name": "email", "tags": [{"tagFQN": "PII.Email"}]}, ...]
    """
    table = db.query(Table).filter(Table.id == table_id, Table.tenant_id == tenant_id).first()
    if not table:
        logger.warning("sync_table_classifications: table %d not found", table_id)
        return

    column_policies: dict[str, dict] = {}
    highest_classification = "PUBLIC"

    for om_col in om_columns:
        col_name = om_col.get("name", "")
        col_entity = (
            db.query(ColumnEntity)
            .filter(ColumnEntity.table_id == table_id, ColumnEntity.name == col_name, ColumnEntity.tenant_id == tenant_id)
            .first()
        )
        for tag in om_col.get("tags", []):
            tag_fqn = tag.get("tagFQN", "")
            mapping = TAG_ACTION_MAP.get(tag_fqn)
            if not mapping:
                continue
            if col_entity:
                col_entity.pii_type = mapping.get("pii_type")
                col_entity.classification = "PII" if "PII" in tag_fqn else ("FINANCIAL" if tag_fqn == "Financial" else "PUBLIC")
                col_entity.action = mapping["action"]
            column_policies[col_name] = {
                "action": mapping["action"],
                "roles_exempt": ["admin"],
            }
            if "PII" in tag_fqn or tag_fqn == "Financial":
                highest_classification = "PII" if "PII" in tag_fqn else "FINANCIAL"

    # Upsert PolicyRule for this table
    existing = (
        db.query(PolicyRule)
        .filter(PolicyRule.resource == table.name, PolicyRule.tenant_id == tenant_id)
        .first()
    )
    if existing:
        existing.column_policies = column_policies
        existing.classification = highest_classification
    else:
        db.add(PolicyRule(
            resource=table.name,
            classification=highest_classification,
            source_type="postgres",
            column_policies=column_policies,
            row_filters=[],
            tenant_id=tenant_id,
        ))
    db.commit()
    logger.info("sync_table_classifications: synced %d columns for table %s", len(om_columns), table.name)
