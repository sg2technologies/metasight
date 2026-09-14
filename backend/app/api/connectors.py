from fastapi import APIRouter, Depends
from app.core.deps import get_current_user
from app.core.connectors import CONNECTOR_CATALOG, VALID_CATEGORIES
from app.schemas.schemas import ConnectorCatalogResponse

router = APIRouter()


@router.get("", response_model=ConnectorCatalogResponse)
def list_connectors(user: dict = Depends(get_current_user)):
    """Return the full OpenMetadata-aligned connector catalog."""
    return ConnectorCatalogResponse(
        categories=sorted(VALID_CATEGORIES),
        connectors=CONNECTOR_CATALOG,
    )
