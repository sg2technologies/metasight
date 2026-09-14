"""
Shared HashiCorp Vault KV-v2 credential fetch helper.

Used by both Community (app/services/dam_native_poller.py) and Enterprise
(app/enterprise/services/pam_jit.py) to resolve a DataSource's connection
config when it's stored in Vault rather than the built-in AES-256-GCM
`encrypted_config` column. Lives in core rather than either package so
neither depends on the other for it.
"""
from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger(__name__)


def fetch_from_vault(vault_path: str) -> Optional[dict]:
    """Fetch a secret from HashiCorp Vault KV v2. Returns None on any error."""
    try:
        import hvac
        from app.core.config import settings
        if not settings.VAULT_ADDR or not settings.VAULT_TOKEN:
            return None
        client = hvac.Client(url=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)
        secret = client.secrets.kv.v2.read_secret(path=vault_path)
        return secret["data"]["data"]
    except Exception as exc:
        log.warning("Vault lookup failed (path=%s): %s", vault_path, exc)
        return None
