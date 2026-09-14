import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "Multi-Tenant Metadata Ingestion API"

    # Database
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "metadata_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: str = "5432"

    # Auth — no insecure defaults; must be set via env
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    # One-time setup protection token — must be set via env
    SETUP_SECRET: str

    # Super Admin credentials
    SUPER_ADMIN_EMAIL: str
    SUPER_ADMIN_PASSWORD: str

    # Encryption — no insecure defaults; must be set via env
    ENCRYPTION_KEY: str

    # Celery / Redis
    REDIS_BROKER_URL: str = "redis://localhost:6379/0"

    # CORS
    CORS_ORIGINS: list[str] = ["*"]

    # HashiCorp Vault (optional — leave unset to use encrypted_config fallback)
    VAULT_ADDR:  Optional[str] = None   # e.g. "http://vault:8200"
    VAULT_TOKEN: Optional[str] = None   # root or AppRole token

    # Screenshot / session recording storage (cross-platform default: ~/.metasight/screenshots)
    SCREENSHOT_STORAGE_DIR: str = os.path.join(os.path.expanduser("~"), ".metasight", "screenshots")

    # Callback URL the server passes to locally-spawned agents (--server flag)
    # in app/core/agent_runner.py's Windows-only local-testing convenience.
    # Override in production if the API isn't reachable at localhost:8000
    # (different port, behind a reverse proxy, etc).
    AGENT_CALLBACK_URL: str = "http://localhost:8000"

    # Native DAM polling interval (seconds); 0 = disabled
    DAM_POLL_INTERVAL_SECONDS: int = 300

    # Environment mode — "production" disables /docs, /redoc, /openapi.json.
    ENV: str = "production"

    # Policy for resources with no explicit PolicyRule and no scan data yet
    # (brand-new/unclassified tables). "deny" is fail-closed and the safe
    # default; set to "allow" only as a temporary migration aid.
    DEFAULT_UNCLASSIFIED_POLICY: str = "deny"

    # Computed — filled in by model_validator
    SQLALCHEMY_DATABASE_URI: Optional[str] = None

    @field_validator("ENCRYPTION_KEY")
    @classmethod
    def validate_encryption_key(cls, v: str) -> str:
        if len(v.encode()) < 32:
            raise ValueError(
                "ENCRYPTION_KEY must be at least 32 bytes. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(16))\""
            )
        return v

    @model_validator(mode="after")
    def assemble_db_uri(self) -> "Settings":
        if not self.SQLALCHEMY_DATABASE_URI:
            from urllib.parse import quote_plus
            encoded_pwd = quote_plus(self.POSTGRES_PASSWORD) if self.POSTGRES_PASSWORD else ""
            self.SQLALCHEMY_DATABASE_URI = (
                f"postgresql+psycopg2://{self.POSTGRES_USER}:{encoded_pwd}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        return self


settings = Settings()
