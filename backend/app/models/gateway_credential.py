"""
MetaSight Gateway — SQLAlchemy ORM model.

Backs the Go-based database wire-protocol adapters (backend/gateway/): a
mandatory network proxy real clients (psql, mysql CLI, BI tools,
applications using their normal DB driver) connect through, unlike the
Enterprise SDK (metasight_sdk / SDKCredential) which requires an
application code change and only covers engines/situations the gateway
doesn't (Oracle, MongoDB, or clients that can't be network-routed through a
gateway host). Each GatewayCredential is a wire-protocol identity
(username + secret) the gateway authenticates a connecting client against
— never the target DataSource's own DB password, which only the gateway
process itself ever sees (fetched via Vault/encrypted_config, same
precedence pam_jit.py uses).

Unlike SDKCredential, this IS scoped to exactly one DataSource: a wire
listener naturally maps one username to one target database (the startup
handshake's own "database" parameter is informational only, not a
selector, to sidestep name-mapping ambiguity).
"""
from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class GatewayCredential(Base):
    __tablename__ = "gateway_credentials"

    id               = Column(Integer, primary_key=True, index=True)
    tenant_id        = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    data_source_id   = Column(Integer, ForeignKey("data_sources.id"), nullable=False)

    # Nullable: null identifies a service-account credential (e.g. an
    # application's own identity) not tied to a human MetaSight User row.
    user_id          = Column(Integer, ForeignKey("users.id"), nullable=True)

    # What the client puts in the startup handshake's "user" field.
    # Globally unique: the wire protocol carries only a username at auth
    # time, no tenant hint, so lookup must be unambiguous from username alone.
    gateway_username = Column(String(256), nullable=False, unique=True, index=True)
    secret_hash      = Column(String(256), nullable=False)  # Argon2id via app.core.security.hash_password
    display_name     = Column(String(256), nullable=False)

    # Effective policy-evaluation identity overrides — used verbatim when
    # user_id is null, or to issue a deliberately scoped-down identity for
    # an existing human user.
    role_override            = Column(String(64), nullable=True)
    department_id_override   = Column(Integer, ForeignKey("departments.id"), nullable=True)
    region_override           = Column(String(64), nullable=True)

    status           = Column(String(32), default="ACTIVE")  # ACTIVE|REVOKED|DISABLED
    created_by_id    = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at       = Column(DateTime(timezone=True), default=_utcnow)
    last_used_at     = Column(DateTime(timezone=True), nullable=True)
    expires_at       = Column(DateTime(timezone=True), nullable=True)
    revoked_at        = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("gateway_username", name="_gateway_credentials_username_uc"),
    )

    tenant      = relationship("Tenant")
    data_source = relationship("DataSource")
    user        = relationship("User", foreign_keys=[user_id])
    created_by  = relationship("User", foreign_keys=[created_by_id])
