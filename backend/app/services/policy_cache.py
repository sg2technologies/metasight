"""
Redis-backed policy cache.
Caches PolicyDecision per (tenant_id, table_name, user_role) with TTL=60s.
Falls back silently if Redis is unavailable.
"""
from __future__ import annotations

import dataclasses
import json
import logging
from typing import TYPE_CHECKING

from app.core.config import settings

if TYPE_CHECKING:
    from app.services.policy_engine import PolicyDecision

logger = logging.getLogger(__name__)

_POLICY_TTL = 60  # seconds

_redis_client = None


def _get_redis():
    """Lazy-init Redis connection. Returns None if Redis is unavailable."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis
        client = redis.from_url(settings.REDIS_BROKER_URL, socket_connect_timeout=1)
        client.ping()
        _redis_client = client
        logger.info("PolicyCache: connected to Redis at %s", settings.REDIS_BROKER_URL)
    except Exception as exc:
        logger.debug("PolicyCache: Redis unavailable (%s), running without cache", exc)
        _redis_client = None
    return _redis_client


def _cache_key(tenant_id: int, table_name: str, user_role: str) -> str:
    return f"dg:policy:{tenant_id}:{table_name}:{user_role}"


def get_cached_policy(
    tenant_id: int,
    table_name: str,
    user_role: str,
) -> "PolicyDecision | None":
    """Return a cached PolicyDecision, or None on miss/error."""
    r = _get_redis()
    if r is None:
        return None
    try:
        data = r.get(_cache_key(tenant_id, table_name, user_role))
        if data:
            from app.services.policy_engine import PolicyDecision
            return PolicyDecision(**json.loads(data))
    except Exception as exc:
        logger.debug("PolicyCache: get error: %s", exc)
    return None


def set_cached_policy(
    tenant_id: int,
    table_name: str,
    user_role: str,
    decision: "PolicyDecision",
    ttl: int = _POLICY_TTL,
) -> None:
    """Store a PolicyDecision in Redis with TTL."""
    r = _get_redis()
    if r is None:
        return
    try:
        # json, not pickle: PolicyDecision is a plain dataclass of primitives,
        # and deserializing pickle from Redis is unnecessary attack surface for
        # a security product (anyone who can write to Redis — SSRF, a shared/
        # misconfigured instance — gets arbitrary object deserialization, i.e.
        # a path to RCE).
        r.setex(
            _cache_key(tenant_id, table_name, user_role),
            ttl,
            json.dumps(dataclasses.asdict(decision)),
        )
    except Exception as exc:
        logger.debug("PolicyCache: set error: %s", exc)


def invalidate_policy_cache(
    tenant_id: int,
    table_name: str | None = None,
) -> int:
    """
    Invalidate cached policies for a tenant (optionally scoped to one table).
    Returns number of keys deleted.
    """
    r = _get_redis()
    if r is None:
        return 0
    try:
        pattern = f"dg:policy:{tenant_id}:{table_name or '*'}:*"
        deleted = 0
        for key in r.scan_iter(pattern, count=100):
            r.delete(key)
            deleted += 1
        if deleted:
            logger.info(
                "PolicyCache: invalidated %d keys for tenant=%d table=%s",
                deleted, tenant_id, table_name or "*",
            )
        return deleted
    except Exception as exc:
        logger.debug("PolicyCache: invalidate error: %s", exc)
        return 0
