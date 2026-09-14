"""
PolicyEngine — loads PolicyRule from DB or auto-builds from column scan data.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.models import ColumnEntity, PolicyRule, Table
from app.services.policy_cache import get_cached_policy, set_cached_policy
from app.services.settings_service import get_settings

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
    resource: str
    allowed: bool
    denied_columns: list[str]
    masked_columns: list[str]
    tokenized_columns: list[str]
    row_filter_conditions: list[dict]   # [{column, operator, value}]
    policy_id: int | None
    classification: str
    is_admin_exempt: bool
    source_type: str
    auto_policy: bool                   # True = built from column scan data, no explicit PolicyRule
    # Map col_name → pii_type (used by masking layer)
    column_pii_map: dict[str, str | None] = field(default_factory=dict)
    # All known columns (from scan), used for SELECT * expansion
    known_columns: list[str] = field(default_factory=list)
    # Map col_name → explicit masking_type override from policy rule
    # e.g. {"email": "EMAIL", "ssn": "SSN"} — overrides auto-detected pii_type
    column_masking_type_map: dict[str, str | None] = field(default_factory=dict)
    # Map tag_name → action (e.g. {"PII": "mask"})
    # Allows query layer to apply tags dynamically to unscanned fields
    active_tag_policies: dict[str, str] = field(default_factory=dict)
    # Map field_name → action (e.g. {"email": "mask"})
    active_field_policies: dict[str, str] = field(default_factory=dict)


class PolicyEngine:
    """Evaluates access-control decisions for a given resource and user."""

    def __init__(self, db: Session, tenant_id: int):
        self.db = db
        self.tenant_id = tenant_id

    # ── Public API ────────────────────────────────────────────────────────────

    def decide(
        self,
        resource: str,
        user: dict,
        source_type: str = "postgres",
        source_id: int | None = None,
    ) -> PolicyDecision:
        """
        Load PolicyRule for resource+tenant.
        If no explicit rule exists, auto-build from ColumnEntity scan data.
        Admin role with roles_exempt bypasses column controls (NOT row filters).
        """
        user_role = user.get("role", "")

        # ── 1. Find the best matching policy rule ──────────
        # We look for: Exact match > Wildcard match (e.g. folder/*) > Global match (*)
        all_rules = (
            self.db.query(PolicyRule)
            .filter(PolicyRule.tenant_id == self.tenant_id)
            .all()
        )
        
        rule = None
        # Sort rules by resource length descending to prioritize more specific matches
        all_rules.sort(key=lambda r: len(r.resource), reverse=True)
        
        for r in all_rules:
            if r.resource == resource:
                rule = r
                break
            if "*" in r.resource:
                # Glob-to-regex conversion for wildcard support
                pattern = re.escape(r.resource).replace(r"\*", ".*")
                try:
                    if re.fullmatch(pattern, resource, re.IGNORECASE):
                        rule = r
                        break
                except Exception:
                    continue
            if r.resource == "*":
                # Save global rule as fallback if no better match found
                if not rule:
                    rule = r
        
        # If still no rule, try a case-insensitive exact match
        if not rule:
            rule = (
                self.db.query(PolicyRule)
                .filter(
                    PolicyRule.resource.ilike(resource),
                    PolicyRule.tenant_id == self.tenant_id,
                )
                .first()
            )

        # ── 2. Resolve known columns from scan data ───────────────────────
        # Filter table by source_id if provided to avoid cross-source collisions
        table_query = (
            self.db.query(Table)
            .filter(Table.name == resource, Table.tenant_id == self.tenant_id)
        )
        
        if source_id:
            from app.models.models import Schema, Database
            table_query = table_query.join(Schema).join(Database).filter(Database.data_source_id == source_id)
        
        table_obj = table_query.first()
        
        # ── 1.5 Strict Departmental Access Check ───────────────────────
        # If the table is assigned to a department, user MUST belong to it.
        # SuperAdmins bypass this check.
        if user_role != "superadmin" and table_obj and table_obj.department_id:
            user_dept_id = user.get("department_id")
            if user_dept_id != table_obj.department_id:
                logger.warning(
                    "PolicyEngine: ACCESS DENIED. Table '%s' belongs to department %d, "
                    "but user belongs to department %s.",
                    resource, table_obj.department_id, user_dept_id
                )
                return PolicyDecision(
                    resource=resource,
                    allowed=False,  # <── BLOCKED
                    denied_columns=[],
                    masked_columns=[],
                    tokenized_columns=[],
                    row_filter_conditions=[],
                    policy_id=None,
                    classification="INTERNAL",
                    is_admin_exempt=False,
                    source_type=source_type,
                    auto_policy=False,
                    column_pii_map={},
                    known_columns=[],
                )

        scan_columns: list[ColumnEntity] = []
        if table_obj:
            scan_columns = (
                self.db.query(ColumnEntity)
                .filter(
                    ColumnEntity.table_id == table_obj.id,
                    ColumnEntity.tenant_id == self.tenant_id,
                )
                .all()
            )


        known_columns = [c.name for c in scan_columns]
        column_pii_map: dict[str, str | None] = {c.name: c.pii_type for c in scan_columns}

        # ── Global Masking Check ───────────────────────────────────────────
        cfg = get_settings(self.tenant_id, self.db)
        if not cfg.get("masking", {}).get("global_masking_enabled", True):
            if user_role == "admin":
                return PolicyDecision(
                    resource=resource,
                    allowed=True,
                    denied_columns=[],
                    masked_columns=[],
                    tokenized_columns=[],
                    row_filter_conditions=[],
                    policy_id=None,
                    classification="PUBLIC",
                    is_admin_exempt=True,
                    source_type=source_type,
                    auto_policy=False,
                    column_pii_map=column_pii_map,
                    known_columns=known_columns,
                )

        # ── 3. Build decision from explicit rule ──────────────────────────
        if rule:
            # Cache hit: check if we have a cached base decision (without row filters)
            cache_key_no_rf = f"{resource}::no_rf"
            cached = get_cached_policy(self.tenant_id, cache_key_no_rf, user_role)
            if cached is not None and not rule.row_filters:
                logger.debug("PolicyCache: HIT for %s/%s", resource, user_role)
                return cached
            decision = self._from_rule(rule, user, user_role, known_columns, column_pii_map, source_type)
            # Cache only if no user-specific row filters
            if not rule.row_filters:
                set_cached_policy(self.tenant_id, cache_key_no_rf, user_role, decision)
            return decision

        # ── 4. Auto-policy from column scan data ─────────────────────────
        if scan_columns:
            cached = get_cached_policy(self.tenant_id, resource, user_role)
            if cached is not None:
                logger.debug("PolicyCache: HIT (auto) for %s/%s", resource, user_role)
                return cached
            decision = self._auto_policy(scan_columns, user, user_role, known_columns, column_pii_map, source_type, resource)
            set_cached_policy(self.tenant_id, resource, user_role, decision)
            return decision

        # ── 5. No rule, no scan data ───────────────────────────────────────
        # An unclassified resource (never scanned, no explicit PolicyRule) has
        # no basis for deciding what's sensitive — historically this branch
        # returned allowed=True with zero enforcement (no masking, no deny),
        # and with auto_policy=False the caller-side "no explicit policy"
        # warning never even fired, so this was a *silent* full-access default
        # for brand-new/unclassified tables. Default to deny; DEFAULT_UNCLASSIFIED_POLICY
        # is an explicit, documented escape hatch for anyone who needs the old
        # permissive behavior while they backfill scans/policies.
        from app.core.config import settings as _settings
        deny_by_default = getattr(_settings, "DEFAULT_UNCLASSIFIED_POLICY", "deny") != "allow"
        logger.warning(
            "PolicyEngine: no rule or scan data for resource '%s' (tenant %d). %s.",
            resource, self.tenant_id,
            "Denying access" if deny_by_default else "Allowing through (DEFAULT_UNCLASSIFIED_POLICY=allow)",
        )
        return PolicyDecision(
            resource=resource,
            allowed=not deny_by_default,
            denied_columns=[],
            masked_columns=[],
            tokenized_columns=[],
            row_filter_conditions=[],
            policy_id=None,
            classification="UNCLASSIFIED",
            is_admin_exempt=False,
            source_type=source_type,
            auto_policy=True,
            column_pii_map={},
            known_columns=known_columns,
        )

    def substitute_user_attrs(self, template: str, user: dict) -> str:
        """Replace {user.email}, {user.region}, {user.role}, {user.tenant_id} etc."""
        replacements = {
            "{user.email}":     user.get("sub", ""),
            "{user.role}":      user.get("role", ""),
            "{user.tenant_id}": str(user.get("tenant_id", "")),
            "{user.region}":    user.get("region", ""),
            "{user.department}": user.get("department", ""),
        }
        result = template
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, str(value))
        # Also handle arbitrary {user.xxx} patterns not in the map
        result = re.sub(
            r"\{user\.(\w+)\}",
            lambda m: str(user.get(m.group(1), "")),
            result,
        )
        return result

    # ── Private helpers ───────────────────────────────────────────────────────

    # ── Time-based access control ─────────────────────────────────────────────

    @staticmethod
    def _check_time_restrictions(schedule: dict) -> None:
        """
        Raise PermissionError if current UTC time is outside the allowed schedule.

        Schedule format (stored under column_policies["__schedule__"]):
          {
            "allowed_hours": [9, 17],   # hour range [start, end) in UTC
            "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
            "timezone": "UTC"           # only UTC supported for now
          }
        """
        now = datetime.now(timezone.utc)
        day_name = now.strftime("%a")  # Mon, Tue, …
        hour = now.hour

        allowed_days: list[str] = schedule.get("allowed_days", [])
        allowed_hours: list[int] = schedule.get("allowed_hours", [])

        if allowed_days and day_name not in allowed_days:
            raise PermissionError(
                f"Access denied: today ({day_name}) is not in the allowed schedule "
                f"({', '.join(allowed_days)})."
            )

        if len(allowed_hours) == 2:
            start_h, end_h = allowed_hours[0], allowed_hours[1]
            if not (start_h <= hour < end_h):
                raise PermissionError(
                    f"Access denied: current hour ({hour}:00 UTC) is outside allowed "
                    f"window ({start_h}:00–{end_h}:00 UTC)."
                )

    def _from_rule(
        self,
        rule: PolicyRule,
        user: dict,
        user_role: str,
        known_columns: list[str],
        column_pii_map: dict[str, str | None],
        source_type: str,
    ) -> PolicyDecision:
        col_policies: dict = rule.column_policies or {}
        denied: list[str] = []
        masked: list[str] = []
        tokenized: list[str] = []
        # Per-column masking type override: col_name → explicit pii_type string
        column_masking_type_map: dict[str, str | None] = {}
        # Tag-level actions (e.g. {"PII": "mask"})
        active_tag_policies: dict[str, str] = {}
        # Field-level actions (e.g. {"email": "mask"})
        active_field_policies: dict[str, str] = {}
        is_admin_exempt = False

        # ── Time restriction check ─────────────────────────────────────────
        schedule = col_policies.get("__schedule__")
        if schedule and user_role not in schedule.get("exempt_roles", ["admin"]):
            self._check_time_restrictions(schedule)

        # ── Tag-based overrides ────────────────────────────────────────────
        tag_policies: dict = col_policies.get("__tags__", {})
        for tag_name, tag_pol in tag_policies.items():
            action = tag_pol.get("action", "allow")
            if action != "allow":
                active_tag_policies[tag_name] = action
        
        # Merge physical column policies with tag policies (physical overrides tag)
        merged_policies = {}
        for col_name in known_columns:
            tag = column_pii_map.get(col_name)
            if tag and tag in tag_policies:
                merged_policies[col_name] = tag_policies[tag]

        for col_name, pol in col_policies.items():
            if col_name not in ("__schedule__", "__tags__"):
                merged_policies[col_name] = pol

        for col_name, pol in merged_policies.items():
            action = pol.get("action", "allow")
            exempt_roles: list[str] = list(pol.get("roles_exempt", []))  # Safely copy

            # Admin is never added to exempt_roles — admin masking is controlled
            # by the global masking level (raw/partial/full) in settings, not exemption.
            # Other roles listed in roles_exempt bypass this specific column rule.
            if user_role in exempt_roles:
                # This role is explicitly exempted from this column's rule — skip it.
                # Do NOT set is_admin_exempt globally; only flag it if the user bypasses
                # ALL column controls (i.e. they have no masked/denied columns at all).
                continue

            if action == "deny":
                denied.append(col_name)
            elif action == "mask":
                masked.append(col_name)
                # Capture explicit masking_type if configured in the policy rule
                # e.g. {"action": "mask", "masking_type": "EMAIL"}
                masking_type = pol.get("masking_type")
                if masking_type:
                    column_masking_type_map[col_name] = masking_type.upper()
            elif action == "tokenize":
                tokenized.append(col_name)
            
            # If this is a global or field-level specific rule, track as field action
            if rule.resource == "*" or rule.resource.startswith("FIELD:"):
                active_field_policies[col_name] = action
            # "allow" → no action needed

        # is_admin_exempt: True only when user has zero column restrictions
        # (used by sql_rewriter to skip policy evaluation for this user)
        is_admin_exempt = (not denied and not masked and not tokenized)

        # Row filters — apply to everyone (including admins)
        row_filter_conditions = self._resolve_row_filters(rule.row_filters or [], user)

        return PolicyDecision(
            resource=rule.resource,
            allowed=True,
            denied_columns=denied,
            masked_columns=masked,
            tokenized_columns=tokenized,
            row_filter_conditions=row_filter_conditions,
            policy_id=rule.id,
            classification=rule.classification,
            is_admin_exempt=is_admin_exempt,
            source_type=rule.source_type or source_type,
            auto_policy=False,
            column_pii_map=column_pii_map,
            known_columns=known_columns,
            column_masking_type_map=column_masking_type_map,
            active_tag_policies=active_tag_policies,
            active_field_policies=active_field_policies,
        )

    def _auto_policy(
        self,
        scan_columns: list[ColumnEntity],
        user: dict,
        user_role: str,
        known_columns: list[str],
        column_pii_map: dict[str, str | None],
        source_type: str,
        resource: str,
    ) -> PolicyDecision:
        """Build a temporary policy from column scan data (no explicit PolicyRule)."""
        denied: list[str] = []
        masked: list[str] = []
        tokenized: list[str] = []

        # Admins bypass auto-policy column controls (but row filters still apply)
        bypass = user_role in ("admin",)

        classification = "PUBLIC"

        for col in scan_columns:
            if not col.pii_type and not col.classification and not col.action:
                continue

            # Determine classification (escalate if needed)
            if col.classification in ("PII", "FINANCIAL"):
                if classification == "PUBLIC":
                    classification = col.classification

            if bypass:
                continue

            action = col.action or "mask"  # default auto-action for PII columns

            if action == "deny":
                denied.append(col.name)
            elif action == "mask":
                masked.append(col.name)
            elif action == "tokenize":
                tokenized.append(col.name)
            else:
                # "allow" or unknown
                pass

        logger.info(
            "PolicyEngine: auto-policy for '%s': masked=%d denied=%d tokenized=%d",
            resource, len(masked), len(denied), len(tokenized),
        )

        return PolicyDecision(
            resource=resource,
            allowed=True,
            denied_columns=denied,
            masked_columns=masked,
            tokenized_columns=tokenized,
            row_filter_conditions=[],
            policy_id=None,
            classification=classification,
            is_admin_exempt=bypass,
            source_type=source_type,
            auto_policy=True,
            column_pii_map=column_pii_map,
            known_columns=known_columns,
        )

    def _resolve_row_filters(self, raw_filters: list, user: dict) -> list[dict]:
        resolved = []
        for rf in raw_filters:
            column = rf.get("column", "")
            raw_value = rf.get("value", "")
            operator = rf.get("operator", "=")
            resolved_value = self.substitute_user_attrs(str(raw_value), user)
            resolved.append({"column": column, "operator": operator, "value": resolved_value})
        return resolved
