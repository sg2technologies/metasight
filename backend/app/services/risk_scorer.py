"""
Query risk scorer — assigns a risk score and level to each executed query.

Score formula:
  denied_cols   × 15  (high risk: data being actively blocked)
  masked_cols   × 10  (medium risk: PII present)
  tokenized_cols × 8  (medium risk: sensitive identifiers)
  join_depth    × 5   (each extra table join = wider blast radius)
  no_row_filter + 10  (unrestricted access = higher risk)
  row_count     × 0.01 (capped at 20)
  admin_bypass  + 5   (exemption used)
  warnings      × 3   (function leakage warnings caught)

Levels:
  LOW      < 20
  MEDIUM   20–49
  HIGH     50–79
  CRITICAL ≥ 80
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.rewriters.sql_rewriter import RewriteMeta
    from app.services.policy_engine import PolicyDecision


@dataclass
class RiskScore:
    score: float
    level: str                         # LOW | MEDIUM | HIGH | CRITICAL
    factors: dict[str, float] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


_THRESHOLDS = [
    (80, "CRITICAL"),
    (50, "HIGH"),
    (20, "MEDIUM"),
    (0,  "LOW"),
]


def _level(score: float) -> str:
    for threshold, label in _THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def score_query(
    meta: "RewriteMeta",
    decisions: "dict[str, PolicyDecision]",
    row_count: int = 0,
) -> RiskScore:
    """
    Compute a risk score for a query given its RewriteMeta and per-table PolicyDecisions.

    Args:
        meta:       What the SQL rewriter detected (denied/masked/tokenized cols, warnings).
        decisions:  Per-table PolicyDecision map (table_name → decision).
        row_count:  Actual rows returned (0 if not yet executed, e.g. in simulation).

    Returns:
        RiskScore with score, level, per-factor breakdown, and recommendations.
    """
    factors: dict[str, float] = {}
    recs: list[str] = []

    # ── Column sensitivity ─────────────────────────────────────────────────────
    n_denied    = len(meta.denied_columns)
    n_masked    = len(meta.masked_columns)
    n_tokenized = len(meta.tokenized_columns)

    if n_denied:
        factors["denied_columns"] = n_denied * 15
        recs.append(f"{n_denied} denied column(s) present — consider narrowing SELECT list")
    if n_masked:
        factors["masked_columns"] = n_masked * 10
    if n_tokenized:
        factors["tokenized_columns"] = n_tokenized * 8

    # ── JOIN depth ─────────────────────────────────────────────────────────────
    join_depth = max(0, len(decisions) - 1)
    if join_depth:
        factors["join_depth"] = join_depth * 5
        if join_depth >= 3:
            recs.append("Query spans 4+ tables — verify data minimization")

    # ── Row filter coverage ────────────────────────────────────────────────────
    if not meta.row_filter_applied and decisions:
        factors["no_row_filter"] = 10
        recs.append("No row-level filter applied — full table scan risk")

    # ── Row count ─────────────────────────────────────────────────────────────
    row_score = min(row_count * 0.01, 20)
    if row_score:
        factors["row_count"] = round(row_score, 2)
        if row_count > 5000:
            recs.append(f"Large result set ({row_count} rows) — consider adding filters")

    # ── Admin bypass ──────────────────────────────────────────────────────────
    any_admin_exempt = any(d.is_admin_exempt for d in decisions.values())
    if any_admin_exempt:
        factors["admin_exempt"] = 5
        recs.append("Admin exemption in effect — access is unmasked")

    # ── Function leakage warnings ─────────────────────────────────────────────
    if meta.warnings:
        factors["leakage_warnings"] = len(meta.warnings) * 3
        recs.append(f"{len(meta.warnings)} function leakage expression(s) suppressed")

    # ── Auto-policy (no explicit rule) ────────────────────────────────────────
    any_auto = any(d.auto_policy for d in decisions.values())
    if any_auto:
        factors["auto_policy"] = 5
        recs.append("Auto-policy in effect — create an explicit PolicyRule for better control")

    total = round(sum(factors.values()), 1)
    level = _level(total)

    return RiskScore(score=total, level=level, factors=factors, recommendations=recs)
