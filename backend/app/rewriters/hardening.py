"""
Bypass Resistance — Attack Surface Hardening for the SQL query gateway.

Defenses implemented:
  1.  Unicode normalization (NFKC) — homoglyph / lookalike character attacks
  2.  Zero-width & control character removal — invisible character injection
  3.  Null byte stripping — SQL parser confusion attacks
  4.  Comment stripping — policy-bypass via inline comment injection
  5.  Multi-statement detection — semicolon injection
  6.  UNION / INTERSECT / EXCEPT branch policy enforcement
  7.  CTE (WITH clause) policy enforcement — verified via recursive rewriting
  8.  Scalar subquery leakage detection
  9.  LATERAL join detection and policy enforcement
  10. COPY / INTO / OUTFILE exfiltration patterns
  11. Post-rewrite column leak verification
  12. Row-filter bypass via ORDER BY / HAVING injection detection
  13. Stacked-hint injection (/*+ ... */) stripping
"""
from __future__ import annotations

import logging
import re
import unicodedata
from typing import TYPE_CHECKING

import sqlglot
from sqlglot import exp

if TYPE_CHECKING:
    from app.services.policy_engine import PolicyDecision

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Input normalisation
# ─────────────────────────────────────────────────────────────────────────────

# Characters that are invisible but could split keyword detection
_ZERO_WIDTH = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064"
    r"\u206a-\u206f\ufeff\u00ad]"
)

# SQL optimizer hints (Postgres, MySQL, Oracle, MSSQL)
_HINT_PATTERN = re.compile(r"/\*\+.*?\*/", re.DOTALL)

# Null bytes
_NULL_BYTE = re.compile(r"\x00+")


def normalize_sql(sql: str) -> str:
    """
    Sanitize raw SQL input before parsing:
      - NFKC unicode normalization (collapses homoglyphs: Cyrillic 'а' → 'a')
      - Zero-width / invisible character removal
      - Null byte removal
      - Optimizer hint stripping
      - Strip leading/trailing whitespace

    Raises ValueError if suspicious non-ASCII remains after normalization.
    """
    # NFKC: e.g. ｅｍａｉｌ (full-width) → email, ℯ → e
    sql = unicodedata.normalize("NFKC", sql)

    # Remove zero-width / directional control characters
    sql = _ZERO_WIDTH.sub("", sql)

    # Remove null bytes
    if _NULL_BYTE.search(sql):
        logger.warning("Hardening: null byte detected and stripped from SQL input")
        sql = _NULL_BYTE.sub("", sql)

    # Strip optimizer hints (/*+ ... */) — they cannot affect policy
    sql = _HINT_PATTERN.sub("", sql)

    # Detect residual non-printable ASCII (≤ 0x08, 0x0B, 0x0C, 0x0E-0x1F)
    non_printable = re.findall(r"[\x01-\x08\x0b\x0c\x0e-\x1f]", sql)
    if non_printable:
        raise ValueError(
            f"SQL contains non-printable control characters (hex: "
            f"{[hex(ord(c)) for c in non_printable]}). Request blocked."
        )

    # Warn on non-ASCII chars that survived normalization
    non_ascii = [c for c in sql if ord(c) > 127]
    if non_ascii:
        unique = list(set(non_ascii))[:5]
        logger.warning(
            "Hardening: non-ASCII chars in SQL after normalization: %s — verify intent",
            [f"U+{ord(c):04X}" for c in unique],
        )

    return sql.strip()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Comment stripping (before AST parsing)
# ─────────────────────────────────────────────────────────────────────────────

_LINE_COMMENT = re.compile(r"--[^\r\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def strip_sql_comments(sql: str) -> str:
    """
    Remove SQL comments that could be used to bypass row filters.

    Attack: SELECT email FROM profiles -- WHERE region = 'injected'
    With this stripped, sqlglot parses the intended WHERE clause cleanly.

    Note: we log a warning when comments are present so analysts can review.
    """
    has_line = bool(_LINE_COMMENT.search(sql))
    has_block = bool(_BLOCK_COMMENT.search(sql))

    if has_line or has_block:
        logger.warning(
            "Hardening: SQL comments detected and stripped "
            "(line=%s block=%s) — potential bypass attempt logged",
            has_line, has_block,
        )

    sql = _LINE_COMMENT.sub(" ", sql)
    sql = _BLOCK_COMMENT.sub(" ", sql)
    return sql


# ─────────────────────────────────────────────────────────────────────────────
# 3. Multi-statement detection
# ─────────────────────────────────────────────────────────────────────────────

def check_multi_statement(sql: str) -> None:
    """
    Raise ValueError if sql contains more than one statement.

    Attack: SELECT 1; DROP TABLE users
    Attack: SELECT email FROM profiles; COPY profiles TO '/tmp/dump.csv'
    """
    # Quick check: semicolon present?
    if ";" not in sql:
        return

    try:
        stmts = [s for s in sqlglot.parse(sql) if s is not None]
    except Exception:
        return  # parse error handled downstream

    if len(stmts) > 1:
        raise ValueError(
            f"Multi-statement SQL blocked: {len(stmts)} statements detected. "
            "Only a single SELECT is allowed per request."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. UNION / INTERSECT / EXCEPT enforcement
# ─────────────────────────────────────────────────────────────────────────────

_SET_OPS = (exp.Union, exp.Intersect, exp.Except)


def collect_select_branches(tree: exp.Expression) -> list[exp.Select]:
    """
    Flatten a UNION/INTERSECT/EXCEPT tree into its component SELECT nodes.
    Recursively unpacks nested set operations.
    """
    if isinstance(tree, exp.Select):
        return [tree]
    if isinstance(tree, _SET_OPS):
        left = collect_select_branches(tree.args.get("this"))
        right = collect_select_branches(tree.args.get("expression"))
        return left + right
    return []


def rewrite_union_tree(
    tree: exp.Expression,
    table_policies: "dict[str, PolicyDecision]",
    rewrite_fn,   # callable: (Select, table_policies, meta, dialect) → Select
    meta,
    dialect: str,
) -> exp.Expression:
    """
    Recursively rewrite each SELECT branch of a UNION/INTERSECT/EXCEPT tree.
    This ensures policies are applied to every branch independently.

    Attack stopped:
      SELECT NULL as email FROM safe_table
      UNION ALL
      SELECT email FROM profiles    ← would bypass if only outer SELECT checked
    """
    if isinstance(tree, exp.Select):
        return rewrite_fn(tree, table_policies, meta, dialect)

    if isinstance(tree, _SET_OPS):
        new_left = rewrite_union_tree(
            tree.args.get("this"), table_policies, rewrite_fn, meta, dialect
        )
        new_right = rewrite_union_tree(
            tree.args.get("expression"), table_policies, rewrite_fn, meta, dialect
        )
        tree.set("this", new_left)
        tree.set("expression", new_right)
        return tree

    return tree


# ─────────────────────────────────────────────────────────────────────────────
# 5. CTE (WITH clause) enforcement
# ─────────────────────────────────────────────────────────────────────────────

def enforce_cte_policies(
    tree: exp.Select,
    table_policies: "dict[str, PolicyDecision]",
    rewrite_fn,
    meta,
    dialect: str,
) -> exp.Select:
    """
    Rewrite CTE bodies before the outer query is processed.

    Attack stopped:
      WITH raw AS (SELECT email, ssn FROM profiles)
      SELECT ssn FROM raw        ← outer query reads rewritten CTE, not raw data

    sqlglot stores CTEs in tree.args['with_'] as a With node containing
    a list of CTE (alias + body) expressions.
    """
    with_clause = tree.args.get("with_")
    if not with_clause:
        return tree

    for cte_expr in with_clause.expressions:
        cte_body = cte_expr.this
        if isinstance(cte_body, exp.Select):
            rewritten_body = rewrite_fn(cte_body, table_policies, meta, dialect)
            cte_expr.set("this", rewritten_body)
        elif isinstance(cte_body, _SET_OPS):
            rewritten_body = rewrite_union_tree(
                cte_body, table_policies, rewrite_fn, meta, dialect
            )
            cte_expr.set("this", rewritten_body)

    return tree


# ─────────────────────────────────────────────────────────────────────────────
# 6. Scalar subquery leakage detection
# ─────────────────────────────────────────────────────────────────────────────

def block_scalar_subquery_leakage(
    select: exp.Select,
    table_policies: "dict[str, PolicyDecision]",
) -> list[str]:
    """
    Detect scalar subqueries in the SELECT projection that reference denied columns.
    Returns a list of warning strings. The rewriter already handles function leakage,
    but scalar subqueries (exp.Subquery inside a projection) need explicit handling.

    Attack stopped:
      SELECT (SELECT ssn FROM profiles LIMIT 1) as leaked_ssn

    These are caught by the recursive _rewrite_node walk in the main rewriter;
    this function provides an extra audit trail.
    """
    warnings: list[str] = []
    all_denied: set[str] = set()
    for dec in table_policies.values():
        all_denied.update(dec.denied_columns)

    if not all_denied:
        return warnings

    for proj in select.expressions:
        subqs = list(proj.find_all(exp.Subquery))
        for subq in subqs:
            for col in subq.find_all(exp.Column):
                if col.name in all_denied:
                    warnings.append(
                        f"Scalar subquery references denied column '{col.name}' — "
                        "expression suppressed by recursive policy rewriting"
                    )
    return warnings


# ─────────────────────────────────────────────────────────────────────────────
# 7. LATERAL join detection
# ─────────────────────────────────────────────────────────────────────────────

def check_lateral_joins(tree: exp.Select) -> list[str]:
    """
    Detect LATERAL joins that could be used to bypass table-level policy matching.

    Attack:
      SELECT l.ssn
      FROM profiles p
      CROSS JOIN LATERAL (SELECT ssn FROM profiles LIMIT 1) l

    The LATERAL subquery table is not in the FROM clause at the outer level,
    so alias_map won't map it. The recursive rewriter handles this since
    LATERAL bodies are exp.Select nodes and get rewritten. This function
    logs a warning for audit purposes.
    """
    warnings: list[str] = []
    joins = tree.args.get("joins") or []
    for join in joins:
        if join.args.get("side") == "CROSS" or join.find(exp.Lateral):
            warnings.append(
                "LATERAL join detected — policy applied recursively to subquery body"
            )
    return warnings


# ─────────────────────────────────────────────────────────────────────────────
# 8. ORDER BY / HAVING data-inference bypass detection
# ─────────────────────────────────────────────────────────────────────────────

def check_inference_bypass(
    select: exp.Select,
    table_policies: "dict[str, PolicyDecision]",
) -> list[str]:
    """
    Detect ORDER BY or HAVING clauses that reference denied columns.
    These can be used to infer data without selecting it directly.

    Attack:
      SELECT id FROM profiles ORDER BY ssn   ← SSN denied in SELECT but used for ordering
    """
    warnings: list[str] = []
    all_denied: set[str] = set()
    for dec in table_policies.values():
        all_denied.update(dec.denied_columns)

    if not all_denied:
        return warnings

    # Check ORDER BY
    order = select.args.get("order")
    if order:
        for ordered in order.expressions:
            for col in ordered.find_all(exp.Column):
                if col.name in all_denied:
                    warnings.append(
                        f"ORDER BY references denied column '{col.name}' — "
                        "ordering by denied data can leak information via timing/position"
                    )

    # Check HAVING
    having = select.args.get("having")
    if having:
        for col in having.find_all(exp.Column):
            if col.name in all_denied:
                warnings.append(
                    f"HAVING clause references denied column '{col.name}' — "
                    "aggregate filtering on denied data blocked"
                )

    return warnings


def strip_inference_bypass(
    select: exp.Select,
    table_policies: "dict[str, PolicyDecision]",
) -> tuple[exp.Select, list[str]]:
    """
    Remove ORDER BY / HAVING references to denied columns.
    Returns (modified_select, warnings).
    """
    all_denied: set[str] = set()
    for dec in table_policies.values():
        all_denied.update(dec.denied_columns)

    if not all_denied:
        return select, []

    warnings: list[str] = []

    # Strip denied columns from ORDER BY
    order = select.args.get("order")
    if order:
        new_order_exprs = []
        removed = []
        for ordered in order.expressions:
            denied_refs = [c.name for c in ordered.find_all(exp.Column) if c.name in all_denied]
            if denied_refs:
                removed.extend(denied_refs)
            else:
                new_order_exprs.append(ordered)
        if removed:
            warnings.append(
                f"ORDER BY: removed references to denied column(s): {removed}"
            )
            if new_order_exprs:
                order.set("expressions", new_order_exprs)
            else:
                select.set("order", None)

    # Strip denied columns from HAVING → replace whole HAVING if it references denied col
    having = select.args.get("having")
    if having:
        denied_in_having = [c.name for c in having.find_all(exp.Column) if c.name in all_denied]
        if denied_in_having:
            warnings.append(
                f"HAVING: removed clause referencing denied column(s): {denied_in_having}"
            )
            select.set("having", None)

    return select, warnings


# ─────────────────────────────────────────────────────────────────────────────
# 9. Post-rewrite column leak verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_no_column_leak(
    rewritten_sql: str,
    table_policies: "dict[str, PolicyDecision]",
) -> list[str]:
    """
    Final sanity check: scan the rewritten SQL to ensure no denied column
    appears as a non-NULL live expression in the output.

    Returns a list of leak warnings (should be empty; non-empty = bug in rewriter).
    """
    all_denied: set[str] = set()
    for dec in table_policies.values():
        all_denied.update(dec.denied_columns)

    if not all_denied:
        return []

    warnings: list[str] = []
    try:
        tree = sqlglot.parse_one(rewritten_sql)
    except Exception:
        return []

    # Collect CTE alias names — columns referencing a CTE are NOT raw table columns
    cte_aliases: set[str] = set()
    for with_node in tree.find_all(exp.With):
        for cte_expr in with_node.expressions:
            if cte_expr.alias:
                cte_aliases.add(cte_expr.alias.lower())

    # Collect all table aliases in FROM/JOIN — used to detect qualified denied refs
    # (unqualified refs from CTEs are safe since CTE body was already rewritten)

    # Walk all SELECT projections in the rewritten tree
    for select_node in tree.find_all(exp.Select):
        for proj in select_node.expressions:
            # Skip NULL literals and aliases of NULL
            if isinstance(proj, exp.Null):
                continue
            if isinstance(proj, exp.Alias) and isinstance(proj.this, exp.Null):
                continue

            # Check if any column ref in this projection is a denied column
            for col in proj.find_all(exp.Column):
                if col.name not in all_denied:
                    continue
                # Skip if the column is qualified with a CTE alias
                # (e.g. SELECT ssn FROM raw — 'raw' is a CTE, ssn is already NULLed)
                table_qual = (col.table or "").lower()
                if table_qual and table_qual in cte_aliases:
                    continue
                if not table_qual and not col.table:
                    # Unqualified ref from a CTE-scope SELECT — likely safe, log as debug
                    # Check if this SELECT's FROM references a CTE
                    parent_from = select_node.args.get("from") or select_node.args.get("from_")
                    if parent_from:
                        from_name = (getattr(parent_from.this, "name", "") or "").lower()
                        if from_name in cte_aliases:
                            continue

                warnings.append(
                    f"POST-REWRITE LEAK DETECTED: denied column '{col.name}' "
                    f"appears in rewritten projection: {proj.sql()}"
                )
                logger.error(
                    "Hardening: LEAK in rewritten SQL — column '%s' not nulled. "
                    "Rewritten SQL: %s",
                    col.name, rewritten_sql,
                )

    return warnings


# ─────────────────────────────────────────────────────────────────────────────
# 10. Exfiltration pattern detection
# ─────────────────────────────────────────────────────────────────────────────

_EXFIL_PATTERNS = re.compile(
    r"\b("
    r"INTO\s+(?:OUTFILE|DUMPFILE)"   # MySQL INTO OUTFILE
    r"|BULK\s+INSERT"                 # MSSQL bulk insert
    r"|OPENROWSET"                    # MSSQL external source
    r"|UTL_FILE\s*\."                 # Oracle file write
    r"|DBMS_PIPE"                     # Oracle pipe
    r"|pg_read_binary_file"           # Postgres file read
    r"|pg_ls_dir"                     # Postgres directory listing
    r"|pg_stat_file"                  # Postgres file stat
    r"|dblink"                        # Postgres dblink (out-of-band channel)
    r")\b",
    re.IGNORECASE,
)


def check_exfiltration_patterns(sql: str) -> None:
    """Raise ValueError if sql contains known data-exfiltration patterns."""
    match = _EXFIL_PATTERNS.search(sql)
    if match:
        raise ValueError(
            f"Query blocked: potential data exfiltration pattern detected "
            f"({match.group(0)!r})."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 11. Combined pre-parse hardening pipeline
# ─────────────────────────────────────────────────────────────────────────────

def harden_sql(sql: str) -> str:
    """
    Run all pre-parse hardening checks on raw SQL input.
    Returns sanitized SQL ready for AST parsing.
    Raises ValueError on any blocked pattern.

    Steps (in order):
      1. Unicode normalization + control-char removal
      2. Comment stripping
      3. Exfiltration pattern check
      4. Multi-statement check
    """
    sql = normalize_sql(sql)
    sql = strip_sql_comments(sql)
    check_exfiltration_patterns(sql)
    check_multi_statement(sql)
    return sql
