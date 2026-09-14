"""
SQL query rewriter — multi-table policy enforcement, recursive subquery protection,
function leakage detection, DDL/DML blocking, row-level filters, and bypass resistance.
Uses sqlglot for AST-level rewriting (dialect-agnostic).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import sqlglot
from sqlglot import exp

from app.rewriters.hardening import (
    harden_sql,
    enforce_cte_policies,
    rewrite_union_tree,
    strip_inference_bypass,
    verify_no_column_leak,
    check_lateral_joins,
    block_scalar_subquery_leakage,
)

if TYPE_CHECKING:
    from app.services.policy_engine import PolicyDecision

logger = logging.getLogger(__name__)

# ── DDL/DML blocklist ────────────────────────────────────────────────────────

_BLOCKED_TYPES = (
    exp.Insert, exp.Update, exp.Delete, exp.Create, exp.Drop, exp.Alter,
    exp.Grant, exp.Revoke, exp.Use, exp.TruncateTable,
)

_BLOCKED_PATTERN = re.compile(
    r"\b("
    r"INSERT\s+INTO"
    r"|UPDATE\s+\w"
    r"|DELETE\s+FROM"
    r"|CREATE\s+(TABLE|FUNCTION|VIEW|INDEX|SCHEMA|DATABASE|ROLE|USER)"
    r"|DROP\s+(TABLE|VIEW|FUNCTION|SCHEMA|DATABASE|INDEX)"
    r"|ALTER\s+(TABLE|COLUMN|SCHEMA|DATABASE)"
    r"|TRUNCATE"
    r"|GRANT"
    r"|REVOKE"
    r"|COPY\s"
    r"|DO\s*\$"
    r"|EXEC(?:UTE)?\s"
    r"|xp_cmdshell"
    r"|pg_read_file"
    r"|pg_write_file"
    r"|lo_import"
    r"|lo_export"
    r")\b",
    re.IGNORECASE,
)


def _guard_sql(sql: str) -> None:
    """Raise ValueError if sql contains blocked DDL/DML patterns."""
    # Fast regex check
    if _BLOCKED_PATTERN.search(sql):
        raise ValueError(
            "Query blocked: DDL/DML/dangerous statements are not allowed."
        )
    # AST check
    try:
        stmts = sqlglot.parse(sql)
    except Exception:
        return  # parse errors handled downstream
    for stmt in stmts:
        if isinstance(stmt, _BLOCKED_TYPES):
            raise ValueError(
                f"Query blocked: {type(stmt).__name__} statements are not allowed."
            )
        # `SELECT ... INTO <table>` (Postgres table-creating SELECT, MSSQL SELECT INTO)
        # parses as exp.Select — it slips past both the regex above and the
        # isinstance() check — but sqlglot re-serializes it as a real
        # `CREATE TABLE ... AS SELECT ...`, which the target DB executes as DDL.
        # Reject any statement carrying an INTO clause, anywhere in its tree
        # (covers CTEs/UNION branches too), before it ever reaches rewriting.
        if stmt is not None and list(stmt.find_all(exp.Into)):
            raise ValueError(
                "Query blocked: 'SELECT ... INTO' (table-creating SELECT) is not allowed."
            )


# ── RewriteMeta ──────────────────────────────────────────────────────────────

@dataclass
class RewriteMeta:
    """Tracks what the rewriter did — returned alongside rewritten SQL."""
    # col_name → pii_type (or None) for columns that will be masked post-execution
    masked_columns: dict[str, str | None] = field(default_factory=dict)
    # col_name → original_col for tokenized columns
    tokenized_columns: dict[str, str] = field(default_factory=dict)
    # columns set to NULL in the rewritten SQL
    denied_columns: list[str] = field(default_factory=list)
    row_filter_applied: bool = False
    tables_affected: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ── Helper: resolve column action ────────────────────────────────────────────

def _resolve_action(
    table_qualifier: str | None,
    col_name: str,
    alias_map: dict[str, "PolicyDecision"],
) -> tuple[str, str | None]:
    """
    Return (action, pii_type) for a column reference.
    action ∈ {"deny", "mask", "tokenize", "allow"}
    """
    # Try to find the policy from the table qualifier
    policies_to_check: list["PolicyDecision"] = []

    if table_qualifier and table_qualifier in alias_map:
        policies_to_check = [alias_map[table_qualifier]]
    elif not table_qualifier:
        # Unqualified column — check all tables
        policies_to_check = list(alias_map.values())

    col_name_lower = col_name.lower()

    for policy in policies_to_check:
        if policy.is_admin_exempt:
            continue
        
        denied_cols_lower = {c.lower() for c in policy.denied_columns}
        if col_name_lower in denied_cols_lower:
            orig_key = next((k for k in policy.column_pii_map if k.lower() == col_name_lower), col_name)
            return "deny", policy.column_pii_map.get(orig_key)

        masked_cols_lower = {c.lower() for c in policy.masked_columns}
        if col_name_lower in masked_cols_lower:
            orig_key = next((k for k in policy.column_pii_map if k.lower() == col_name_lower), col_name)
            return "mask", policy.column_pii_map.get(orig_key)

        tok_cols_lower = {c.lower() for c in policy.tokenized_columns}
        if col_name_lower in tok_cols_lower:
            orig_key = next((k for k in policy.column_pii_map if k.lower() == col_name_lower), col_name)
            return "tokenize", policy.column_pii_map.get(orig_key)

    return "allow", None


# ── Helper: most-restrictive action ─────────────────────────────────────────

_ACTION_RANK = {"deny": 3, "mask": 2, "tokenize": 1, "allow": 0}


def _most_restrictive(a: str, b: str) -> str:
    return a if _ACTION_RANK.get(a, 0) >= _ACTION_RANK.get(b, 0) else b


# ── Helper: collect all Column refs in an expression ─────────────────────────

def _collect_columns(expr: exp.Expression) -> list[exp.Column]:
    return list(expr.find_all(exp.Column))


# ── Core rewriter ─────────────────────────────────────────────────────────────

class SQLRewriter:
    """
    Rewrites SQL to enforce data-governance policies.

    New interface (multi-table):
        rewrite(sql, table_policies, dialect) -> (rewritten_sql, RewriteMeta)

    Legacy interface (single-table, backward-compat):
        rewrite(query, policy, user, known_columns, dialect) -> rewritten_sql
    """

    # ── Public: new multi-table interface ─────────────────────────────────────

    def rewrite_with_meta(
        self,
        sql: str,
        table_policies: dict[str, "PolicyDecision"],  # table_name → PolicyDecision
        dialect: str = "postgres",
    ) -> tuple[str, RewriteMeta]:
        """
        Rewrite *sql* applying per-table policies with full bypass resistance.

        Returns (rewritten_sql, RewriteMeta).

        Pipeline:
          1.  Pre-parse hardening (unicode normalize, comment strip, multi-stmt, exfil)
          2.  DDL/DML AST blocklist
          3.  CTE (WITH clause) body rewriting
          4.  UNION/INTERSECT/EXCEPT branch-wise rewriting
          5.  Recursive subquery protection (bottom-up AST walk)
          6.  SELECT * expansion per table
          7.  Column deny/mask/tokenize + function leakage detection
          8.  ORDER BY / HAVING inference bypass removal
          9.  Row filter injection (all tables, AND-combined)
          10. LATERAL join audit
          11. Post-rewrite column leak verification
        """
        # ── Step 1: Pre-parse hardening ───────────────────────────────────────
        sql = harden_sql(sql)

        # ── Step 2: DDL/DML AST guard ─────────────────────────────────────────
        _guard_sql(sql)

        meta = RewriteMeta()
        meta.tables_affected = list(table_policies.keys())

        # ── Step 3: Parse ─────────────────────────────────────────────────────
        try:
            tree = sqlglot.parse_one(sql)
        except Exception as exc:
            raise ValueError(f"Cannot parse SQL: {exc}") from exc

        # ── Step 4: Handle UNION/INTERSECT/EXCEPT ─────────────────────────────
        from app.rewriters.hardening import _SET_OPS
        if isinstance(tree, _SET_OPS):
            tree = rewrite_union_tree(
                tree, table_policies, self._rewrite_node, meta, dialect
            )
            rewritten = tree.sql(dialect=dialect)
            # Post-rewrite verification
            leak_warnings = verify_no_column_leak(rewritten, table_policies)
            if leak_warnings:
                meta.warnings.extend(leak_warnings)
                logger.error("Hardening: post-rewrite leaks: %s", leak_warnings)
            return rewritten, meta

        if not isinstance(tree, exp.Select):
            raise ValueError(
                f"Only SELECT statements are allowed. Got: {type(tree).__name__}"
            )

        # Note: CTE body rewriting is handled automatically by the recursive
        # _rewrite_node walk (sqlglot's walk() descends into with_ CTE nodes).
        # enforce_cte_policies() is kept in hardening.py for cases where a caller
        # wants explicit CTE-first processing; here we skip to avoid double-processing.

        # ── Step 6: LATERAL join audit ────────────────────────────────────────
        lateral_warns = check_lateral_joins(tree)
        if lateral_warns:
            meta.warnings.extend(lateral_warns)

        # ── Step 7: Scalar subquery audit ─────────────────────────────────────
        scalar_warns = block_scalar_subquery_leakage(tree, table_policies)
        if scalar_warns:
            meta.warnings.extend(scalar_warns)

        # ── Step 8: Main recursive rewrite ────────────────────────────────────
        tree = self._rewrite_node(tree, table_policies, meta, dialect)

        # ── Step 9: ORDER BY / HAVING inference bypass ────────────────────────
        tree, infer_warns = strip_inference_bypass(tree, table_policies)
        if infer_warns:
            meta.warnings.extend(infer_warns)

        # ── Step 10: Serialize ────────────────────────────────────────────────
        # Use dialect-specific serialization. For Oracle, quoting is stripped
        # downstream in _oracle_qualify_tables so Oracle's own case-folding and
        # synonym resolution work correctly. Using the oracle dialect here is
        # important so FETCH FIRST / FETCH NEXT clauses are preserved as-is —
        # the base dialect wrongly converts them to LIMIT, causing ORA-00933.
        rewritten = tree.sql(dialect=dialect)

        # ── Step 11: Post-rewrite leak verification ───────────────────────────
        leak_warnings = verify_no_column_leak(rewritten, table_policies)
        if leak_warnings:
            meta.warnings.extend(leak_warnings)
            logger.error("Hardening: post-rewrite leaks detected: %s", leak_warnings)

        return rewritten, meta

    # ── Public: legacy single-table interface (backward-compat) ──────────────

    def rewrite(
        self,
        query: str,
        policy,           # accepts dict OR PolicyDecision
        user: dict | None = None,
        known_columns: list[str] | None = None,
        dialect: str = "postgres",
    ) -> str:
        """
        Legacy single-table rewrite. Returns rewritten SQL string.
        Delegates to rewrite_with_meta internally.
        """
        # Always run the DDL/DML + INTO-clause guard, even on the old dict-policy
        # fallback path below, which historically skipped it entirely.
        harden_sql_query = harden_sql(query)
        _guard_sql(harden_sql_query)

        is_decision = hasattr(policy, "denied_columns")

        if is_decision:
            # Wrap single PolicyDecision as table_policies dict
            # Use resource name as table key, also register empty string for unqualified refs
            table_name = getattr(policy, "resource", "__default__")
            table_policies = {table_name: policy, "": policy}
            try:
                result_sql, _ = self.rewrite_with_meta(query, table_policies, dialect)
                return result_sql
            except Exception:
                pass  # Fall through to old path on error

        # ── Old path (dict policy or fallback) ───────────────────────────────
        if user is None:
            user = {}

        is_decision = hasattr(policy, "denied_columns")
        if is_decision:
            denied_cols = list(policy.denied_columns)
            masked_cols = list(policy.masked_columns)
            row_filters = list(policy.row_filter_conditions)
            kc = known_columns or list(policy.known_columns)
        else:
            denied_cols = []
            masked_cols = []
            raw_filters = policy.get("row_filters", [])
            row_filters = self._substitute_legacy_filters(raw_filters, user)
            col_policies = policy.get("columns", {})
            for col_name, pol in col_policies.items():
                action = pol.get("action", "allow")
                exempt = pol.get("roles_exempt", ["admin"])
                if user.get("role") not in exempt:
                    if action == "deny":
                        denied_cols.append(col_name)
                    elif action == "mask":
                        masked_cols.append(col_name)
            kc = known_columns

        try:
            tree = sqlglot.parse_one(harden_sql_query)
        except Exception as exc:
            raise ValueError(f"Cannot parse SQL: {exc}") from exc

        if not isinstance(tree, exp.Select):
            raise ValueError(
                f"Only SELECT statements are allowed. Got: {type(tree).__name__}"
            )

        if kc:
            tree = self._expand_star(tree, kc, dialect)

        tree = self._apply_column_controls_v2(
            tree, denied_cols, masked_cols, user,
            policy if not is_decision else None,
        )
        tree = self._inject_row_filters_legacy(tree, row_filters)

        return tree.sql(dialect=dialect)

    def get_tables(self, sql: str) -> list[str]:
        """Extract table names from SQL (for policy lookup)."""
        try:
            tree = sqlglot.parse_one(sql)
        except Exception:
            return []
        tables = []
        for tbl in tree.find_all(exp.Table):
            name = tbl.name
            if name:
                tables.append(name)
        return list(dict.fromkeys(tables))  # deduplicated, insertion order

    # ── Private: new multi-table rewriter internals ───────────────────────────

    def _rewrite_node(
        self,
        select: exp.Select,
        table_policies: dict[str, "PolicyDecision"],
        meta: RewriteMeta,
        dialect: str,
    ) -> exp.Select:
        """
        Recursively rewrite a SELECT node and all nested subqueries (bottom-up).
        """
        # First, recurse into subqueries (bottom-up ensures innermost rewrites first)
        for node in select.walk():
            if node is select:
                continue
            if isinstance(node, exp.Select):
                self._rewrite_node(node, table_policies, meta, dialect)

        # Build alias map for THIS SELECT's FROM/JOIN tables
        alias_map = self._build_alias_map(select, table_policies)

        if not alias_map:
            return select  # No known tables — pass through

        # Expand SELECT * per table
        select = self._expand_stars(select, alias_map, dialect)

        # Rewrite projections (column deny/mask/tokenize + function leakage)
        select = self._rewrite_projections(select, alias_map, meta)

        # Inject row filters for all tables
        select = self._inject_row_filters_multi(select, alias_map, meta)

        return select

    def _build_alias_map(
        self,
        select: exp.Select,
        table_policies: dict[str, "PolicyDecision"],
    ) -> dict[str, "PolicyDecision"]:
        """
        Maps alias (or table name) → PolicyDecision for tables in THIS SELECT.
        Only processes direct FROM/JOIN tables, not subqueries.
        """
        alias_map: dict[str, "PolicyDecision"] = {}

        # sqlglot v29 uses "from_" key (not "from")
        from_clause = select.args.get("from") or select.args.get("from_")
        joins = select.args.get("joins") or []

        sources = []
        if from_clause:
            sources.append(from_clause.this if hasattr(from_clause, "this") else from_clause)
        for join in joins:
            sources.append(join.this)

        for source in sources:
            if isinstance(source, exp.Table):
                tbl_name = source.name
                alias = source.alias or tbl_name
                # Lookup policy by table name (case-insensitive)
                policy = (
                    table_policies.get(tbl_name)
                    or table_policies.get(tbl_name.lower())
                    or table_policies.get(tbl_name.upper())
                )
                if policy:
                    alias_map[alias] = policy
                    if alias != tbl_name:
                        alias_map[tbl_name] = policy

        return alias_map

    def _expand_stars(
        self,
        select: exp.Select,
        alias_map: dict[str, "PolicyDecision"],
        dialect: str = "postgres",
    ) -> exp.Select:
        """Replace SELECT * and SELECT t.* with explicit column lists."""
        is_oracle = dialect.lower() in ("oracle", "oracledb")

        # For Oracle, never expand SELECT * in SQL.
        # Oracle resolves the star natively and returns all columns.
        # Column-level masking/denial is applied post-fetch in the query gateway,
        # so expanding stars here is both unnecessary and harmful: it generates
        # a quoted column list (e.g. "COLUMN_NAME") that can collide with the
        # wrong schema when the user or rewriter targets a different schema object.
        if is_oracle:
            return select

        new_exprs = []
        changed = False

        for proj in select.expressions:
            # Bare star: SELECT *
            if isinstance(proj, exp.Star):
                expanded_cols = []
                for policy in alias_map.values():
                    if policy.known_columns:
                        for col in policy.known_columns:
                            expanded_cols.append(exp.column(exp.Identifier(this=col, quoted=True)))
                if expanded_cols:
                    new_exprs.extend(expanded_cols)
                    changed = True
                else:
                    new_exprs.append(proj)
                continue

            # Qualified star: SELECT t.*
            if isinstance(proj, exp.Column) and isinstance(proj.this, exp.Star):
                qualifier = proj.table
                policy = alias_map.get(qualifier)
                if policy and policy.known_columns:
                    for col in policy.known_columns:
                        new_exprs.append(exp.column(exp.Identifier(this=col, quoted=True), table=qualifier))
                    changed = True
                else:
                    new_exprs.append(proj)
                continue

            new_exprs.append(proj)

        if changed:
            select.set("expressions", new_exprs)
        return select

    def _rewrite_projections(
        self,
        select: exp.Select,
        alias_map: dict[str, "PolicyDecision"],
        meta: RewriteMeta,
    ) -> exp.Select:
        """
        Rewrite each projection expression:
        - If the expression is a plain Column: apply deny/mask/tokenize
        - If the expression contains sensitive Column refs (function leakage):
          apply most-restrictive action to the ENTIRE expression
        """
        new_exprs = []

        for proj in select.expressions:
            # Extract alias if present
            alias_name: str | None = None
            inner_expr = proj
            if isinstance(proj, exp.Alias):
                alias_name = proj.alias
                inner_expr = proj.this

            # Collect all column references in this projection
            col_refs = _collect_columns(inner_expr)

            if not col_refs:
                new_exprs.append(proj)
                continue

            # Determine most-restrictive action across all column refs
            overall_action = "allow"
            primary_col_name: str | None = None
            primary_pii: str | None = None

            for col_ref in col_refs:
                tbl_qualifier = col_ref.table or None
                col_name = col_ref.name
                action, pii_type = _resolve_action(tbl_qualifier, col_name, alias_map)
                if _ACTION_RANK.get(action, 0) > _ACTION_RANK.get(overall_action, 0):
                    overall_action = action
                    primary_col_name = col_name
                    primary_pii = pii_type

            # Output alias: prefer explicit alias, then single-col name, then generate
            out_alias = alias_name or (
                col_refs[0].name if len(col_refs) == 1 else None
            )

            if overall_action == "deny":
                # Null out the entire expression
                null_expr = exp.alias_(exp.null(), out_alias) if out_alias else exp.null()
                new_exprs.append(null_expr)
                if out_alias and out_alias not in meta.denied_columns:
                    meta.denied_columns.append(out_alias)
                if len(col_refs) > 1 and primary_col_name:
                    meta.warnings.append(
                        f"Expression containing '{primary_col_name}' was suppressed "
                        f"(function leakage protection)"
                    )

            elif overall_action == "mask":
                # If this is a plain column reference → keep raw, mask post-execution
                # If this is a function/expression wrapping the column → null it out
                # (we can't reliably identify the result column for post-execution masking)
                is_plain_col = isinstance(inner_expr, exp.Column)
                if is_plain_col:
                    new_exprs.append(proj)
                    col_key = out_alias or (primary_col_name or "")
                    if col_key and col_key not in meta.masked_columns:
                        meta.masked_columns[col_key] = primary_pii
                else:
                    # Function leakage: null out the entire expression
                    null_expr = exp.alias_(exp.null(), out_alias) if out_alias else exp.null()
                    new_exprs.append(null_expr)
                    if out_alias and out_alias not in meta.denied_columns:
                        meta.denied_columns.append(out_alias)
                    meta.warnings.append(
                        f"Expression containing masked column '{primary_col_name}' "
                        f"was suppressed to prevent function leakage"
                    )

            elif overall_action == "tokenize":
                # Keep raw — tokenization happens post-execution
                new_exprs.append(proj)
                col_key = out_alias or (primary_col_name or "")
                if col_key and col_key not in meta.tokenized_columns:
                    meta.tokenized_columns[col_key] = primary_col_name or col_key

            else:
                # allow
                new_exprs.append(proj)

        select.set("expressions", new_exprs)
        return select

    def _inject_row_filters_multi(
        self,
        select: exp.Select,
        alias_map: dict[str, "PolicyDecision"],
        meta: RewriteMeta,
    ) -> exp.Select:
        """
        Inject row filters from ALL tables in alias_map as AND-combined WHERE conditions.
        Conditions are qualified with the table alias.
        """
        conditions: list[exp.Expression] = []

        # Deduplicate: use (alias, column, operator, value) as key
        seen: set[tuple] = set()

        for alias, policy in alias_map.items():
            # Avoid duplicate processing when both alias and table_name map to same policy
            policy_id = id(policy)
            for rf in policy.row_filter_conditions:
                col = rf.get("column", "")
                operator = rf.get("operator", "=")
                value = rf.get("value", "")
                if not col:
                    continue
                key = (policy_id, col, operator, value)
                if key in seen:
                    continue
                seen.add(key)

                # Use the first alias found for this policy
                qualifying_alias = alias

                col_expr = exp.column(col, table=qualifying_alias)
                cond = self._build_condition(col_expr, operator, value)
                if cond is not None:
                    conditions.append(cond)
                    meta.row_filter_applied = True

        if not conditions:
            return select

        combined = conditions[0]
        for c in conditions[1:]:
            combined = exp.And(this=combined, expression=c)

        where = select.args.get("where")
        if where:
            select.set(
                "where",
                exp.Where(this=exp.And(this=where.this, expression=combined)),
            )
        else:
            select.set("where", exp.Where(this=combined))

        return select

    @staticmethod
    def _build_condition(
        col_expr: exp.Expression,
        operator: str,
        value: str,
    ) -> exp.Expression | None:
        """Build a comparison expression from operator string."""
        val_expr = exp.Literal.string(value)
        op_map = {
            "=":  exp.EQ,
            "!=": exp.NEQ,
            "<>": exp.NEQ,
            ">":  exp.GT,
            ">=": exp.GTE,
            "<":  exp.LT,
            "<=": exp.LTE,
        }
        cls = op_map.get(operator)
        if cls:
            return cls(this=col_expr, expression=val_expr)
        # IN operator
        if operator.upper() == "IN":
            items = [exp.Literal.string(v.strip()) for v in value.split(",")]
            return exp.In(this=col_expr, expressions=items)
        # LIKE
        if operator.upper() == "LIKE":
            return exp.Like(this=col_expr, expression=val_expr)
        # Fallback
        return exp.EQ(this=col_expr, expression=val_expr)

    # ── Private: legacy helpers (backward-compat) ─────────────────────────────

    def _expand_star(self, tree, columns: list[str], dialect: str = "postgres"):
        has_star = any(isinstance(e, exp.Star) for e in tree.expressions)
        if not has_star:
            return tree
        is_oracle = dialect.lower() == "oracle"
        tree.set("expressions", [exp.column(exp.Identifier(this=c.upper() if is_oracle else c, quoted=True)) for c in columns])
        return tree

    def _apply_column_controls_v2(
        self,
        tree,
        denied_cols: list[str],
        masked_cols: list[str],
        user: dict,
        legacy_policy: dict | None,
    ):
        denied_set = set(denied_cols)
        legacy_col_policies = {}
        if legacy_policy is not None:
            legacy_col_policies = legacy_policy.get("columns", {})

        new_exprs = []
        for proj in tree.expressions:
            col_name = self._expr_col_name(proj)

            if col_name and legacy_col_policies:
                pol = legacy_col_policies.get(col_name)
                if pol:
                    action = pol.get("action", "allow")
                    exempt_roles = pol.get("roles_exempt", ["admin"])
                    if user.get("role") not in exempt_roles:
                        if action == "deny":
                            new_exprs.append(exp.alias_(exp.null(), col_name))
                            continue
                        elif action == "mask":
                            # Pass through raw — post-execution masking via mask_row() handles this
                            new_exprs.append(proj)
                            continue
                        elif action == "tokenize":
                            new_exprs.append(proj)
                            continue
                    new_exprs.append(proj)
                    continue

            if col_name and col_name in denied_set:
                new_exprs.append(exp.alias_(exp.null(), col_name))
                continue

            new_exprs.append(proj)

        tree.set("expressions", new_exprs)
        return tree

    def _inject_row_filters_legacy(self, tree, row_filters: list[dict]):
        conditions = []
        for rf in row_filters:
            col = rf.get("column", "")
            operator = rf.get("operator", "=")
            value = rf.get("value", "")
            if not col:
                continue
            cond = self._build_condition(exp.column(col), operator, value)
            if cond:
                conditions.append(cond)

        if not conditions:
            return tree

        combined = conditions[0]
        for c in conditions[1:]:
            combined = exp.And(this=combined, expression=c)

        where = tree.args.get("where")
        if where:
            tree.set(
                "where",
                exp.Where(this=exp.And(this=where.this, expression=combined)),
            )
        else:
            tree.set("where", exp.Where(this=combined))
        return tree

    @staticmethod
    def _expr_col_name(proj) -> str | None:
        if isinstance(proj, exp.Alias):
            return proj.alias
        elif isinstance(proj, exp.Column):
            return proj.name
        return None

    @staticmethod
    def _substitute_legacy_filters(raw_filters: list, user: dict) -> list[dict]:
        resolved = []
        for rf in raw_filters:
            raw_val = rf.get("value", "")
            val = (
                str(raw_val)
                .replace("{user.region}", user.get("region", ""))
                .replace("{user.email}", user.get("sub", ""))
                .replace("{user.tenant_id}", str(user.get("tenant_id", "")))
                .replace("{user.role}", user.get("role", ""))
                .replace("{user.department}", user.get("department", ""))
            )
            resolved.append({
                "column": rf.get("column", ""),
                "operator": rf.get("operator", "="),
                "value": val,
            })
        return resolved

    # ── Legacy private helpers (kept for backward compat) ─────────────────────

    def _apply_row_filter(self, tree, policy: dict, user: dict):
        filters = self._substitute_legacy_filters(policy.get("row_filters", []), user)
        return self._inject_row_filters_legacy(tree, filters)

    def _apply_column_controls(self, tree, policy: dict, user: dict):
        return self._apply_column_controls_v2(tree, [], [], user, policy)
