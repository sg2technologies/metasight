"""
Smart PII-aware masking that preserves format while hiding sensitive data.
Masking is deterministic for the same input value.

Masking levels:
  full    — maximum protection (default, analyst role)
  partial — shows a bit more data (manager role)
  raw     — no masking (admin role, or roles_exempt)
"""
from __future__ import annotations
import re

# Role → masking level mapping
_ROLE_MASK_LEVEL: dict[str, str] = {
    "admin":   "raw",
    "manager": "partial",
    "analyst": "full",
    "viewer":  "full",
}

# Field name patterns to PII types
_FIELD_PII_MAP: dict[str, str] = {
    r"email|mail": "EMAIL",
    r"phone|mobile|tele": "PHONE",
    r"ssn|social_security|socialsecurity": "SSN",
    r"credit_card|card_num|cardnum|cc_": "CREDIT_CARD",
    r"name|fullname|full_name|first_name|last_name": "NAME",
    r"address": "ADDRESS",
    r"ip_addr|ip_address": "IP_ADDRESS",
    r"amount|balance|salary": "AMOUNT",
    r"account|acc_num": "ACCOUNT",
    r"govt_id|national_id|passport": "GOVT_ID",
    r"secret|password|passwd|token|key": "SECRET",
    r"dob|birth": "DOB",
}

def infer_pii_type(col_name: str) -> str | None:
    """Guess the PII type of a column based on its name."""
    name = col_name.lower()
    for pattern, pii_type in _FIELD_PII_MAP.items():
        if re.search(pattern, name):
            return pii_type
    return None

def infer_tags(col_name: str) -> list[str]:
    """Return a list of tags (e.g. ['PII']) that likely apply to this column name."""
    pii_type = infer_pii_type(col_name)
    if pii_type:
        return ["PII", pii_type]
    return []


def masking_level_for_role(role: str, role_levels: dict | None = None) -> str:
    """Return 'raw', 'partial', or 'full' for the given role.

    role_levels — optional override dict from SystemSettings (masking.role_levels).
    Falls back to built-in defaults if not provided.
    """
    levels = role_levels or _ROLE_MASK_LEVEL
    return levels.get(role, "full")


# ── Partial masking helpers ────────────────────────────────────────────────────

def _partial_email(value: str) -> str:
    """jo**@example.com (show first 2 chars of local)"""
    try:
        local, domain = value.split("@", 1)
        shown = local[:2] if len(local) >= 2 else local
        return shown + "*" * max(0, len(local) - 2) + "@" + domain
    except Exception:
        return value[:3] + "***"

def _partial_phone(value: str) -> str:
    """Show first 3 + last 4 digits."""
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 7:
        return digits[:3] + "-***-" + digits[-4:]
    return value

def _partial_ssn(value: str) -> str:
    """***-xx-1234 (show last 4)"""
    digits = re.sub(r"\D", "", value)
    return "***-**-" + digits[-4:] if len(digits) >= 4 else value

def _partial_card(value: str) -> str:
    """****-****-xxxx-1234 (show last 8 digits)"""
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 8:
        return "****-****-" + digits[-8:-4] + "-" + digits[-4:]
    return "****-" + value[-4:]

def _partial_name(value: str) -> str:
    """John D*** (full first name, initial of last)"""
    parts = str(value).split()
    if len(parts) >= 2:
        return parts[0] + " " + parts[-1][0] + "***"
    return parts[0] if parts else value


def _partial_generic(value: str) -> str:
    """Show first 2 chars and last 2 chars, hide the middle"""
    s = str(value)
    if not s:
        return s
    if len(s) > 4:
        return s[:2] + "***" + s[-2:]
    return s[:1] + "***" if len(s) > 1 else "***"


# ── Per-type masking functions ─────────────────────────────────────────────────

def _mask_email(value: str) -> str:
    """j***@example.com  (show first char + domain)"""
    try:
        local, domain = value.split("@", 1)
        if local:
            return local[0] + "***@" + domain
        return "***@" + domain
    except Exception:
        return "********"


def _mask_phone(value: str) -> str:
    """+1-***-***-1234  (show last 4 digits)"""
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        last4 = digits[-4:]
        # Reconstruct with original prefix style
        prefix = re.sub(r"\d", "*", value[:-4]) if len(value) > 4 else "***-***-"
        return prefix + last4
    return "***-***-" + digits


def _mask_ssn(value: str) -> str:
    """***-**-1234  (show last 4)"""
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return "***-**-" + digits[-4:]
    return "***-**-" + digits


def _mask_credit_card(value: str) -> str:
    """****-****-****-1234  (show last 4)"""
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return "****-****-****-" + digits[-4:]
    return "****-****-****-" + digits


def _mask_name(value: str) -> str:
    """J*** D***  (show first char of each word)"""
    parts = str(value).split()
    masked = []
    for part in parts:
        if part:
            masked.append(part[0] + "***")
        else:
            masked.append(part)
    return " ".join(masked) if masked else "********"


def _mask_address(value: str) -> str:
    """*** Main St, ***  (hash street number, mask city)"""
    # Replace leading digits with ***
    masked = re.sub(r"^\d+", "***", str(value))
    # Mask text after the last comma (city/state)
    if "," in masked:
        parts = masked.rsplit(",", 1)
        return parts[0] + ", ***"
    return masked


def _mask_ip_address(value: str) -> str:
    """192.168.*.*  (mask last 2 octets)"""
    parts = str(value).split(".")
    if len(parts) == 4:
        return ".".join(parts[:2]) + ".*.*"
    # IPv6 or unusual format — mask last half
    return str(value)[:len(str(value))//2] + "***"


def _mask_amount(value: str) -> str:
    """***.** (fully hidden)"""
    return "***.**"


def _mask_account(value: str) -> str:
    """***1234  (show last 4)"""
    s = str(value)
    if len(s) >= 4:
        return "***" + s[-4:]
    return "***" + s


def _mask_govt_id(value: str) -> str:
    """***1234  (show last 4)"""
    digits = re.sub(r"\D", "", str(value))
    if len(digits) >= 4:
        return "***" + digits[-4:]
    s = str(value)
    if len(s) >= 4:
        return "***" + s[-4:]
    return "***" + s


def _mask_secret(_value: str) -> str:
    return "********"


def _mask_dob(value: str) -> str:
    """****/**, ****  (hide day/year)"""
    # Try to detect YYYY-MM-DD or MM/DD/YYYY
    s = str(value)
    # YYYY-MM-DD
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return "****-" + m.group(2) + "-**"
    # MM/DD/YYYY
    m2 = re.match(r"(\d{1,2})/(\d{1,2})/(\d{4})", s)
    if m2:
        return m2.group(1) + "/**/****"
    return "****/**, ****"


def _mask_location(_value: str) -> str:
    return "****, ****"


def _mask_sensitive(_value: str) -> str:
    return "********"


def _mask_generic(_value: str) -> str:
    return "********"


# ── Dispatch table ─────────────────────────────────────────────────────────────

_MASK_FN = {
    "EMAIL":       _mask_email,
    "PHONE":       _mask_phone,
    "SSN":         _mask_ssn,
    "CREDIT_CARD": _mask_credit_card,
    "NAME":        _mask_name,
    "ADDRESS":     _mask_address,
    "IP_ADDRESS":  _mask_ip_address,
    "AMOUNT":      _mask_amount,
    "ACCOUNT":     _mask_account,
    "GOVT_ID":     _mask_govt_id,
    "TAX_ID":      _mask_account,      # same pattern
    "SECRET":      _mask_secret,
    "DOB":         _mask_dob,
    "LOCATION":    _mask_location,
    "SENSITIVE":   _mask_sensitive,
}


# ── Partial dispatch table ──────────────────────────────────────────────────────

_PARTIAL_MASK_FN = {
    "EMAIL":       _partial_email,
    "PHONE":       _partial_phone,
    "SSN":         _partial_ssn,
    "CREDIT_CARD": _partial_card,
    "NAME":        _partial_name,
    # For other types, fall through to full mask (no partial variant)
}


def mask_value(value, pii_type: str | None = None, level: str = "full") -> str:
    """
    Mask a single value according to its PII type and masking level.

    level:
      'raw'     — return value unchanged
      'partial' — show partial data (manager-friendly)
      'full'    — maximum protection (default)
    """
    if value is None:
        return None  # type: ignore[return-value]
    if level == "raw":
        return value if isinstance(value, str) else str(value)
    str_value = str(value)
    if not str_value:
        return str_value
    pii_upper = (pii_type or "").upper()
    if level == "partial":
        fn = _PARTIAL_MASK_FN.get(pii_upper) or _MASK_FN.get(pii_upper, _partial_generic)
    else:
        fn = _MASK_FN.get(pii_upper, _mask_generic)
    return fn(str_value)


def mask_row(
    row_dict: dict,
    masked_columns: list[str],
    column_pii_map: dict[str, str | None],
    level: str = "full",
) -> dict:
    """
    Apply the right masking per column to a result row dict.

    Args:
        row_dict: Mutable dict representing a single row {col_name: value}.
        masked_columns: Column names that require masking.
        column_pii_map: {col_name: pii_type} — used to choose the masking strategy.
        level: 'full', 'partial', or 'raw'.

    Returns:
        The same dict with masked values in-place.
    """
    result = dict(row_dict)
    for col in masked_columns:
        if col in result:
            pii_type = column_pii_map.get(col)
            result[col] = mask_value(result[col], pii_type, level=level)
    return result
