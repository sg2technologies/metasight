# models/policy.py
from pydantic import BaseModel
from typing import Dict, List, Optional

class ColumnPolicy(BaseModel):
    action: str  # "allow" | "mask" | "tokenize" | "deny"
    roles_exempt: List[str] = ["admin"]  # these roles see raw data

class RowFilter(BaseModel):
    column: str
    value: str  # e.g. region = user's region

class Policy(BaseModel):
    resource: str          # e.g. "customers"
    classification: str    # "PII" | "FINANCIAL" | "PUBLIC"
    columns: Dict[str, ColumnPolicy]
    row_filters: Optional[List[RowFilter]] = []
    source_type: str       # "postgres" | "mysql" | "mongodb"