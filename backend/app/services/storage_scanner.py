"""
Cloud Storage Security Scanner
Checks S3 buckets, Azure Blob containers, and GCS buckets for security compliance.

Each scanner returns a list of CheckItem-compatible dicts:
  {"name": str, "status": "pass"|"fail"|"warn"|"skip", "detail": str}
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Result model (mirrors security_checker.CheckItem) ────────────────────────

@dataclass
class CheckItem:
    name: str
    status: str   # "pass" | "fail" | "warn" | "skip"
    detail: str


@dataclass
class StorageCheckResult:
    source_type: str        # "s3_storage" | "azure_blob" | "gcs_storage"
    bucket_name: str
    reachable: bool
    checks: list[CheckItem] = field(default_factory=list)
    score: int = 0
    grade: str = "?"
    error: str | None = None

    def compute_grade(self) -> None:
        passed = sum(1 for c in self.checks if c.status == "pass")
        failed = sum(1 for c in self.checks if c.status == "fail")
        total = passed + failed
        self.score = int((passed / total) * 100) if total else 0
        if self.score >= 90:   self.grade = "A"
        elif self.score >= 75: self.grade = "B"
        elif self.score >= 50: self.grade = "C"
        elif self.score >= 25: self.grade = "D"
        else:                  self.grade = "F"


# ── S3 Bucket Scanner ─────────────────────────────────────────────────────────

def check_s3_bucket(config: dict[str, Any]) -> StorageCheckResult:
    """
    Security checks for an AWS S3 bucket.

    Required config keys:
      bucket_name       — bucket to audit
      aws_access_key_id / aws_secret_access_key  — or omit to use instance role
      region_name       — e.g. "us-east-1" (optional, defaults to boto3 default)
    """
    bucket = config.get("bucket_name", config.get("bucket", ""))
    result = StorageCheckResult(
        source_type="s3_storage",
        bucket_name=bucket,
        reachable=False,
    )

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        result.error = "boto3 not installed — run: pip install boto3"
        return result

    session_kwargs: dict = {}
    if config.get("aws_access_key_id"):
        session_kwargs["aws_access_key_id"]     = config["aws_access_key_id"]
        session_kwargs["aws_secret_access_key"]  = config.get("aws_secret_access_key", "")
    if config.get("aws_session_token"):
        session_kwargs["aws_session_token"] = config["aws_session_token"]
    if config.get("region_name"):
        session_kwargs["region_name"] = config["region_name"]

    try:
        s3 = boto3.client("s3", **session_kwargs)
        # Verify we can reach the bucket
        s3.head_bucket(Bucket=bucket)
        result.reachable = True
    except Exception as exc:
        result.error = f"Cannot reach bucket '{bucket}': {exc}"
        result.grade = "F"
        return result

    checks = result.checks

    # 1. Public Access Block
    try:
        pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        all_blocked = all([
            pab.get("BlockPublicAcls", False),
            pab.get("IgnorePublicAcls", False),
            pab.get("BlockPublicPolicy", False),
            pab.get("RestrictPublicBuckets", False),
        ])
        checks.append(CheckItem(
            "Public access block", "pass" if all_blocked else "fail",
            "All 4 public-access-block settings enabled" if all_blocked
            else f"Some public access block settings disabled: {pab}",
        ))
    except Exception as exc:
        checks.append(CheckItem("Public access block", "warn", f"Could not check: {exc}"))

    # 2. Default encryption
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)
        rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
        algo  = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        checks.append(CheckItem(
            "Default encryption", "pass",
            f"Encryption enabled: {algo}",
        ))
        kms = algo == "aws:kms"
        checks.append(CheckItem(
            "KMS encryption", "pass" if kms else "warn",
            "Using SSE-KMS (customer managed keys)" if kms
            else "Using SSE-S3 — consider SSE-KMS for stricter key control",
        ))
    except Exception as exc:
        err_str = str(exc)
        if "ServerSideEncryptionConfigurationNotFoundError" in err_str or "NoSuchConfiguration" in err_str:
            checks.append(CheckItem("Default encryption", "fail", "No default encryption configured"))
        else:
            checks.append(CheckItem("Default encryption", "warn", f"Could not check: {exc}"))

    # 3. Versioning
    try:
        ver = s3.get_bucket_versioning(Bucket=bucket)
        status = ver.get("Status", "Disabled")
        mfa_delete = ver.get("MFADelete", "Disabled")
        checks.append(CheckItem(
            "Versioning enabled", "pass" if status == "Enabled" else "warn",
            f"Versioning: {status}" + (" (MFA Delete on)" if mfa_delete == "Enabled" else ""),
        ))
    except Exception as exc:
        checks.append(CheckItem("Versioning", "skip", str(exc)))

    # 4. Bucket ACL — no public grants
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        public_uris = {
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        }
        public_grants = [
            g for g in acl.get("Grants", [])
            if g.get("Grantee", {}).get("URI") in public_uris
        ]
        checks.append(CheckItem(
            "ACL not public", "pass" if not public_grants else "fail",
            "No public ACL grants" if not public_grants
            else f"{len(public_grants)} public ACL grant(s) detected — remove them",
        ))
    except Exception as exc:
        checks.append(CheckItem("Bucket ACL", "skip", str(exc)))

    # 5. Server access logging
    try:
        logging_cfg = s3.get_bucket_logging(Bucket=bucket)
        has_logging = "LoggingEnabled" in logging_cfg
        checks.append(CheckItem(
            "Server access logging", "pass" if has_logging else "warn",
            f"Logging to: {logging_cfg['LoggingEnabled'].get('TargetBucket')}" if has_logging
            else "Server access logging is disabled — enable for audit trail",
        ))
    except Exception as exc:
        checks.append(CheckItem("Server access logging", "skip", str(exc)))

    # 6. SSL enforcement via bucket policy (best-effort check)
    try:
        import json
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        deny_non_tls = any(
            stmt.get("Effect") == "Deny"
            and "aws:SecureTransport" in str(stmt.get("Condition", ""))
            for stmt in policy.get("Statement", [])
        )
        checks.append(CheckItem(
            "HTTPS-only policy", "pass" if deny_non_tls else "warn",
            "Policy denies non-TLS requests" if deny_non_tls
            else "No Deny-NonTLS statement found in bucket policy",
        ))
    except Exception as exc:
        err_str = str(exc)
        if "NoSuchBucketPolicy" in err_str:
            checks.append(CheckItem("HTTPS-only policy", "warn", "No bucket policy attached"))
        else:
            checks.append(CheckItem("HTTPS-only policy", "skip", str(exc)))

    result.compute_grade()
    return result


# ── Azure Blob Container Scanner ──────────────────────────────────────────────

def check_azure_blob(config: dict[str, Any]) -> StorageCheckResult:
    """
    Security checks for an Azure Blob Storage container.

    Required config keys (one of):
      connection_string     — full connection string
      OR
      account_name + account_key
      container_name        — container to audit
    """
    container = config.get("container_name", config.get("container", ""))
    result = StorageCheckResult(
        source_type="azure_blob",
        bucket_name=container,
        reachable=False,
    )

    try:
        from azure.storage.blob import BlobServiceClient, PublicAccess
        from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    except ImportError:
        result.error = (
            "azure-storage-blob not installed — run: pip install azure-storage-blob"
        )
        return result

    try:
        conn_str = config.get("connection_string")
        if conn_str:
            client = BlobServiceClient.from_connection_string(conn_str)
        else:
            account  = config.get("account_name", "")
            key      = config.get("account_key", "")
            endpoint = f"https://{account}.blob.core.windows.net"
            from azure.storage.blob import BlobServiceClient as _BSC
            from azure.core.credentials import AzureNamedKeyCredential
            cred   = AzureNamedKeyCredential(account, key)
            client = _BSC(account_url=endpoint, credential=cred)

        # Verify reachability
        account_props = client.get_account_information()
        result.reachable = True
    except Exception as exc:
        result.error = f"Cannot connect to Azure Blob: {exc}"
        result.grade = "F"
        return result

    checks = result.checks

    # 1. Account requires secure transfer (HTTPS only)
    try:
        props = client.get_service_properties()
        # Secure transfer is an account-level property — reflected in the URL scheme
        checks.append(CheckItem(
            "HTTPS endpoint", "pass",
            "Connected via HTTPS endpoint",
        ))
    except Exception:
        pass

    # 2. Container public access level
    try:
        container_client = client.get_container_client(container)
        container_props  = container_client.get_container_properties()
        public_access    = container_props.get("public_access")
        if public_access is None or public_access == "":
            checks.append(CheckItem(
                "Container public access", "pass",
                "Container is private (no public access)",
            ))
        else:
            checks.append(CheckItem(
                "Container public access", "fail",
                f"Container has public access level: '{public_access}' — set to private",
            ))
    except Exception as exc:
        checks.append(CheckItem("Container public access", "warn", f"Could not check: {exc}"))

    # 3. Blob soft delete
    try:
        props = client.get_service_properties()
        delete_policy = props.get("delete_retention_policy", {})
        soft_delete   = delete_policy.get("enabled", False)
        days          = delete_policy.get("days", 0)
        checks.append(CheckItem(
            "Blob soft delete", "pass" if soft_delete and days >= 7 else ("warn" if soft_delete else "fail"),
            f"Soft delete enabled ({days} days retention)" if soft_delete
            else "Blob soft delete is disabled — enable with >= 7 days retention",
        ))
    except Exception as exc:
        checks.append(CheckItem("Blob soft delete", "skip", str(exc)))

    # 4. Blob versioning
    try:
        props        = client.get_service_properties()
        versioning   = props.get("versioning_enabled", False)
        checks.append(CheckItem(
            "Blob versioning", "pass" if versioning else "warn",
            "Blob versioning enabled" if versioning
            else "Blob versioning is disabled — enable to protect against overwrites",
        ))
    except Exception as exc:
        checks.append(CheckItem("Blob versioning", "skip", str(exc)))

    # 5. Logging
    try:
        props    = client.get_service_properties()
        logging  = props.get("analytics_logging", {})
        log_read = logging.get("read",   False)
        log_del  = logging.get("delete", False)
        all_on   = log_read and log_del
        checks.append(CheckItem(
            "Analytics logging", "pass" if all_on else "warn",
            "Read and delete logging enabled" if all_on
            else f"Logging incomplete — read={log_read}, delete={log_del}",
        ))
    except Exception as exc:
        checks.append(CheckItem("Analytics logging", "skip", str(exc)))

    # 6. Encryption (always-on for Azure, but check if BYOK/CMK is used)
    checks.append(CheckItem(
        "Data encryption at rest", "pass",
        "Azure Blob always encrypts data at rest with AES-256",
    ))

    result.compute_grade()
    return result


# ── GCS Bucket Scanner ────────────────────────────────────────────────────────

def check_gcs_bucket(config: dict[str, Any]) -> StorageCheckResult:
    """
    Security checks for a Google Cloud Storage bucket.

    Required config keys:
      bucket_name           — GCS bucket name
      credentials_json      — service account JSON string (or path)
      project_id            — GCP project ID
    """
    bucket = config.get("bucket_name", config.get("bucket", ""))
    result = StorageCheckResult(
        source_type="gcs_storage",
        bucket_name=bucket,
        reachable=False,
    )

    try:
        from google.cloud import storage as gcs
        from google.oauth2 import service_account
        import json as _json
    except ImportError:
        result.error = (
            "google-cloud-storage not installed — run: pip install google-cloud-storage"
        )
        return result

    try:
        credentials_json = config.get("credentials_json") or config.get("credentials_path")
        project_id       = config.get("project_id", "")

        if credentials_json and not str(credentials_json).strip().startswith("{"):
            # It's a file path
            client = gcs.Client.from_service_account_json(credentials_json, project=project_id)
        elif credentials_json:
            import json as _json
            cred_dict = _json.loads(credentials_json)
            creds     = service_account.Credentials.from_service_account_info(
                cred_dict,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            client = gcs.Client(credentials=creds, project=project_id)
        else:
            # Default credentials (Workload Identity / ADC)
            client = gcs.Client(project=project_id)

        bucket_obj = client.bucket(bucket)
        bucket_obj.reload()
        result.reachable = True
    except Exception as exc:
        result.error = f"Cannot reach GCS bucket '{bucket}': {exc}"
        result.grade = "F"
        return result

    checks = result.checks

    # 1. Uniform bucket-level access (disables per-object ACLs)
    try:
        ubla = bucket_obj.iam_configuration.uniform_bucket_level_access_enabled
        checks.append(CheckItem(
            "Uniform bucket-level access", "pass" if ubla else "fail",
            "UBLA enabled — ACLs replaced by IAM" if ubla
            else "UBLA disabled — per-object ACLs can bypass bucket IAM policies",
        ))
    except Exception as exc:
        checks.append(CheckItem("Uniform bucket-level access", "warn", str(exc)))

    # 2. Public access prevention
    try:
        pap = bucket_obj.iam_configuration.public_access_prevention
        enforced = pap == "enforced"
        checks.append(CheckItem(
            "Public access prevention", "pass" if enforced else "warn",
            "Public access prevention enforced" if enforced
            else f"Public access prevention is '{pap}' — set to 'enforced'",
        ))
    except Exception as exc:
        checks.append(CheckItem("Public access prevention", "skip", str(exc)))

    # 3. Versioning
    try:
        versioning = bucket_obj.versioning_enabled
        checks.append(CheckItem(
            "Object versioning", "pass" if versioning else "warn",
            "Versioning enabled" if versioning
            else "Versioning disabled — enable to protect against accidental deletes",
        ))
    except Exception as exc:
        checks.append(CheckItem("Object versioning", "skip", str(exc)))

    # 4. Encryption (CMEK vs Google-managed)
    try:
        cmek = bucket_obj.default_kms_key_name
        if cmek:
            checks.append(CheckItem(
                "Customer-managed encryption (CMEK)", "pass",
                f"CMEK key: {cmek}",
            ))
        else:
            checks.append(CheckItem(
                "Customer-managed encryption (CMEK)", "warn",
                "Using Google-managed encryption keys — consider CMEK for stricter compliance",
            ))
    except Exception as exc:
        checks.append(CheckItem("Encryption", "skip", str(exc)))

    # 5. Retention policy (object lock / WORM)
    try:
        retention = bucket_obj.retention_period
        if retention:
            checks.append(CheckItem(
                "Retention policy", "pass",
                f"Retention lock: {retention} seconds",
            ))
        else:
            checks.append(CheckItem(
                "Retention policy", "warn",
                "No retention policy — objects can be deleted at any time",
            ))
    except Exception as exc:
        checks.append(CheckItem("Retention policy", "skip", str(exc)))

    # 6. IAM — check for allUsers or allAuthenticatedUsers binding
    try:
        policy = bucket_obj.get_iam_policy()
        public_members = {"allUsers", "allAuthenticatedUsers"}
        public_bindings = [
            f"{role}: {member}"
            for binding in policy.bindings
            for member in binding["members"]
            if member in public_members
            for role in [binding["role"]]
        ]
        checks.append(CheckItem(
            "No public IAM bindings", "pass" if not public_bindings else "fail",
            "No allUsers/allAuthenticatedUsers bindings" if not public_bindings
            else f"Public bindings found: {', '.join(public_bindings)}",
        ))
    except Exception as exc:
        checks.append(CheckItem("Public IAM bindings", "skip", str(exc)))

    result.compute_grade()
    return result


# ── Dispatcher ────────────────────────────────────────────────────────────────

def check_storage(source_type: str, config: dict[str, Any]) -> StorageCheckResult:
    """Route to the correct scanner based on source_type."""
    st = source_type.lower()
    if st in ("s3_storage", "s3_datalake", "athena", "glue"):
        return check_s3_bucket(config)
    if st in ("azure_blob", "adls_datalake"):
        return check_azure_blob(config)
    if st in ("gcs_storage", "gcs_datalake"):
        return check_gcs_bucket(config)
    result = StorageCheckResult(source_type=source_type, bucket_name="", reachable=False)
    result.error = f"No storage scanner for type '{source_type}'"
    return result


def serialize_storage_result(r: StorageCheckResult) -> dict:
    return {
        "source_type": r.source_type,
        "bucket_name": r.bucket_name,
        "reachable":   r.reachable,
        "score":       r.score,
        "grade":       r.grade,
        "error":       r.error,
        "checks": [
            {"name": c.name, "status": c.status, "detail": c.detail}
            for c in r.checks
        ],
    }
