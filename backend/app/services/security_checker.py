"""
Security Posture Checker
Connects to each registered data source and verifies the gateway user's
privilege level. Returns a structured report per source.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.core.encryption import aes_cipher
from app.ingestion.native_scanner import _build_url

logger = logging.getLogger(__name__)


# ── Result model ──────────────────────────────────────────────────────────────

@dataclass
class CheckItem:
    name: str
    status: str          # "pass" | "fail" | "warn" | "skip"
    detail: str


@dataclass
class SecurityCheckResult:
    source_id: int
    source_name: str
    connector_type: str
    reachable: bool
    checks: list[CheckItem] = field(default_factory=list)
    score: int = 0        # 0-100
    grade: str = "?"      # A / B / C / D / F
    error: str | None = None

    def _compute_grade(self) -> None:
        passed  = sum(1 for c in self.checks if c.status == "pass")
        failed  = sum(1 for c in self.checks if c.status == "fail")
        total   = passed + failed
        self.score = int((passed / total) * 100) if total else 0
        if self.score >= 90:   self.grade = "A"
        elif self.score >= 75: self.grade = "B"
        elif self.score >= 50: self.grade = "C"
        elif self.score >= 25: self.grade = "D"
        else:                  self.grade = "F"


# ── Per-connector privilege queries ───────────────────────────────────────────

def _check_postgres(conn, checks: list[CheckItem]) -> None:
    # Is superuser? (Using pg_roles for better compatibility)
    row = conn.execute(text(
        "SELECT rolsuper, rolcreatedb, rolcreaterole "
        "FROM pg_roles WHERE rolname = current_user"
    )).fetchone()
    if row:
        checks.append(CheckItem(
            "Not superuser", "pass" if not row[0] else "fail",
            "Current user is superuser — give minimal privileges" if row[0] else "OK"
        ))
        checks.append(CheckItem(
            "No CREATE DB", "pass" if not row[1] else "fail",
            "User can create databases" if row[1] else "OK"
        ))
        checks.append(CheckItem(
            "No CREATE ROLE", "pass" if not row[2] else "fail",
            "User can create roles" if row[2] else "OK"
        ))

    # Can INSERT into a system table? (proxy for write access)
    try:
        ins = conn.execute(text(
            "SELECT has_table_privilege(current_user, 'pg_class', 'INSERT')"
        )).scalar()
        checks.append(CheckItem(
            "No system-table write", "pass" if not ins else "warn",
            "Has INSERT on pg_class" if ins else "OK"
        ))
    except Exception:
        pass

    # SSL in use?
    try:
        ssl_on = conn.execute(text("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")).scalar()
        checks.append(CheckItem(
            "SSL/TLS connection", "pass" if ssl_on else "warn",
            "Not encrypted in transit" if not ssl_on else "OK"
        ))
    except Exception:
        checks.append(CheckItem("SSL/TLS connection", "skip", "Could not determine"))

    # Check for write grants on public schema
    try:
        has_insert = conn.execute(text(
            "SELECT has_schema_privilege(current_user, 'public', 'CREATE')"
        )).scalar()
        checks.append(CheckItem(
            "No schema CREATE", "pass" if not has_insert else "fail",
            "Can create objects in public schema" if has_insert else "OK"
        ))
    except Exception:
        pass


def _check_mysql(conn, checks: list[CheckItem]) -> None:
    try:
        rows = conn.execute(text("SHOW GRANTS FOR CURRENT_USER()")).fetchall()
        grants_text = " ".join(str(r[0]).upper() for r in rows)

        danger_privs = ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
                        "GRANT", "SUPER", "ALL PRIVILEGES"]
        for priv in danger_privs:
            has_it = priv in grants_text and "INFORMATION_SCHEMA" not in grants_text
            checks.append(CheckItem(
                f"No {priv}", "fail" if has_it else "pass",
                f"User has {priv} privilege" if has_it else "OK"
            ))
    except Exception as e:
        checks.append(CheckItem("Grants check", "skip", str(e)))

    # SSL check via status variable
    try:
        row = conn.execute(text("SHOW STATUS LIKE 'Ssl_cipher'")).fetchone()
        ssl_on = row and row[1] and len(row[1]) > 0
        checks.append(CheckItem(
            "SSL/TLS connection", "pass" if ssl_on else "warn",
            "Not encrypted in transit" if not ssl_on else f"Cipher: {row[1]}"
        ))
    except Exception:
        checks.append(CheckItem("SSL/TLS connection", "skip", "Could not determine"))


def _check_mssql(conn, checks: list[CheckItem]) -> None:
    try:
        row = conn.execute(text(
            "SELECT IS_SRVROLEMEMBER('sysadmin') AS sa, "
            "       IS_SRVROLEMEMBER('db_owner') AS dbo, "
            "       IS_SRVROLEMEMBER('securityadmin') AS sec"
        )).fetchone()
        if row:
            checks.append(CheckItem("Not sysadmin", "fail" if row[0] else "pass",
                "User is sysadmin" if row[0] else "OK"))
            checks.append(CheckItem("Not db_owner", "fail" if row[1] else "pass",
                "User is db_owner" if row[1] else "OK"))
            checks.append(CheckItem("Not securityadmin", "fail" if row[2] else "pass",
                "User is securityadmin" if row[2] else "OK"))
    except Exception as e:
        checks.append(CheckItem("Role check", "skip", str(e)))

    # Encrypted connection
    try:
        enc = conn.execute(text(
            "SELECT encrypt_option FROM sys.dm_exec_connections "
            "WHERE session_id = @@SPID"
        )).scalar()
        checks.append(CheckItem(
            "SSL/TLS connection", "pass" if enc else "warn",
            "Connection not encrypted" if not enc else "OK"
        ))
    except Exception:
        checks.append(CheckItem("SSL/TLS connection", "skip", "Could not determine"))


def _check_oracle(conn, checks: list[CheckItem]) -> None:
    danger_privs = ["DBA", "CREATE ANY TABLE", "DROP ANY TABLE",
                    "INSERT ANY TABLE", "UPDATE ANY TABLE", "DELETE ANY TABLE"]
    try:
        rows = conn.execute(text("SELECT PRIVILEGE FROM SESSION_PRIVS")).fetchall()
        held = {r[0].upper() for r in rows}
        for priv in danger_privs:
            has_it = priv in held
            checks.append(CheckItem(f"No {priv}", "fail" if has_it else "pass",
                f"User holds {priv}" if has_it else "OK"))
    except Exception as e:
        checks.append(CheckItem("Privilege check", "skip", str(e)))

    # Encryption
    try:
        enc = conn.execute(text(
            "SELECT NETWORK_SERVICE_BANNER FROM V$SESSION_CONNECT_INFO "
            "WHERE SID = SYS_CONTEXT('USERENV', 'SID') "
            "AND NETWORK_SERVICE_BANNER LIKE '%Encryption%'"
        )).fetchone()
        checks.append(CheckItem(
            "Network encryption", "pass" if enc else "warn",
            "No network encryption detected" if not enc else str(enc[0])
        ))
    except Exception:
        checks.append(CheckItem("Network encryption", "skip", "Could not determine"))


def _check_snowflake(conn, checks: list[CheckItem]) -> None:
    try:
        row = conn.execute(text("SELECT CURRENT_ROLE()")).scalar()
        danger_roles = {"ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN"}
        checks.append(CheckItem(
            "Non-privileged role", "fail" if str(row).upper() in danger_roles else "pass",
            f"Using role {row} — switch to a read-only custom role"
            if str(row).upper() in danger_roles else f"Role: {row}"
        ))
    except Exception as e:
        checks.append(CheckItem("Role check", "skip", str(e)))

    # Snowflake always uses TLS
    checks.append(CheckItem("SSL/TLS connection", "pass", "Snowflake enforces TLS by default"))


def _check_bigquery(conn, checks: list[CheckItem]) -> None:
    # BigQuery always uses TLS — check via sqlalchemy driver metadata
    checks.append(CheckItem("SSL/TLS connection", "pass", "BigQuery enforces TLS by default"))
    checks.append(CheckItem(
        "Credential type", "warn",
        "Ensure the service account has only bigquery.dataViewer, not bigquery.admin"
    ))


def _check_mongodb(conn, checks: list[CheckItem]) -> None:
    # MongoDB connections go through pymongo — limited via sqlalchemy dialect
    try:
        result = conn.execute(text("SELECT 1")).scalar()
        checks.append(CheckItem("Connection OK", "pass", "Connected successfully"))
    except Exception:
        pass
    checks.append(CheckItem(
        "Role check", "warn",
        "Verify MongoDB user has only 'read' role, not 'readWrite' or 'dbAdmin'"
    ))
    checks.append(CheckItem(
        "TLS check", "warn",
        "Ensure --tlsMode requireTLS is set on the MongoDB server"
    ))


def _check_generic_sql(conn, checks: list[CheckItem]) -> None:
    """Generic SELECT-1 reachability check for connectors without specific checks."""
    try:
        conn.execute(text("SELECT 1"))
        checks.append(CheckItem("Connection OK", "pass", "Reached the data source"))
    except Exception as e:
        checks.append(CheckItem("Connection OK", "fail", str(e)))
    checks.append(CheckItem(
        "Privilege review", "warn",
        "Manually verify the gateway user has read-only access on this connector type"
    ))


# ── Router ────────────────────────────────────────────────────────────────────

_CHECKER_MAP = {
    "postgres":    _check_postgres,
    "redshift":    _check_postgres,
    "greenplum":   _check_postgres,
    "cockroach":   _check_postgres,
    "timescaledb": _check_postgres,
    "mysql":       _check_mysql,
    "mariadb":     _check_mysql,
    "mssql":       _check_mssql,
    "azuresql":    _check_mssql,
    "oracle":      _check_oracle,
    "snowflake":   _check_snowflake,
    "bigquery":    _check_bigquery,
    "mongodb":     _check_mongodb,
}


# ── Hardening guides ──────────────────────────────────────────────────────────

HARDENING_GUIDES: dict[str, dict[str, Any]] = {
    "postgres": {
        "title": "PostgreSQL / Redshift / Greenplum",
        "network": "Block port 5432 from all IPs except the MetaSight server. Edit pg_hba.conf to restrict to the gateway IP.",
        "steps": [
            {
                "title": "Create a read-only gateway user",
                "sql": (
                    "CREATE USER metasight_gateway WITH PASSWORD '<strong-password>';\n"
                    "GRANT CONNECT ON DATABASE your_db TO metasight_gateway;\n"
                    "GRANT USAGE ON SCHEMA public TO metasight_gateway;\n"
                    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO metasight_gateway;\n"
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA public\n"
                    "  GRANT SELECT ON TABLES TO metasight_gateway;"
                ),
            },
            {
                "title": "Restrict pg_hba.conf (server-side)",
                "sql": (
                    "# In /etc/postgresql/*/main/pg_hba.conf\n"
                    "# Replace 0.0.0.0/0 with your MetaSight server IP:\n"
                    "host  your_db  metasight_gateway  <metasight-ip>/32  scram-sha-256\n"
                    "host  all      all                 0.0.0.0/0          reject"
                ),
            },
            {
                "title": "Force SSL connections",
                "sql": (
                    "# In postgresql.conf:\n"
                    "ssl = on\n"
                    "ssl_cert_file = 'server.crt'\n"
                    "ssl_key_file  = 'server.key'\n\n"
                    "# In pg_hba.conf change 'host' → 'hostssl':\n"
                    "hostssl  your_db  metasight_gateway  <metasight-ip>/32  scram-sha-256"
                ),
            },
            {
                "title": "Revoke all access from human users",
                "sql": (
                    "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM analyst_user;\n"
                    "REVOKE CONNECT ON DATABASE your_db FROM analyst_user;"
                ),
            },
        ],
    },
    "mysql": {
        "title": "MySQL / MariaDB",
        "network": "Bind MySQL to 127.0.0.1 or the MetaSight server IP only. Block port 3306 externally.",
        "steps": [
            {
                "title": "Create a read-only gateway user",
                "sql": (
                    "CREATE USER 'metasight_gateway'@'<metasight-ip>'\n"
                    "  IDENTIFIED WITH caching_sha2_password BY '<strong-password>';\n"
                    "GRANT SELECT ON your_db.* TO 'metasight_gateway'@'<metasight-ip>';\n"
                    "FLUSH PRIVILEGES;"
                ),
            },
            {
                "title": "Require SSL for gateway user",
                "sql": (
                    "ALTER USER 'metasight_gateway'@'<metasight-ip>' REQUIRE SSL;\n"
                    "FLUSH PRIVILEGES;"
                ),
            },
            {
                "title": "Bind MySQL to specific IP (my.cnf)",
                "sql": (
                    "# /etc/mysql/my.cnf\n"
                    "[mysqld]\n"
                    "bind-address = <metasight-ip>"
                ),
            },
            {
                "title": "Revoke all access from other users",
                "sql": (
                    "REVOKE ALL ON your_db.* FROM 'analyst'@'%';\n"
                    "FLUSH PRIVILEGES;"
                ),
            },
        ],
    },
    "mssql": {
        "title": "Microsoft SQL Server / Azure SQL",
        "network": "Use SQL Server Configuration Manager to restrict TCP listener IPs. Use Windows Firewall to block port 1433 except for MetaSight server.",
        "steps": [
            {
                "title": "Create a read-only login and user",
                "sql": (
                    "-- Server level login\n"
                    "CREATE LOGIN metasight_gateway WITH PASSWORD = '<strong-password>';\n\n"
                    "-- Database level user\n"
                    "USE your_db;\n"
                    "CREATE USER metasight_gateway FOR LOGIN metasight_gateway;\n"
                    "ALTER ROLE db_datareader ADD MEMBER metasight_gateway;"
                ),
            },
            {
                "title": "Deny write operations explicitly",
                "sql": (
                    "USE your_db;\n"
                    "DENY INSERT, UPDATE, DELETE, DROP, CREATE, ALTER\n"
                    "  ON SCHEMA::dbo TO metasight_gateway;"
                ),
            },
            {
                "title": "Force encrypted connections",
                "sql": (
                    "-- In SQL Server Configuration Manager:\n"
                    "-- Protocols for MSSQLSERVER > Properties > Force Encryption = Yes\n\n"
                    "-- Or T-SQL:\n"
                    "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\n"
                    "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;"
                ),
            },
        ],
    },
    "oracle": {
        "title": "Oracle Database",
        "network": "Use Oracle Net listener to restrict connections. Use sqlnet.ora VALID_NODE_CHECKING.",
        "steps": [
            {
                "title": "Create a read-only user",
                "sql": (
                    "CREATE USER metasight_gateway IDENTIFIED BY \"<strong-password>\"\n"
                    "  DEFAULT TABLESPACE users TEMPORARY TABLESPACE temp\n"
                    "  QUOTA 0 ON users;\n\n"
                    "GRANT CREATE SESSION TO metasight_gateway;\n"
                    "GRANT SELECT ANY TABLE TO metasight_gateway;  -- or per-table\n"
                    "-- Preferred: per-table grants\n"
                    "GRANT SELECT ON your_schema.your_table TO metasight_gateway;"
                ),
            },
            {
                "title": "Restrict listener access (sqlnet.ora)",
                "sql": (
                    "# $ORACLE_HOME/network/admin/sqlnet.ora\n"
                    "TCP.VALIDNODE_CHECKING = YES\n"
                    "TCP.INVITED_NODES = (<metasight-ip>)\n"
                    "TCP.EXCLUDED_NODES = (*)"
                ),
            },
            {
                "title": "Enable network encryption (sqlnet.ora)",
                "sql": (
                    "# $ORACLE_HOME/network/admin/sqlnet.ora\n"
                    "SQLNET.ENCRYPTION_SERVER = REQUIRED\n"
                    "SQLNET.ENCRYPTION_TYPES_SERVER = (AES256)\n"
                    "SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED"
                ),
            },
        ],
    },
    "snowflake": {
        "title": "Snowflake",
        "network": "Use Snowflake Network Policies to restrict access to the MetaSight server IP.",
        "steps": [
            {
                "title": "Create a read-only role and user",
                "sql": (
                    "-- Create a minimal read-only role\n"
                    "CREATE ROLE metasight_reader;\n"
                    "GRANT USAGE ON DATABASE your_db TO ROLE metasight_reader;\n"
                    "GRANT USAGE ON SCHEMA your_db.public TO ROLE metasight_reader;\n"
                    "GRANT SELECT ON ALL TABLES IN SCHEMA your_db.public TO ROLE metasight_reader;\n\n"
                    "-- Create user with that role\n"
                    "CREATE USER metasight_gateway\n"
                    "  PASSWORD = '<strong-password>'\n"
                    "  DEFAULT_ROLE = metasight_reader\n"
                    "  DEFAULT_WAREHOUSE = your_warehouse;\n"
                    "GRANT ROLE metasight_reader TO USER metasight_gateway;"
                ),
            },
            {
                "title": "Create a Network Policy (IP allowlist)",
                "sql": (
                    "CREATE NETWORK POLICY metasight_policy\n"
                    "  ALLOWED_IP_LIST = ('<metasight-ip>')\n"
                    "  BLOCKED_IP_LIST = ();\n\n"
                    "ALTER USER metasight_gateway\n"
                    "  SET NETWORK_POLICY = metasight_policy;"
                ),
            },
        ],
    },
    "bigquery": {
        "title": "Google BigQuery",
        "network": "Use VPC Service Controls and restrict the service account to your MetaSight server's service account or IP.",
        "steps": [
            {
                "title": "Create a read-only service account",
                "sql": (
                    "# Google Cloud Console or gcloud CLI:\n"
                    "gcloud iam service-accounts create metasight-gateway \\\n"
                    "  --display-name='MetaSight Gateway'\n\n"
                    "# Grant only BigQuery Data Viewer (read-only)\n"
                    "gcloud projects add-iam-policy-binding YOUR_PROJECT \\\n"
                    "  --member='serviceAccount:metasight-gateway@YOUR_PROJECT.iam.gserviceaccount.com' \\\n"
                    "  --role='roles/bigquery.dataViewer'\n\n"
                    "# Also need Job User to run queries\n"
                    "gcloud projects add-iam-policy-binding YOUR_PROJECT \\\n"
                    "  --member='serviceAccount:metasight-gateway@YOUR_PROJECT.iam.gserviceaccount.com' \\\n"
                    "  --role='roles/bigquery.jobUser'"
                ),
            },
            {
                "title": "Enable VPC Service Controls",
                "sql": (
                    "# In Google Cloud Console:\n"
                    "# Security > VPC Service Controls > New Perimeter\n"
                    "# Add BigQuery to services\n"
                    "# Set access levels to MetaSight server IP only"
                ),
            },
        ],
    },
    "mongodb": {
        "title": "MongoDB",
        "network": "Bind MongoDB to the MetaSight server IP only. Use TLS certificates for the connection.",
        "steps": [
            {
                "title": "Create a read-only user",
                "sql": (
                    "// In mongosh:\n"
                    "use admin\n"
                    "db.createUser({\n"
                    "  user: 'metasight_gateway',\n"
                    "  pwd: '<strong-password>',\n"
                    "  roles: [\n"
                    "    { role: 'read', db: 'your_db' }\n"
                    "  ]\n"
                    "})"
                ),
            },
            {
                "title": "Bind to specific IP (mongod.conf)",
                "sql": (
                    "# /etc/mongod.conf\n"
                    "net:\n"
                    "  bindIp: 127.0.0.1,<metasight-ip>\n"
                    "  port: 27017\n"
                    "  tls:\n"
                    "    mode: requireTLS\n"
                    "    certificateKeyFile: /path/to/mongo.pem"
                ),
            },
            {
                "title": "Enable authentication",
                "sql": (
                    "# /etc/mongod.conf\n"
                    "security:\n"
                    "  authorization: enabled"
                ),
            },
        ],
    },
    "cassandra": {
        "title": "Apache Cassandra",
        "network": "Use Cassandra's built-in authentication and restrict rpc_address.",
        "steps": [
            {
                "title": "Create a read-only role",
                "sql": (
                    "-- In cqlsh:\n"
                    "CREATE ROLE metasight_gateway WITH PASSWORD = '<strong-password>'\n"
                    "  AND LOGIN = true;\n\n"
                    "GRANT SELECT ON KEYSPACE your_keyspace TO metasight_gateway;"
                ),
            },
            {
                "title": "Enable authentication (cassandra.yaml)",
                "sql": (
                    "# cassandra.yaml\n"
                    "authenticator: PasswordAuthenticator\n"
                    "authorizer: CassandraAuthorizer\n"
                    "rpc_address: <metasight-ip>"
                ),
            },
        ],
    },
    "elasticsearch": {
        "title": "Elasticsearch / OpenSearch",
        "network": "Use Elasticsearch security (X-Pack) to restrict access. Bind to specific IPs.",
        "steps": [
            {
                "title": "Create a read-only role and user",
                "sql": (
                    "# Via Kibana Dev Tools or API:\n"
                    "PUT /_security/role/metasight_reader\n"
                    "{\n"
                    "  \"indices\": [{\n"
                    "    \"names\": [\"*\"],\n"
                    "    \"privileges\": [\"read\", \"view_index_metadata\"]\n"
                    "  }]\n"
                    "}\n\n"
                    "PUT /_security/user/metasight_gateway\n"
                    "{\n"
                    "  \"password\": \"<strong-password>\",\n"
                    "  \"roles\": [\"metasight_reader\"]\n"
                    "}"
                ),
            },
            {
                "title": "Bind to specific IP (elasticsearch.yml)",
                "sql": (
                    "# elasticsearch.yml\n"
                    "network.host: <metasight-ip>\n"
                    "xpack.security.enabled: true\n"
                    "xpack.security.transport.ssl.enabled: true\n"
                    "xpack.security.http.ssl.enabled: true"
                ),
            },
        ],
    },
    # Generic fallback for all other types
    "_default": {
        "title": "General Hardening Principles",
        "network": "Block direct access to the database port from all IPs except the MetaSight server.",
        "steps": [
            {
                "title": "Create a dedicated read-only gateway user",
                "sql": (
                    "-- Create a user with SELECT-only permissions.\n"
                    "-- Do not use root/admin/superuser credentials in MetaSight.\n"
                    "-- Grant only the minimum privileges needed for reading."
                ),
            },
            {
                "title": "Restrict network access",
                "sql": (
                    "# Allow only the MetaSight server IP to connect on the DB port.\n"
                    "# Use OS-level firewall (iptables, ufw, Windows Firewall, security groups)."
                ),
            },
            {
                "title": "Enable TLS/SSL",
                "sql": (
                    "# Enable TLS encryption on the database server.\n"
                    "# Configure the MetaSight data source to require SSL."
                ),
            },
        ],
    },
}


def get_hardening_guide(connector_type: str) -> dict:
    return HARDENING_GUIDES.get(connector_type, HARDENING_GUIDES["_default"])


# ── Storage source security checks ────────────────────────────────────────────

_STORAGE_TYPES = {
    "s3_storage", "s3_datalake", "athena", "glue",
    "azure_blob", "adls_datalake",
    "gcs_storage", "gcs_datalake",
}


def is_storage_source(connector_type: str) -> bool:
    return connector_type.lower() in _STORAGE_TYPES


def check_source_security_storage(source, db: Session) -> SecurityCheckResult:
    """
    Run storage-specific security checks (S3, Azure Blob, GCS).
    Wraps the storage_scanner result into a SecurityCheckResult.
    """
    from app.services.storage_scanner import check_storage, StorageCheckResult

    result = SecurityCheckResult(
        source_id=source.id,
        source_name=source.name,
        connector_type=source.type,
        reachable=False,
    )

    try:
        config = {
            k: aes_cipher.decrypt(v) if isinstance(v, str) else v
            for k, v in (source.encrypted_config or {}).items()
        }
    except Exception as exc:
        result.error = f"Credential decryption failed: {exc}"
        result.grade = "?"
        return result

    storage_result = check_storage(source.type, config)
    result.reachable = storage_result.reachable
    result.score     = storage_result.score
    result.grade     = storage_result.grade
    result.error     = storage_result.error
    result.checks    = [
        CheckItem(name=c.name, status=c.status, detail=c.detail)
        for c in storage_result.checks
    ]
    return result


# ── Active DB hardening enforcement ──────────────────────────────────────────

@dataclass
class HardeningStepResult:
    title: str
    status: str    # "applied" | "skipped" | "manual" | "error"
    detail: str


@dataclass
class HardeningResult:
    source_id: int
    source_name: str
    connector_type: str
    steps: list[HardeningStepResult] = field(default_factory=list)
    error: str | None = None


def _harden_postgres(conn, gateway_ip: str, steps: list[HardeningStepResult]) -> None:
    """Apply read-only gateway user + schema lockdown on PostgreSQL."""
    import secrets as _secrets

    tmp_pass = _secrets.token_urlsafe(20)

    # Step 1 — create read-only gateway user if not already present
    try:
        exists = conn.execute(text(
            "SELECT 1 FROM pg_roles WHERE rolname = 'metasight_gateway'"
        )).scalar()
        if not exists:
            conn.execute(text(
                f"CREATE USER metasight_gateway WITH PASSWORD :pwd"
            ).bindparams(pwd=tmp_pass))
            conn.execute(text(
                "GRANT CONNECT ON DATABASE current_database() TO metasight_gateway"
            ))
            conn.execute(text(
                "GRANT USAGE ON SCHEMA public TO metasight_gateway"
            ))
            conn.execute(text(
                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO metasight_gateway"
            ))
            conn.execute(text(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                "GRANT SELECT ON TABLES TO metasight_gateway"
            ))
            conn.commit()
            steps.append(HardeningStepResult(
                "Create gateway user",
                "applied",
                f"Created 'metasight_gateway' with SELECT-only grants. "
                f"Temp password: {tmp_pass} — change this immediately in MetaSight.",
            ))
        else:
            steps.append(HardeningStepResult(
                "Create gateway user", "skipped",
                "'metasight_gateway' already exists",
            ))
    except Exception as exc:
        steps.append(HardeningStepResult("Create gateway user", "error", str(exc)))

    # Step 2 — revoke CREATE on public schema from PUBLIC
    try:
        conn.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
        conn.commit()
        steps.append(HardeningStepResult(
            "Revoke schema CREATE from PUBLIC", "applied",
            "Revoked CREATE on public schema from all non-privileged users",
        ))
    except Exception as exc:
        steps.append(HardeningStepResult("Revoke schema CREATE", "error", str(exc)))

    # Step 3 — pg_hba.conf cannot be edited in-database; provide instruction
    hint = (
        f"Edit /etc/postgresql/*/main/pg_hba.conf — add:\n"
        f"  hostssl your_db metasight_gateway {gateway_ip}/32 scram-sha-256\n"
        f"  host    all     all               0.0.0.0/0        reject\n"
        f"Then reload: SELECT pg_reload_conf();"
    )
    steps.append(HardeningStepResult("Restrict pg_hba.conf (IP allowlist)", "manual", hint))

    # Step 4 — SSL can be checked but not enabled in-database without superuser alter
    try:
        ssl_on = conn.execute(text(
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
        )).scalar()
        if ssl_on:
            steps.append(HardeningStepResult(
                "SSL/TLS enforcement", "skipped",
                "Connection already uses SSL — ensure ssl=on in postgresql.conf",
            ))
        else:
            steps.append(HardeningStepResult(
                "SSL/TLS enforcement", "manual",
                "Set ssl=on in postgresql.conf and use hostssl in pg_hba.conf",
            ))
    except Exception:
        steps.append(HardeningStepResult(
            "SSL/TLS enforcement", "manual",
            "Set ssl=on in postgresql.conf and restart the server",
        ))


def _harden_mysql(conn, gateway_ip: str, steps: list[HardeningStepResult]) -> None:
    """Apply read-only gateway user + SSL requirement on MySQL/MariaDB."""
    import secrets as _secrets

    tmp_pass = _secrets.token_urlsafe(20)

    # Step 1 — create read-only user
    try:
        conn.execute(text(
            "CREATE USER IF NOT EXISTS 'metasight_gateway'@:host "
            "IDENTIFIED BY :pwd"
        ).bindparams(host=gateway_ip or "%", pwd=tmp_pass))
        db_row = conn.execute(text("SELECT DATABASE()")).scalar() or "your_db"
        conn.execute(text(
            f"GRANT SELECT ON `{db_row}`.* TO 'metasight_gateway'@:host"
        ).bindparams(host=gateway_ip or "%"))
        conn.execute(text("FLUSH PRIVILEGES"))
        conn.commit()
        steps.append(HardeningStepResult(
            "Create gateway user", "applied",
            f"Created 'metasight_gateway'@'{gateway_ip or '%'}' with SELECT grants. "
            f"Temp password: {tmp_pass} — change via MetaSight.",
        ))
    except Exception as exc:
        steps.append(HardeningStepResult("Create gateway user", "error", str(exc)))

    # Step 2 — require SSL on gateway user
    try:
        conn.execute(text(
            "ALTER USER 'metasight_gateway'@:host REQUIRE SSL"
        ).bindparams(host=gateway_ip or "%"))
        conn.execute(text("FLUSH PRIVILEGES"))
        conn.commit()
        steps.append(HardeningStepResult(
            "Require SSL on gateway user", "applied",
            "Gateway user now requires SSL/TLS connection",
        ))
    except Exception as exc:
        steps.append(HardeningStepResult("Require SSL on gateway user", "error", str(exc)))

    # Step 3 — bind-address is my.cnf — manual
    steps.append(HardeningStepResult(
        "Bind MySQL to MetaSight IP (my.cnf)", "manual",
        f"Edit /etc/mysql/my.cnf: bind-address = {gateway_ip or '<metasight-ip>'}",
    ))


def _harden_mssql(conn, gateway_ip: str, steps: list[HardeningStepResult]) -> None:
    """Apply read-only gateway login + deny write on MSSQL."""
    import secrets as _secrets

    tmp_pass = "Ms@" + _secrets.token_urlsafe(16) + "1"  # meets complexity

    # Step 1 — create login + user
    try:
        conn.execute(text(
            "IF NOT EXISTS (SELECT name FROM sys.server_principals "
            "WHERE name = 'metasight_gateway') "
            "CREATE LOGIN metasight_gateway WITH PASSWORD = :pwd"
        ).bindparams(pwd=tmp_pass))
        conn.execute(text(
            "IF NOT EXISTS (SELECT name FROM sys.database_principals "
            "WHERE name = 'metasight_gateway') "
            "BEGIN "
            "  CREATE USER metasight_gateway FOR LOGIN metasight_gateway; "
            "  ALTER ROLE db_datareader ADD MEMBER metasight_gateway "
            "END"
        ))
        conn.commit()
        steps.append(HardeningStepResult(
            "Create gateway login/user", "applied",
            f"Created 'metasight_gateway' with db_datareader role. "
            f"Temp password: {tmp_pass} — update immediately.",
        ))
    except Exception as exc:
        steps.append(HardeningStepResult("Create gateway login/user", "error", str(exc)))

    # Step 2 — deny write permissions
    try:
        conn.execute(text(
            "DENY INSERT, UPDATE, DELETE, DROP, CREATE, ALTER "
            "ON SCHEMA::dbo TO metasight_gateway"
        ))
        conn.commit()
        steps.append(HardeningStepResult(
            "Deny write permissions", "applied",
            "Denied INSERT/UPDATE/DELETE/DDL on dbo schema",
        ))
    except Exception as exc:
        steps.append(HardeningStepResult("Deny write permissions", "error", str(exc)))

    # Step 3 — force encryption is a server config — manual
    steps.append(HardeningStepResult(
        "Force encrypted connections", "manual",
        "In SQL Server Configuration Manager: Protocols > Force Encryption = Yes",
    ))


_HARDENING_FN_MAP = {
    "postgres":    _harden_postgres,
    "redshift":    _harden_postgres,
    "greenplum":   _harden_postgres,
    "cockroach":   _harden_postgres,
    "timescaledb": _harden_postgres,
    "mysql":       _harden_mysql,
    "mariadb":     _harden_mysql,
    "mssql":       _harden_mssql,
    "azuresql":    _harden_mssql,
}


def apply_db_hardening(source, gateway_ip: str, db: Session) -> HardeningResult:
    """
    Connect to *source* and apply hardening steps in-database.
    Returns HardeningResult with per-step status.
    """
    result = HardeningResult(
        source_id=source.id,
        source_name=source.name,
        connector_type=source.type,
    )

    harden_fn = _HARDENING_FN_MAP.get(source.type)
    if harden_fn is None:
        result.steps.append(HardeningStepResult(
            "Automated hardening", "manual",
            f"No automated hardening for connector type '{source.type}'. "
            f"Follow the hardening guide at GET /security/hardening/{source.type}.",
        ))
        return result

    try:
        config = {
            k: aes_cipher.decrypt(v) if isinstance(v, str) else v
            for k, v in (source.encrypted_config or {}).items()
        }
    except Exception as exc:
        result.error = f"Credential decryption failed: {exc}"
        return result

    try:
        url, engine_kwargs = _build_url(source.type, config)
        engine = create_engine(
            url,
            connect_args=engine_kwargs.get("connect_args", {}),
            pool_pre_ping=True,
        )
        with engine.connect() as conn:
            harden_fn(conn, gateway_ip, result.steps)
        engine.dispose()
    except Exception as exc:
        result.error = f"Connection or hardening failed: {exc}"

    return result


# ── Main checker ──────────────────────────────────────────────────────────────

def check_source_security(source, db: Session) -> SecurityCheckResult:
    """
    Connect to a DataSource and run privilege checks.
    source: DataSource ORM object
    """
    result = SecurityCheckResult(
        source_id=source.id,
        source_name=source.name,
        connector_type=source.type,
        reachable=False,
    )

    # Decrypt config
    try:
        config = {
            k: aes_cipher.decrypt(v) if isinstance(v, str) else v
            for k, v in (source.encrypted_config or {}).items()
        }
    except Exception as exc:
        result.error = f"Credential decryption failed: {exc}"
        result.grade = "?"
        return result

    # Build connection URL
    if is_storage_source(source.type):
        return check_source_security_storage(source, db)

    # MongoDB and other NoSQL sources should skip SQL-style URL building
    if source.type.lower() == "mongodb":
        result.reachable = True
        _check_mongodb(None, result.checks)
        result._compute_grade()
        return result

    try:
        url, engine_kwargs = _build_url(source.type, config)
    except Exception as exc:
        result.error = f"Cannot build connection URL for type '{source.type}': {exc}"
        result.grade = "?"
        return result

    # Connect and run checks
    try:
        engine = create_engine(url, connect_args=engine_kwargs.get("connect_args", {}),
                               pool_pre_ping=True)
        with engine.connect() as conn:
            result.reachable = True
            checker_fn = _CHECKER_MAP.get(source.type, _check_generic_sql)
            checker_fn(conn, result.checks)
        engine.dispose()
    except Exception as exc:
        result.reachable = False
        result.error = f"Connection failed: {exc}"
        result.grade = "F"
        return result

    # Always check: is using a dedicated user (not 'root', 'postgres', 'sa', 'admin')?
    username = config.get("user") or config.get("username") or config.get("login") or ""
    danger_names = {"root", "postgres", "sa", "admin", "administrator",
                    "sys", "system", "dba", "superuser"}
    checks_username = username.lower() in danger_names
    result.checks.append(CheckItem(
        "Not using root/admin account",
        "fail" if checks_username else "pass",
        f"Using '{username}' — create a dedicated read-only user"
        if checks_username else f"User: {username}"
    ))

    result._compute_grade()
    return result
