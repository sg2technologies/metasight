"""
Local DB-mode agent process management (server-side "start agent locally"
testing convenience — see _agent_exe_path's docstring). Community edition.

The PAM-endpoint-mode equivalent (metasight_enterprise.agent_runner) imports
is_agent_running/stop_agent/_agent_exe_path from this module rather than
duplicating the process-tracking dict — Enterprise depending on Community is
the allowed direction.
"""
import os
import sys
import subprocess
import logging
from typing import Dict, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings

logger = logging.getLogger(__name__)

# Cache of running processes: key ("db", agent_id) or ("pam", agent_id) -> subprocess.Popen
# Shared across editions — metasight_enterprise imports this same dict via
# is_agent_running/stop_agent so a ("pam", ...) key started by Enterprise
# code is tracked the same way as a ("db", ...) key started here.
_running_processes: Dict[Tuple[str, str], subprocess.Popen] = {}


def _agent_exe_path() -> str:
    """
    Resolve the local `agent.exe` used by the server-side "start agent locally"
    convenience feature (start_db_agent below).

    This spawns a *compiled Windows binary* directly on the MetaSight server
    itself — it only ever works on a Windows host, and it's explicitly a
    local-testing convenience, not how agents are deployed for real (real
    rollout is via `backend/agent/install.sh` + systemd on the monitored host
    — see DEPLOYMENT.md). Fail with a clear message on Linux/macOS rather
    than silently trying to exec a `.exe`.
    """
    if sys.platform != "win32":
        raise RuntimeError(
            "Local agent auto-start is a Windows-only convenience for testing "
            "on the MetaSight server itself; it is not supported on this platform. "
            "Deploy agents on the monitored database host via "
            "backend/agent/install.sh (systemd) instead — see DEPLOYMENT.md."
        )
    agent_path = os.path.join(os.getcwd(), "agent", "agent.exe")
    if not os.path.exists(agent_path):
        agent_path = "agent.exe"
    return agent_path


def is_agent_running(key: Tuple[str, str]) -> bool:
    process = _running_processes.get(key)
    if not process:
        return False
    # Check if process is still alive
    if process.poll() is not None:
        # Process has finished, clean it up from cache
        del _running_processes[key]
        return False
    return True


def get_db_agent_cmd(agent_id: int, db: Session) -> list[str]:
    from app.models.models import AgentRegistration, DataSource
    from app.core.encryption import aes_cipher

    agent = db.query(AgentRegistration).filter(AgentRegistration.id == agent_id).first()
    if not agent:
        raise ValueError("Agent not found")

    source_id = agent.source_id
    db_type = agent.db_type

    # If no source_id, find the first DataSource of matching type for this tenant
    if not source_id:
        ds = db.query(DataSource).filter(
            DataSource.tenant_id == agent.tenant_id,
            DataSource.type == db_type
        ).first()
    else:
        ds = db.query(DataSource).filter(DataSource.id == source_id).first()

    if not ds:
        raise ValueError(f"No matching DataSource found for agent type {db_type}")

    config = {
        k: aes_cipher.decrypt(v) if isinstance(v, str) else v
        for k, v in ds.encrypted_config.items()
    }

    host = config.get("host", "localhost")
    port = config.get("port")
    if not port:
        port = "5432" if db_type == "postgres" else "1521" if db_type == "oracle" else "3306"

    dbname = config.get("database") or config.get("service_name") or config.get("oracleServiceName") or config.get("sid") or "xe"
    user = config.get("username") or config.get("user") or "postgres"
    password = config.get("password")
    if not password:
        # No hardcoded fallback credential — a wrong-but-silent password here
        # would just fail DB auth confusingly, or worse, work by coincidence
        # against a DB that happens to share that default.
        raise ValueError(
            f"DataSource '{ds.name}' has no password configured — cannot start agent."
        )

    agent_path = _agent_exe_path()

    cmd = [
        agent_path,
        "--mode", "db",
        "--server", settings.AGENT_CALLBACK_URL,
        "--api-key", aes_cipher.decrypt(agent.encrypted_api_key),
        "--db-type", db_type,
        "--db-host", host,
        "--db-port", str(port),
        "--db-name", dbname,
        "--db-user", user,
        "--db-password", password,
        "--interval", "1s"
    ]
    return cmd


def start_db_agent(agent_id: int, db: Session) -> bool:
    key = ("db", str(agent_id))
    if is_agent_running(key):
        return True

    try:
        cmd = get_db_agent_cmd(agent_id, db)
        log_path = os.path.join(os.getcwd(), "logs", "agents", f"agent_db_{agent_id}.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        log_file = open(log_path, "w")
        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )
        _running_processes[key] = process
        logger.info(f"Started DB Agent {agent_id} in background, pid={process.pid}")
        return True
    except Exception as e:
        logger.exception(f"Failed to start DB Agent {agent_id}: {e}")
        return False


def stop_db_agent(agent_id: int) -> bool:
    key = ("db", str(agent_id))
    return stop_agent(key)


def stop_agent(key: Tuple[str, str]) -> bool:
    process = _running_processes.get(key)
    if not process:
        return False

    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True)
        else:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
    except Exception as e:
        logger.error(f"Error stopping agent {key}: {e}")
        try:
            process.kill()
        except:
            pass
    finally:
        if key in _running_processes:
            del _running_processes[key]
    return True
