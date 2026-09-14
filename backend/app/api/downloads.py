"""
Agent binary download endpoint.

Serves pre-built MetaSight agent binaries from  backend/agent/dist/.
The install.sh / install-agent-aix.sh scripts call:
  GET /downloads/metasight-agent-linux-amd64
  GET /downloads/metasight-agent-linux-arm64
  GET /downloads/metasight-agent-aix-ppc64
  GET /downloads/install-agent.sh
  GET /downloads/install-agent-aix.sh

No authentication required — the binaries contain no secrets and the API key
is supplied at runtime via install.sh env vars.
"""
import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()
logger = logging.getLogger(__name__)

# Resolve the dist directory relative to this file's location
# backend/app/api/downloads.py → backend/agent/dist/
_DIST_DIR = Path(__file__).resolve().parent.parent.parent / "agent" / "dist"
_AGENT_DIR = Path(__file__).resolve().parent.parent.parent / "agent"

# Allowlist of downloadable filenames (prevents path traversal)
_ALLOWED_BINARIES = {
    "metasight-agent-linux-amd64",
    "metasight-agent-linux-arm64",
    "metasight-agent-darwin-amd64",
    "metasight-agent-darwin-arm64",
    "metasight-agent-windows-amd64.exe",
    # AIX / PowerPC — Oracle E-Business Suite database tiers etc.
    # AIX only runs on Power hardware, so there's a single arch (ppc64).
    "metasight-agent-aix-ppc64",
    # Legacy name produced by the old Windows build
    "agent-windows-amd64.exe",
}

# Install-script filename -> source file in backend/agent/
_INSTALL_SCRIPTS = {
    "install-agent.sh": "install.sh",
    "install-agent-aix.sh": "install-agent-aix.sh",
}


@router.get("/install-agent.sh", include_in_schema=False)
def serve_install_script():
    """Serve the Linux (systemd) agent installer shell script."""
    return _serve_install_script("install-agent.sh")


@router.get("/install-agent-aix.sh", include_in_schema=False)
def serve_install_script_aix():
    """Serve the AIX (inittab) agent installer shell script."""
    return _serve_install_script("install-agent-aix.sh")


def _serve_install_script(public_name: str) -> FileResponse:
    source_name = _INSTALL_SCRIPTS[public_name]
    script_path = _AGENT_DIR / source_name
    if not script_path.exists():
        raise HTTPException(status_code=404, detail=f"{public_name} not found")
    return FileResponse(
        path=str(script_path),
        media_type="text/x-shellscript",
        filename=public_name,
    )


@router.get("/{filename}", include_in_schema=False)
def download_agent_binary(filename: str):
    """
    Download a pre-built agent binary.

    Supported filenames:
      metasight-agent-linux-amd64   (Ubuntu x86-64)
      metasight-agent-linux-arm64   (Ubuntu ARM / Graviton)
      metasight-agent-darwin-amd64  (Intel Mac)
      metasight-agent-darwin-arm64  (Apple Silicon)
      metasight-agent-windows-amd64.exe
    """
    if filename not in _ALLOWED_BINARIES:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Binary '{filename}' not found. "
                "Available: " + ", ".join(sorted(_ALLOWED_BINARIES))
            ),
        )

    binary_path = _DIST_DIR / filename
    if not binary_path.exists():
        logger.warning(
            "Agent binary requested but not found on disk: %s "
            "(run 'make linux' inside backend/agent/ to build it)",
            binary_path,
        )
        raise HTTPException(
            status_code=503,
            detail=(
                f"Binary '{filename}' has not been built yet. "
                "Ask your MetaSight administrator to run 'make linux' "
                "inside the backend/agent/ directory."
            ),
        )

    logger.info("Serving agent binary: %s (%d bytes)", filename, binary_path.stat().st_size)
    return FileResponse(
        path=str(binary_path),
        media_type="application/octet-stream",
        filename=filename,
    )
