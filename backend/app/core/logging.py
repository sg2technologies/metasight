"""
Logging configuration for MetaSight.

Sets up:
  - Colorized console output (ANSI, auto-disabled when not a TTY)
  - Rotating file handler → logs/metasight.log (10 MB × 5 files)
  - Quieter uvicorn/SQLAlchemy noise at INFO level
  - Short logger name abbreviation so columns line up

Log line format (console):
  14:23:45.123 [INFO ] native_scanner     | Starting bulk column fetch for HR (1523 tables)
  14:23:49.789 [ERROR] api.sources        | Connection refused: 127.0.0.1:1521
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path

# ── ANSI colour palette ───────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

_LEVEL_COLORS: dict[int, str] = {
    logging.DEBUG:    "\033[36m",    # cyan
    logging.INFO:     "\033[32m",    # green
    logging.WARNING:  "\033[33m",    # yellow
    logging.ERROR:    "\033[31m",    # red
    logging.CRITICAL: "\033[1;31m",  # bold red
}

# Short prefixes for common noisy loggers
_NAME_ABBREV: dict[str, str] = {
    "app.ingestion.native_scanner": "native_scanner",
    "app.ingestion.nosql_scanner":  "nosql_scanner",
    "app.api.scans":                "api.scans",
    "app.api.catalog":              "api.catalog",
    "app.api.sources":              "api.sources",
    "app.api.auth":                 "api.auth",
    "app.core.deps":                "core.deps",
    "app.workers.tasks":            "workers.tasks",
    "app.services.governance_audit":"svc.audit",
    "uvicorn.error":                "uvicorn",
    "uvicorn.access":               "access",
    "celery.app.trace":             "celery",
    "celery.worker":                "celery.worker",
    "sqlalchemy.engine.Engine":     "sqla.engine",
}

_NAME_WIDTH = 18   # pad short names, truncate long ones


def _shorten(name: str) -> str:
    abbrev = _NAME_ABBREV.get(name)
    if abbrev:
        return abbrev[:_NAME_WIDTH].ljust(_NAME_WIDTH)
    # strip "app." prefix for our own modules
    short = name.removeprefix("app.")
    return short[:_NAME_WIDTH].ljust(_NAME_WIDTH)


# ── Formatters ────────────────────────────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    """ANSI-coloured formatter for terminal output."""

    _use_color: bool

    def __init__(self, use_color: bool = True):
        super().__init__()
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        ts   = self.formatTime(record, datefmt="%H:%M:%S")
        ms   = f"{record.msecs:03.0f}"
        lvl  = record.levelname[:5].ljust(5)
        name = _shorten(record.name)
        msg  = record.getMessage()

        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)

        if self._use_color:
            color = _LEVEL_COLORS.get(record.levelno, "")
            level_str = f"{color}[{lvl}]{_RESET}"
            name_str  = f"{_DIM}{name}{_RESET}"
            sep       = f"{_DIM}|{_RESET}"
            ts_str    = f"{_DIM}{ts}.{ms}{_RESET}"
        else:
            level_str = f"[{lvl}]"
            name_str  = name
            sep       = "|"
            ts_str    = f"{ts}.{ms}"

        return f"{ts_str} {level_str} {name_str} {sep} {msg}"


class PlainFormatter(logging.Formatter):
    """Plain (no ANSI) formatter for log files."""

    def format(self, record: logging.LogRecord) -> str:
        ts   = self.formatTime(record, datefmt="%Y-%m-%d %H:%M:%S")
        ms   = f"{record.msecs:03.0f}"
        lvl  = record.levelname[:5].ljust(5)
        name = _shorten(record.name).strip()
        msg  = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        return f"{ts}.{ms} [{lvl}] {name} | {msg}"


# ── Noise filters ─────────────────────────────────────────────────────────────

class _AccessLogFilter(logging.Filter):
    """Drop uvicorn access-log lines for 2xx/3xx health-check-like paths."""

    _SKIP_PATHS = {"/health", "/metrics", "/favicon.ico"}

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        # Drop 200/304 hits to health/metrics endpoints
        for path in self._SKIP_PATHS:
            if path in msg and (' 200 ' in msg or ' 304 ' in msg):
                return False
        # Drop 200 OK for catalog list polling (very chatty during scans)
        if '/scans/runs/' in msg and ' 200 ' in msg:
            return False
        return True


# ── Public entry-point ────────────────────────────────────────────────────────

def setup_logging() -> None:
    """Call once at application startup (main.py)."""
    log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level      = getattr(logging, log_level_name, logging.INFO)

    # ── Console handler ───────────────────────────────────────────────────────
    console = logging.StreamHandler(sys.stdout)
    use_color = sys.stdout.isatty() or os.getenv("FORCE_COLOR", "").lower() in ("1", "true", "yes")
    console.setFormatter(ColorFormatter(use_color=use_color))
    console.setLevel(log_level)
    console.addFilter(_AccessLogFilter())

    # ── Rotating file handler ─────────────────────────────────────────────────
    log_dir = Path(__file__).resolve().parents[3] / "logs"   # backend/logs/
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "metasight.log"

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(PlainFormatter())
    file_handler.setLevel(logging.DEBUG)   # capture everything to file

    # ── Root logger ───────────────────────────────────────────────────────────
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)   # root wide-open; handlers filter
    root.handlers.clear()
    root.addHandler(console)
    root.addHandler(file_handler)

    # ── Third-party noise reduction ───────────────────────────────────────────
    # SQLAlchemy: only log warnings (echo=True on engine handles SQL output)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.orm").setLevel(logging.WARNING)

    # Uvicorn access log: INFO but filtered above for noisy paths
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)

    # Celery internals: only WARNING
    logging.getLogger("celery").setLevel(logging.WARNING)
    logging.getLogger("celery.app.trace").setLevel(logging.INFO)   # show task start/end

    # httpx / httpcore (used by some connectors)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Alembic: show migration steps
    logging.getLogger("alembic").setLevel(logging.INFO)

    logger = logging.getLogger(__name__)
    logger.info("Logging initialised | level=%s | file=%s", log_level_name, log_file)
