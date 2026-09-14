@echo off
setlocal enabledelayedexpansion

:: ─── Paths ────────────────────────────────────────────────────────────────────
set "BACKEND_DIR=%~dp0"
set "VENV_DIR=%BACKEND_DIR%venv"
set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"
set "UVICORN_EXE=%VENV_DIR%\Scripts\uvicorn.exe"
set "CELERY_EXE=%VENV_DIR%\Scripts\celery.exe"
set "FRONTEND_DIR=%BACKEND_DIR%..\frontend"
set "REDIS_OK=0"

echo ============================================================
echo   MetaSight - Dev Startup
echo ============================================================
echo.

cd /d "%BACKEND_DIR%"

:: ─── 1. Python venv ───────────────────────────────────────────────────────────
if not exist "%PYTHON_EXE%" goto :setup_venv
"%PYTHON_EXE%" -c "import sys" >nul 2>&1
if errorlevel 1 goto :setup_venv
goto :check_deps

:setup_venv
echo [SETUP] Creating Python virtual environment...
set "PY_CMD="
for %%v in (3.11 3.12 3.10 3.13) do (
    if "!PY_CMD!"=="" (
        py -%%v --version >nul 2>&1
        if not errorlevel 1 set "PY_CMD=py -%%v"
    )
)
if "!PY_CMD!"=="" (
    python --version >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python"
)
if "!PY_CMD!"=="" (
    echo [ERROR] Python 3.10+ not found. Install from https://python.org
    pause
    exit /b 1
)
echo [SETUP] Using: !PY_CMD!
!PY_CMD! -m venv --clear "%VENV_DIR%"
if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
)

:check_deps
"%PYTHON_EXE%" -c "import uvicorn, celery, fastapi, sqlalchemy, pydantic_settings" >nul 2>&1
if not errorlevel 1 goto :check_redis

echo [SETUP] Installing core dependencies (this may take a few minutes)...
"%PYTHON_EXE%" -m pip install --upgrade pip --quiet
if errorlevel 1 (
    echo [ERROR] Failed to upgrade pip.
    pause
    exit /b 1
)

echo [SETUP] Installing core packages...
"%PYTHON_EXE%" -m pip install fastapi "uvicorn[standard]" "sqlalchemy>=2.0" alembic psycopg2-binary "python-jose[cryptography]" "passlib[argon2]" argon2-cffi python-dotenv pydantic-settings "celery[redis]" redis cryptography python-multipart slowapi sqlglot email-validator pymysql httpx minio apscheduler hvac setuptools --quiet
if errorlevel 1 (
    echo [ERROR] Core package installation failed.
    pause
    exit /b 1
)

echo [SETUP] Installing optional DB drivers (failures here are non-fatal)...
"%PYTHON_EXE%" -m pip install pymssql oracledb snowflake-sqlalchemy sqlalchemy-bigquery duckdb-engine clickhouse-connect trino pyathena vertica-python pydruid pinotdb pymongo cassandra-driver elasticsearch opensearch-py boto3 azure-storage-blob google-cloud-storage databricks-sql-connector --quiet 2>nul
echo [SETUP] Dependencies ready.

:check_redis
:: ─── 2. Redis check ───────────────────────────────────────────────────────────
echo.
echo [CHECK] Verifying Redis on localhost:6379...
"%PYTHON_EXE%" -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',6379)); s.close()" >nul 2>&1
if errorlevel 1 (
    echo.
    echo  WARNING: Redis is not running on localhost:6379.
    echo.
    echo  Celery needs Redis. Choose one option to start Redis on Windows:
    echo.
    echo    1. Docker:   docker run -d -p 6379:6379 redis:alpine
    echo    2. WSL:      wsl -e redis-server --daemonize yes
    echo    3. Memurai:  https://www.memurai.com  (free developer edition)
    echo.
    echo  FastAPI will still start. Celery will be skipped.
    echo  Press any key to continue...
    pause >nul
    set "REDIS_OK=0"
) else (
    echo [CHECK] Redis OK.
    set "REDIS_OK=1"
)

:: ─── 3. Launch FastAPI ────────────────────────────────────────────────────────
::  NOTE: start commands are in subroutines to avoid &&-inside-if-block
::        quoting issues under setlocal enabledelayedexpansion.
echo.
echo [START] Launching FastAPI on http://localhost:8000 ...
call :launch_fastapi

timeout /t 2 /nobreak >nul

:: ─── 4. Launch Celery (only if Redis available) ───────────────────────────────
if "!REDIS_OK!"=="1" call :launch_celery

:: ─── 5. Launch Frontend ───────────────────────────────────────────────────────
if exist "%FRONTEND_DIR%\package.json" call :launch_frontend

:summary
echo.
echo ============================================================
echo   Services launched (each in its own window):
echo     Backend  ^>  http://localhost:8000
echo     API Docs ^>  http://localhost:8000/docs
if exist "%FRONTEND_DIR%\package.json" echo     Frontend ^>  http://localhost:5173
if "!REDIS_OK!"=="1" (
    echo     Celery   ^>  Worker + Beat scheduler running
) else (
    echo     Celery   ^>  NOT started - Redis unavailable
)
echo ============================================================
echo.
echo If a window shows an error, read the message there before closing it.
echo Close each service window to stop that service.
echo.
pause
goto :eof

:: ─── Subroutines ─────────────────────────────────────────────────────────────
::  These live outside any if/for block so && inside "..." works correctly.

:launch_fastapi
start "MetaSight - FastAPI" cmd /k "cd /d ""%BACKEND_DIR%."" && ""%UVICORN_EXE%"" app.main:app --host 0.0.0.0 --port 8000 --reload"
exit /b 0

:launch_celery
echo [START] Launching Celery worker...
start "MetaSight - Celery Worker" cmd /k "cd /d ""%BACKEND_DIR%."" && ""%CELERY_EXE%"" -A app.workers.celery_app.celery_app worker --loglevel=info --pool=solo -c 1"
echo [START] Launching Celery beat scheduler (DAM polling)...
start "MetaSight - Celery Beat" cmd /k "cd /d ""%BACKEND_DIR%."" && ""%CELERY_EXE%"" -A app.workers.celery_app.celery_app beat --loglevel=info"
exit /b 0

:launch_frontend
if not exist "%FRONTEND_DIR%\node_modules" (
    echo [SETUP] Installing frontend dependencies...
    call npm install --prefix "%FRONTEND_DIR%"
    if errorlevel 1 (
        echo [WARNING] Frontend npm install failed - skipping.
        exit /b 0
    )
)
echo [START] Launching frontend on http://localhost:5173 ...
start "MetaSight - Frontend" cmd /k "cd /d ""%FRONTEND_DIR%"" && npm run dev"
exit /b 0
