"""
Create the initial admin (superuser) for the platform.

Usage:
    python scripts/create_superuser.py

The script reads SETUP_SECRET and API base URL from .env (or environment).
Run this ONCE after the first `alembic upgrade head`.
"""

import os
import sys
import getpass

# Load .env from project root (parent of this script's directory)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass  # python-dotenv not installed; fall back to real env vars

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is not installed. Run: pip install requests")
    sys.exit(1)

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")
SETUP_SECRET = os.getenv("SETUP_SECRET", "")

if not SETUP_SECRET:
    print("ERROR: SETUP_SECRET is not set in .env or environment.")
    sys.exit(1)


def prompt(label: str, secret: bool = False) -> str:
    while True:
        value = getpass.getpass(f"{label}: ") if secret else input(f"{label}: ").strip()
        if value:
            return value
        print(f"  {label} cannot be empty.")


def main():
    print("=" * 50)
    print("  Database Governance Platform — Superuser Setup")
    print("=" * 50)
    print(f"  API: {API_BASE}\n")

    tenant_name   = prompt("Tenant / organisation name")
    admin_email   = prompt("Admin email")
    admin_password = prompt("Admin password", secret=True)
    confirm       = prompt("Confirm password", secret=True)

    if admin_password != confirm:
        print("\nERROR: Passwords do not match.")
        sys.exit(1)

    print("\nCreating superuser…")

    try:
        resp = requests.post(
            f"{API_BASE}/auth/setup",
            json={
                "tenant_name": tenant_name,
                "admin_email": admin_email,
                "admin_password": admin_password,
            },
            headers={
                "X-Setup-Secret": SETUP_SECRET,
                "Content-Type": "application/json",
            },
            timeout=10,
        )
    except requests.ConnectionError:
        print(f"\nERROR: Could not connect to {API_BASE}. Is the server running?")
        sys.exit(1)

    if resp.status_code == 201:
        data = resp.json()
        print("\n✓ Superuser created successfully!")
        print(f"  ID     : {data['id']}")
        print(f"  Email  : {data['email']}")
        print(f"  Role   : {data['role']}")
        print(f"  Tenant : {data['tenant_id']}")
        print("\nYou can now log in at POST /auth/login")
    elif resp.status_code == 409:
        print("\nINFO: Setup already completed — a user already exists.")
        print("Use POST /users (with admin JWT) to add more users.")
    elif resp.status_code == 403:
        print("\nERROR: Invalid SETUP_SECRET. Check your .env file.")
        sys.exit(1)
    else:
        print(f"\nERROR: Unexpected response {resp.status_code}: {resp.text}")
        sys.exit(1)


if __name__ == "__main__":
    main()
