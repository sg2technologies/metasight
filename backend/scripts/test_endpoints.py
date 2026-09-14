"""
End-to-end endpoint test script for the Database Governance Platform.

Usage:
    python scripts/test_endpoints.py

Reads API_BASE_URL and SETUP_SECRET from .env.
Runs every endpoint in sequence, prints PASS / FAIL with response details.
"""

import os
import sys
import json

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────

BASE        = os.getenv("API_BASE_URL", "http://localhost:8000")
SETUP_SECRET = os.getenv("SETUP_SECRET", "")

# Test credentials — read from .env or prompt if not set
def _prompt_if_missing(env_var: str, label: str, secret: bool = False) -> str:
    val = os.getenv(env_var, "").strip()
    if val:
        return val
    import getpass
    return getpass.getpass(f"  {label}: ") if secret else input(f"  {label}: ").strip()

print("\nAdmin credentials for testing (set TEST_ADMIN_EMAIL / TEST_ADMIN_PASSWORD in .env to skip prompts):")
ADMIN_EMAIL    = _prompt_if_missing("TEST_ADMIN_EMAIL",    "Admin email")
ADMIN_PASSWORD = _prompt_if_missing("TEST_ADMIN_PASSWORD", "Admin password", secret=True)
TENANT_NAME    = "test-org"
USER_EMAIL     = os.getenv("TEST_USER_EMAIL",    "analyst_test@test.com")
USER_PASSWORD  = os.getenv("TEST_USER_PASSWORD", "Analyst@Test1234")

# ── Helpers ───────────────────────────────────────────────────────────────────

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"
INFO = "\033[94mINFO\033[0m"

results = []


def check(label: str, resp: requests.Response, expected: int):
    ok = resp.status_code == expected
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {label}")
    print(f"         {resp.request.method} {resp.url}  ->  {resp.status_code}")
    body = None
    try:
        if resp.content:
            body = resp.json()
            print(f"         {json.dumps(body, indent=None, default=str)[:200]}")
    except Exception:
        print(f"         {resp.text[:200]}")
    results.append((label, ok))
    return body if ok else None


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def section(title: str):
    print(f"\n{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}")


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_health():
    section("1. Health Check")
    resp = requests.get(f"{BASE}/health")
    check("GET /health", resp, 200)


def test_setup():
    section("2. Auth — Setup (one-time, hidden endpoint)")
    if not SETUP_SECRET:
        print(f"  [{SKIP}] SETUP_SECRET not set in .env — skipping setup")
        return None

    resp = requests.post(
        f"{BASE}/auth/setup",
        json={"tenant_name": TENANT_NAME, "admin_email": ADMIN_EMAIL, "admin_password": ADMIN_PASSWORD},
        headers={"X-Setup-Secret": SETUP_SECRET},
    )
    if resp.status_code == 409:
        print(f"  [{INFO}] Setup already done — continuing with existing admin")
        return True
    return check("POST /auth/setup", resp, 201)


def test_login(email: str, password: str, label: str = "admin") -> str | None:
    section(f"3. Auth — Login ({label})")
    resp = requests.post(
        f"{BASE}/auth/login",
        data={"username": email, "password": password},
    )
    data = check(f"POST /auth/login ({label})", resp, 200)
    if data:
        token = data.get("access_token")
        print(f"         token: {token[:40]}…")
        return token
    return None


def test_login_failures():
    section("4. Auth — Login failure cases")
    # Wrong password
    resp = requests.post(f"{BASE}/auth/login", data={"username": ADMIN_EMAIL, "password": "wrongpass"})
    check("POST /auth/login — wrong password → 401", resp, 401)

    # Non-existent user
    resp = requests.post(f"{BASE}/auth/login", data={"username": "nobody@x.com", "password": "pass"})
    check("POST /auth/login — unknown user → 401", resp, 401)

    # No token on protected route
    resp = requests.get(f"{BASE}/sources")
    check("GET /sources — no token → 401", resp, 401)


def test_users(admin_token: str) -> int | None:
    section("5. Users")
    headers = auth_header(admin_token)

    # List users (should have at least admin)
    resp = requests.get(f"{BASE}/users", headers=headers)
    check("GET /users", resp, 200)

    # Create analyst
    resp = requests.post(
        f"{BASE}/users",
        json={"email": USER_EMAIL, "password": USER_PASSWORD, "role": "analyst"},
        headers=headers,
    )
    if resp.status_code == 409:
        print(f"  [{INFO}] Analyst user already exists")
        data = requests.get(f"{BASE}/users", headers=headers).json()
        analyst = next((u for u in data if u["email"] == USER_EMAIL), None)
        return analyst["id"] if analyst else None

    data = check("POST /users — create analyst", resp, 201)
    return data["id"] if data else None

    # Short password → 422
    resp = requests.post(
        f"{BASE}/users",
        json={"email": "bad@test.com", "password": "short"},
        headers=headers,
    )
    check("POST /users — short password → 422", resp, 422)

    # Invalid role → 422
    resp = requests.post(
        f"{BASE}/users",
        json={"email": "bad2@test.com", "password": "ValidPass123", "role": "superuser"},
        headers=headers,
    )
    check("POST /users — invalid role → 422", resp, 422)


def test_sources(admin_token: str) -> int | None:
    section("6. Data Sources")
    headers = auth_header(admin_token)

    # List (empty initially)
    resp = requests.get(f"{BASE}/sources", headers=headers)
    check("GET /sources", resp, 200)

    # Create
    resp = requests.post(
        f"{BASE}/sources",
        json={
            "name": "test-postgres",
            "type": "postgres",
            "config": {
                "serviceName": "test-postgres",
                "host": "localhost",
                "port": 5432,
                "database": "testdb",
                "username": "pg_user",
                "password": "pg_pass",
            },
        },
        headers=headers,
    )
    data = check("POST /sources — create", resp, 201)
    if not data:
        return None
    source_id = data["id"]

    # encrypted_config must NOT be in response
    if "encrypted_config" in data:
        print(f"  [{FAIL}] SECURITY: encrypted_config leaked in response!")
        results.append(("encrypted_config not leaked", False))
    else:
        print(f"  [{PASS}] encrypted_config not exposed in response")
        results.append(("encrypted_config not leaked", True))

    # Get single
    resp = requests.get(f"{BASE}/sources/{source_id}", headers=headers)
    check(f"GET /sources/{source_id}", resp, 200)

    # 404 for unknown
    resp = requests.get(f"{BASE}/sources/99999", headers=headers)
    check("GET /sources/99999 → 404", resp, 404)

    # Analyst cannot create source
    analyst_token = test_login(USER_EMAIL, USER_PASSWORD, label="analyst")
    if analyst_token:
        resp = requests.post(
            f"{BASE}/sources",
            json={"name": "x", "type": "mysql", "config": {"serviceName": "x"}},
            headers=auth_header(analyst_token),
        )
        check("POST /sources as analyst → 403", resp, 403)

    return source_id


def test_scans(admin_token: str, source_id: int):
    section("7. Scans")
    headers = auth_header(admin_token)

    # Trigger scan
    resp = requests.post(f"{BASE}/scans/{source_id}/scan", headers=headers)
    data = check(f"POST /scans/{source_id}/scan", resp, 202)
    if not data:
        return
    scan_id = data["scan_id"]

    # Get scan status
    resp = requests.get(f"{BASE}/scans/runs/{scan_id}", headers=headers)
    check(f"GET /scans/runs/{scan_id}", resp, 200)

    # Scan history for source
    resp = requests.get(f"{BASE}/scans/{source_id}/history", headers=headers)
    check(f"GET /scans/{source_id}/history", resp, 200)

    # Unknown scan → 404
    resp = requests.get(f"{BASE}/scans/runs/99999", headers=headers)
    check("GET /scans/runs/99999 → 404", resp, 404)

    # Analyst cannot trigger scan
    analyst_token = test_login(USER_EMAIL, USER_PASSWORD, label="analyst (scan check)")
    if analyst_token:
        resp = requests.post(f"{BASE}/scans/{source_id}/scan", headers=auth_header(analyst_token))
        check("POST scan as analyst → 403", resp, 403)


def test_tables(admin_token: str):
    section("8. Tables & Columns")
    headers = auth_header(admin_token)

    resp = requests.get(f"{BASE}/tables", headers=headers)
    check("GET /tables", resp, 200)

    # 404 for unknown table
    resp = requests.get(f"{BASE}/tables/99999", headers=headers)
    check("GET /tables/99999 → 404", resp, 404)

    resp = requests.get(f"{BASE}/tables/99999/columns", headers=headers)
    check("GET /tables/99999/columns → 404", resp, 404)


def test_delete_source(admin_token: str, source_id: int):
    section("9. Delete Data Source")
    headers = auth_header(admin_token)

    resp = requests.delete(f"{BASE}/sources/{source_id}", headers=headers)
    check(f"DELETE /sources/{source_id}", resp, 204)

    # Confirm gone
    resp = requests.get(f"{BASE}/sources/{source_id}", headers=headers)
    check(f"GET /sources/{source_id} after delete → 404", resp, 404)


def test_delete_user(admin_token: str, user_id: int):
    section("10. Delete User")
    resp = requests.delete(f"{BASE}/users/{user_id}", headers=auth_header(admin_token))
    check(f"DELETE /users/{user_id}", resp, 204)


# ── Summary ───────────────────────────────────────────────────────────────────

def summary():
    total  = len(results)
    passed = sum(1 for _, ok in results if ok)
    failed = total - passed

    print(f"\n{'='*55}")
    print(f"  RESULTS: {passed}/{total} passed", end="")
    if failed:
        print(f"  |  {failed} FAILED:")
        for label, ok in results:
            if not ok:
                print(f"    x {label}")
    else:
        print("  - all good!")
    print(f"{'='*55}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'='*55}")
    print(f"  DG Platform - Endpoint Tests")
    print(f"  API: {BASE}")
    print(f"{'='*55}")

    test_health()
    test_setup()

    admin_token = test_login(ADMIN_EMAIL, ADMIN_PASSWORD)
    if not admin_token:
        print("\nERROR: Admin login failed — cannot continue tests.")
        print("  → Make sure the server is running and setup was completed.")
        summary()
        sys.exit(1)

    test_login_failures()
    user_id   = test_users(admin_token)
    source_id = test_sources(admin_token)

    if source_id:
        test_scans(admin_token, source_id)
        test_delete_source(admin_token, source_id)

    test_tables(admin_token)

    if user_id:
        test_delete_user(admin_token, user_id)

    summary()


if __name__ == "__main__":
    main()
