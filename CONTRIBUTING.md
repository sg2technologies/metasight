# Contributing to MetaSight

Thanks for considering a contribution to MetaSight Community.

## Scope of this repository

This repo is the Community edition only. Full PAM (access requests/JIT,
session recording, correlation, evidence, compliance framework reporting)
lives in a separate, private Enterprise distribution. PRs that try to add
Enterprise-shaped features here will likely be redirected rather than
merged; open an issue first if you're not sure which side of the line
something falls on.

## Before you start

- For anything non-trivial (new connector, new masking type, schema change),
  open an issue describing the change before writing code — it's much
  cheaper to align on approach before the PR than after.
- Small fixes (typos, docs, obvious bugs) can go straight to a PR.

## Development setup

See the "Getting started" section of [README.md](README.md) for the backend
(FastAPI + PostgreSQL + Redis) and frontend (React + Vite) dev loops.

## Making a change

1. Fork the repo and create a branch off `main`.
2. Keep the extension-point pattern intact if you touch anything near the
   Enterprise seam: `try: import metasight_enterprise / except ImportError`
   in the backend, the `frontend/src/plugins/` registry in the frontend.
   Never add a feature flag or entitlement check — the boundary here is
   "is the code present," not a runtime toggle.
3. If you touch the scanner, catalog, or data discovery code, keep the
   bulk-fetch and batch-write patterns already in place (`native_scanner.py`,
   `catalog.py`) — this project is built to run against 10,000+ table Oracle
   schemas; per-row/per-table round-trips regress that badly.
4. Add or update tests where the area has them.
5. Run the checks below before opening a PR.

## Checks before opening a PR

```bash
# Backend
cd backend
python -m py_compile $(git diff --name-only main -- '*.py')

# Frontend
cd frontend
npx tsc --noEmit
npm run build
```

## Pull requests

This repo's `main` branch requires a pull request (linear history, no
force-pushes, no direct pushes) — you can't push straight to `main` even
with write access. Open a PR and describe:

- What changed and why.
- Which tier boundary (if any) it touches.
- How you tested it (unit tests, manual run, etc.) — this project doesn't
  yet have CI wired up, so PR descriptions carrying real verification detail
  matter more than usual.

## Reporting bugs

Open a GitHub issue with repro steps, expected vs. actual behavior, and your
environment (OS, Python/Node versions, database engine + version).

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).
