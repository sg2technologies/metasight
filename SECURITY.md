# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected security
vulnerability.

Instead, report it privately via [GitHub Security Advisories](../../security/advisories/new)
for this repository, or email **security@REPLACE-ME.example** <!-- TODO: replace with a real, monitored contact address before this repo goes public -->.

Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (a minimal repro is very helpful).
- The affected version/commit.

We'll acknowledge your report and follow up with next steps. Please give us
a reasonable window to investigate and patch before any public disclosure.

## Supported versions

MetaSight Community doesn't yet have a formal LTS/release-branch policy —
security fixes land on `main`. This will be revisited once tagged releases
start.

## Scope

This policy covers the Community edition in this repository: the FastAPI
backend, the React frontend, the scanner/ingestion code, and the deployment
scripts under `deploy/`. Enterprise (private distribution) has its own
reporting channel — see that repository's `SECURITY.md`.

## Known, already-addressed issues

`SECURITY_AUDIT.md` in this repository is a running log of security
findings and fixes from internal review — check it before reporting
something that might already be tracked or fixed.
