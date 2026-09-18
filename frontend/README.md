# MetaSight Frontend

React 19 + Vite UI for MetaSight (Community edition). See the repo root
[README.md](../README.md) for what MetaSight is and does, including the
Enterprise edition.

## Prerequisites

- Node.js 18+
- A running MetaSight backend (see [`../backend/README.md`](../backend/README.md))

## Run locally

```bash
npm install
cp .env.example .env   # set VITE_API_URL to your backend, e.g. http://localhost:8000
npm run dev
```

## Build

```bash
npm run build     # outputs to dist/
npx tsc --noEmit  # type-check only
```

## Enterprise UI overlay

`src/plugins/pam/index.ts` and `src/plugins/types.ts` are the seam Enterprise's
frontend build overlays with its own pages (access requests, sessions, DAM,
incidents, evidence, risk, compliance, JIT, agents, blocked commands). This
repo ships the empty stub — `App.tsx`/`Layout.tsx` never import an
Enterprise page directly. See `enterprise/frontend/README.md` in the
(private) Enterprise repository for how the overlay is applied.
