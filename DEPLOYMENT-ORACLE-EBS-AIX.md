# Deploying the MetaSight Agent to Oracle E-Business Suite on AIX

This is a companion to [`DEPLOYMENT.md`](DEPLOYMENT.md) for one specific, common customer
topology: **MetaSight itself runs on a Linux server** (per `DEPLOYMENT.md`), and you need to put a
monitoring agent on a **customer's Oracle E-Business Suite database tier running on AIX/PowerPC**.

Two things make this straightforward rather than a special case:

- The Go agent uses **go-ora**, a pure-Go Oracle driver — there is nothing to install on the AIX
  box beyond the one static binary. No Oracle Instant Client, no thick-mode libraries, no matching
  client/server version dance.
- The Makefile already has an AIX/ppc64 build target, and this codebase's download endpoint and
  frontend "Install Agent" wizard already know how to serve and generate commands for it (see
  step 3) — this is the "download & install from the frontend" flow you're already using for
  Linux/Windows, extended to AIX.

## Architecture for this topology

```
   MetaSight server (Linux, per DEPLOYMENT.md)
        │
        │  HTTPS — agent registers, sends heartbeats + activity events
        │
   ┌────┴──────────────────────────────┐
   │  Oracle EBS DB tier (AIX/ppc64)    │
   │  ┌──────────────────────────────┐  │
   │  │ metasight-agent (Go binary)   │  │──▶ read-only queries against
   │  │ registered in /etc/inittab    │  │    V$SESSION / V$SQL (thin
   │  │ ("respawn" — AIX has no       │  │    Oracle protocol, go-ora)
   │  │ systemd)                      │  │
   │  └──────────────────────────────┘  │
   └─────────────────────────────────────┘
```

The agent watches for direct/unauthorized connections to the EBS database and reports them; it
does **not** need to run on the same host as the apps tier or concurrent managers, only somewhere
with a network path to the database listener — but running it on the DB tier itself (as shown
above) is the simplest topology and what this guide assumes.

## 1. Prerequisites on the AIX host

- Root access (the installer writes `/etc/metasight`, `/usr/local/bin`, and an `/etc/inittab` entry).
- Network egress from the AIX host to the MetaSight server on its HTTPS port.
- `curl` or `wget`. Modern AIX (7.2/7.3) usually has one of these via the **AIX Toolbox for Linux
  Applications** (often under `/opt/freeware/bin`) or `bos.net.tcp.client`. If neither is present,
  you can download the binary on another machine and `scp`/`ftp` it across manually — the install
  script's error message walks through that fallback.
- Confirm the DB tier's AIX/PowerPC identity: `uname -s` → `AIX`, `uname -p` → `powerpc`. The agent
  binary is `ppc64` — AIX only ever runs on Power hardware, so there's no arch choice to make.

## 2. Create a least-privilege Oracle monitoring user

**Do not use the `APPS` account or any EBS application schema for this.** Create a dedicated
account with only the read privileges the agent needs, as a DBA:

```sql
CREATE USER metasight_monitor IDENTIFIED BY "a-strong-unique-password";
GRANT CREATE SESSION TO metasight_monitor;
GRANT SELECT ON V_$SESSION TO metasight_monitor;
GRANT SELECT ON V_$SQL     TO metasight_monitor;
-- Only if you intend to enable --block later (see step 6 — not recommended to start with):
-- GRANT ALTER SYSTEM TO metasight_monitor;
```

If MetaSight will also run **schema-wise discovery / the query gateway** against this same EBS
database (not just DAM monitoring), that's a separate `DataSource` registered in MetaSight itself
(step 7) — it typically needs broader `SELECT` on the schemas you want cataloged, and is a
different credential/decision from this DAM monitoring user. Keep them separate.

## 3. Register the agent in MetaSight (the "from frontend" step)

1. Log into MetaSight → **Settings → Agents**.
2. **New Agent** → mode **DB**, DB type **Oracle**, give it a name (e.g. `ebs-prod-aix`).
3. Click **Register & Generate API Key** — copy the key, it's shown once.
4. Open the agent's row → the **Install Agent** panel → OS selector → **AIX (PowerPC)**.
5. Fill in the connection fields (DB Host, Port `1521`, Service Name/SID, DB Username
   `metasight_monitor`, password) and the access policy (authorized users/IPs, blocked ops) — the
   command in the panel updates live as you type. Read the amber EBS-specific notes shown there
   about the SID/service-name field and about leaving Block Mode off initially.
6. Copy the generated command from whichever tab suits you:
   - **One-liner (curl)** — fastest, pipes `install-agent-aix.sh` straight into `sh`.
   - **Manual** — download + run in the foreground (good for a first test).
   - **Inittab Service** — download + register as a persistent `/etc/inittab` "respawn" entry
     (what you want for production — AIX has no systemd, so this is the equivalent of
     `systemctl enable --now`).

## 4. Run it on the AIX host

Paste the copied command over an SSH session to the AIX DB tier, as root. The one-liner looks like:

```sh
curl -sSL https://metasight.example.com/downloads/install-agent-aix.sh | \
  MS_SERVER=https://metasight.example.com \
  MS_API_KEY=<key-from-step-3> \
  MS_DB_TYPE=oracle \
  MS_DB_HOST=localhost \
  MS_DB_PORT=1521 \
  MS_DB_NAME=<EBS SID or service name> \
  MS_DB_USER=metasight_monitor \
  MS_DB_PASSWORD=<password> \
  MS_AUTHORIZED_USERS=metasight_monitor,apps \
  MS_AUTHORIZED_IPS=10.0.0.0/8 \
  sh
```

This downloads `metasight-agent-aix-ppc64` to `/usr/local/bin/metasight-agent`, writes
`/etc/metasight/agent.env` (mode 600), writes a small run wrapper, and registers it in
`/etc/inittab` under the identifier `metasight` with the `respawn` action — init restarts it
whenever it exits, the AIX equivalent of `Restart=on-failure`. It then runs `telinit q` so it
starts immediately, without a reboot.

Set `MS_SERVER` to `https://...`. The agent logs a warning at startup if it isn't, and the DB
password, API key, and captured SQL text all transit in the clear over plaintext HTTP otherwise.

## 5. Verify

```sh
ps -ef | grep metasight-agent           # process running
tail -f /var/log/metasight-agent/agent.log
lsitab metasight                        # confirm the inittab entry
```

In MetaSight → Settings → Agents, the agent should flip to **online** within a heartbeat interval
(60s), and its event feed should start showing entries once there's DB activity to observe.

## 6. Connect a monitored DataSource for schema-wise discovery (optional, separate from DAM)

If you also want MetaSight to catalog EBS's schemas and enforce policies through the query
gateway (not just watch for direct-access sessions via the agent above), add a **DataSource** in
MetaSight → Data Sources → **Add** → type **Oracle**:

| Field | Value |
|---|---|
| Host | the EBS DB tier host/IP |
| Port | `1521` (or your listener's port) |
| Service Name / SID | same value you used for the agent — see the troubleshooting note below |
| Username / Password | a read-focused catalog account (not `APPS`, not the DAM monitoring user) |
| Thick Mode | **leave unchecked** |

Leaving **Thick Mode unchecked** is the "thin client" behavior you asked for — MetaSight's backend
uses `python-oracledb` in thin mode by default (pure Python, no Oracle Instant Client), so nothing
needs to be installed on the MetaSight server for this either.

EBS databases typically have 200+ schemas. Run the first full discovery scan during a maintenance
window, and consider scoping schema selection to what you actually need cataloged first (the core
financials/HR schemas — `GL`, `AP`, `AR`, `PO`, `INV`, `HR`, `PAY`, etc. — rather than every
EBS-internal schema) before expanding scope.

## Troubleshooting

- **`ORA-12514: TNS:listener does not currently know of service`** — the Service Name/SID you
  entered doesn't match what the listener has registered. Run `lsnrctl status` on the DB tier to
  see the exact `SERVICE_NAME` values, and use one of those. EBS almost always auto-registers the
  instance's SID as a matching service name, so entering the SID directly usually works — this
  error means it didn't, in this particular environment.
- **Neither curl nor wget on the AIX host** — download `metasight-agent-aix-ppc64` from
  `https://your-metasight-server/downloads/metasight-agent-aix-ppc64` on any machine with network
  access, then `scp`/`ftp` it to `/usr/local/bin/metasight-agent` on the AIX host, `chmod 755` it,
  and run the **Manual** tab's steps 2 onward (skipping the download).
- **Agent shows offline in the UI** — check `/var/log/metasight-agent/agent.log` for connection
  errors to `MS_SERVER`; confirm outbound HTTPS/8000 isn't blocked by a firewall between the DB
  tier and the MetaSight server.
- **Uninstalling** — `rmitab metasight` (stops future auto-restart), then find and kill the running
  process (`ps -ef | grep metasight-agent`), then optionally remove
  `/usr/local/bin/metasight-agent`, `/usr/local/bin/metasight-agent-run.sh`, `/etc/metasight/agent.env`.
- **Re-running the installer** (e.g. to change connection details) is safe — it overwrites the env
  file and updates the existing inittab entry (`chitab`) rather than duplicating it.

## A note on Block Mode for this environment

The agent's `--block`/Block Mode terminates sessions it judges unauthorized. On an EBS database,
the process holding an "unexpected" session might be a concurrent manager, a middle-tier
connection pool member, or a scheduled job — not just an interactive SQL client. Start with Block
Mode **off** (alert-only), watch the event feed for a representative period (through a normal
batch/concurrent-processing cycle), and only enable blocking once `MS_AUTHORIZED_USERS` /
`MS_AUTHORIZED_IPS` are scoped tightly enough that you're confident nothing legitimate will match
as unauthorized. See `SECURITY_AUDIT.md` for the agent's blocked-ops detection limitations before
relying on it as a hard enforcement boundary rather than a tripwire.
