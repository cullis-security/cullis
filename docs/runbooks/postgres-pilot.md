# Postgres Pilot Runbook (Mastio)

Status: opt-in. Target audience: SRE / SecOps running a Cullis Mastio
in production. Scope: switch the Mastio persistence layer from the
default embedded SQLite to a Postgres instance, for pilots where the
SQLite single-writer bound is the limiting factor.

The default bundle ships SQLite and that path stays the supported
default. Postgres is opt-in and intentionally so: it adds a network
hop, an upgrade window, and a backup story that the embedded SQLite
file does not.

---

## 1. When to switch

Stay on SQLite by default. Plan a switch to Postgres when one or more
of the following hold on the live Mastio:

- **Concurrent principals.** Sustained 50-100+ user principals (ADR-020
  / ADR-021 shared-mode Frontdesk). SQLite serialises write
  transactions; under that level of concurrency the audit-chain insert
  queue starts forming.
- **Audit write rate.** Sustained 100+ audit rows / second
  (`local_audit` + `audit_chain`). Audit is append-only and the chain
  insert holds a row-level reservation while it computes the next hash;
  on SQLite that is a write transaction.
- **Audit insert p95.** p95 latency on the audit-chain write path above
  200 ms during normal operation. That is the early warning that the
  single-writer queue is no longer absorbing burst.
- **Multi-customer Frontdesk.** Second or third customer on the same
  Frontdesk bundle. Even modest per-customer load multiplies on shared
  infra.
- **Measured load.** As a calibration point, a Mastio standalone under
  500 VU sustained k6 traffic shows p99 around 8.7 s on SQLite (4
  uvicorn workers, single audit chain, in-memory rate-limit). That
  number is the SQLite ceiling on commodity hardware: if your pilot
  needs headroom above the single-writer pinch, Postgres is the move.

If none of the above apply, do not switch. SQLite has a smaller
operational surface (no second process, no network, backup = `cp`).

---

## 2. Pre-requisites

- Postgres 16. Earlier 14 / 15 work but 16 is what the migration chain
  is tested against.
- Database reachable from the Mastio container. For the bundle that
  means the Mastio docker network must be able to resolve the Postgres
  host. Either run Postgres inside the same compose project (see the
  sandbox overlay below) or expose the existing Postgres on a hostname
  the Mastio container resolves.
- A database, a role, and a password. The role needs `CREATE`,
  `USAGE` on the schema, plus `SELECT / INSERT / UPDATE / DELETE` on
  every table the alembic chain creates (the simplest grant is
  ownership of the database).
- `asyncpg` is the driver. The Mastio image already bundles it; no
  client-side install needed.
- Outbound TCP from the Mastio container to the Postgres port (default
  5432). If you front Postgres with pgBouncer, use transaction-pool
  mode; SQLAlchemy + asyncpg do not coexist with session-pool mode
  unless you pin every connection.

---

## 3. Deploy: Frontdesk bundle against an external Postgres

The Mastio bundle wires `MCP_PROXY_DATABASE_URL` into the container at
compose time (`packaging/mastio-bundle/docker-compose.yml`). The default
points at SQLite under `/data/mcp_proxy.db`. To target Postgres, set
the env var in `proxy.env` before the next `./deploy.sh` run.

### 3.1 Provision Postgres

For a pilot on a single host, the minimal docker invocation is:

```
docker run -d \
  --name cullis-pg \
  --restart unless-stopped \
  -e POSTGRES_DB=mastio \
  -e POSTGRES_USER=cullis \
  -e POSTGRES_PASSWORD='change-me' \
  -v cullis-pg-data:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:16-alpine
```

That is a pilot-grade Postgres, not production. For production: managed
service (RDS / Cloud SQL / Aiven), or a stateful set with PITR, plus a
backup destination outside the host.

Verify the database accepts connections:

```
docker exec -it cullis-pg \
  psql -U cullis -d mastio -c '\dt'
```

Expected: empty list (no tables yet). The Mastio alembic chain creates
everything on first boot.

### 3.2 Edit `proxy.env`

Open `packaging/mastio-bundle/proxy.env` (the live file, not
`proxy.env.example`) and add or uncomment:

```
MCP_PROXY_DATABASE_URL=postgresql+asyncpg://cullis:change-me@HOST:5432/mastio
```

Where `HOST` is whatever hostname the Mastio container can reach.
Common cases:

- Postgres on the same host as the bundle: `host.docker.internal` on
  Linux works once you add `extra_hosts:` to the `mcp-proxy` service,
  or use the docker bridge gateway IP (`172.17.0.1` by default). The
  sandbox overlay (section 6) avoids this by putting Postgres on the
  bundle network.
- Postgres on a separate VM / managed service: the hostname your DNS
  resolves to.

The Mastio bundle reads `MCP_PROXY_DATABASE_URL` from `proxy.env` and
forwards it into the container (see `docker-compose.yml` line 95).
`PROXY_DB_URL` (ADR-001 Phase 1.3) is also accepted and takes
precedence when both are set; the bundle does not export it by default,
so leaving `MCP_PROXY_DATABASE_URL` alone is the canonical path.

### 3.3 Boot

```
./deploy.sh --pull
```

Always go through `deploy.sh`, never plain `docker compose up`. The
script sets `COMPOSE_PROJECT_NAME=cullis-mastio`; a bare compose call
derives the project name from the directory and silently spawns a
parallel stack with empty volumes.

The first boot will:

1. Acquire a Postgres advisory lock (`pg_advisory_lock` key
   `0xC0115A1E_EB1C0DE`, see `mcp_proxy/db.py:50`). Multi-worker
   uvicorn is safe: only the leader runs alembic, the rest wait then
   no-op.
2. Run the alembic chain to head against the empty database.
3. Generate a new Org CA and derive `org_id` from it (the standard
   ADR-006 first-boot path).

Watch for the bundle's startup guard. If `./data/mcp_proxy.db` already
exists from a previous SQLite boot, `deploy.sh` will refuse to start
(`_check_sqlite_orphan_vs_postgres`, line 155 of `deploy.sh`) because
the new Postgres-backed Org CA would silently invalidate every already
enrolled Connector. Section 4 covers that path.

### 3.4 Verify the dialect

```
docker compose -p cullis-mastio logs mcp-proxy 2>&1 \
  | grep -i 'Database initialized'
```

Expected line:

```
Database initialized (alembic upgrade head): postgresql+asyncpg://...
```

The presence of `postgresql+asyncpg://` is the confirmation. If you
see `sqlite+aiosqlite:////data/mcp_proxy.db`, the env var did not make
it into the container; check `proxy.env` is sitting next to
`docker-compose.yml`, and that `deploy.sh` reported reading it.

---

## 4. Migration from an existing SQLite Mastio

The bundle has no in-place SQLite to Postgres migration, and the
bundle guard rejects the swap to prevent silent CA loss. This is by
design (ADR-030 fresh-deploy convention). The bundle data model is
small (audit chain + agent registry + policy snapshots) but the Org
CA derivation is one-way: switching the persistence layer mints a
new CA on first boot, which invalidates every previously enrolled
Connector at TLS handshake time.

Two supported paths:

### Path A. Fresh deploy, no audit history carried over

1. Export the audit history for offline retention:
   `cp data/mcp_proxy.db data/mcp_proxy.db.archive-$(date +%F).bak`.
   The file is a single SQLite database, queryable with any sqlite3
   client.
2. Remove the SQLite artefacts and the Org CA so the bundle starts
   clean:
   `./deploy.sh --down` first, then either delete `./data/` and
   `./nginx-certs/` manually, or re-run with `--accept-data-loss`
   (`deploy.sh:173`) which garbage-collects `mcp_proxy.db` plus its
   WAL / SHM sidecars after warning you on stderr.
3. Re-run `./deploy.sh --pull` with the Postgres
   `MCP_PROXY_DATABASE_URL` in `proxy.env`. A new Org CA is minted,
   `org_id` changes, every Connector needs to re-enroll.
4. Re-enroll every Connector via the dashboard (`/proxy` → invite
   token), or by re-issuing device-code flows.

### Path B. Roll back the experiment

If you set `MCP_PROXY_DATABASE_URL` to Postgres, hit the bundle
guard, and want to back out:

1. Edit `proxy.env`, comment out the `MCP_PROXY_DATABASE_URL=`
   line (or set it back to the SQLite default).
2. `./deploy.sh --pull`.
3. Mastio comes back up against the existing SQLite DB. Every
   previously enrolled Connector keeps working.

There is no Path C. Do not point an existing Mastio at an empty
Postgres "to see what happens": the silent CA mint cascades into 401
on every Connector and there is no easy undo.

---

## 5. Multi-worker uvicorn

Already handled. PR #759 added leader-election via the Postgres
advisory lock (`mcp_proxy/db.py:50, 277-293`) so concurrent uvicorn
workers serialise the alembic upgrade through `pg_advisory_lock`.
SQLite gets equivalent protection through `fcntl.flock` on a sidecar
file (`db.py:126-164, 294-300`). No operator action required when
scaling workers, the gate is automatic.

Connection pool sizing for Postgres is also fixed in code:
`_engine_kwargs` (`db.py:55-72`) sets `pool_size=20`,
`max_overflow=10`, `pool_timeout=5.0`. SQLite is single-writer so the
pool knobs are no-ops there. Adjust the pool only if you observe DB
pool exhaustion in logs.

---

## 6. Sandbox quick-try (optional)

A docker-compose overlay is shipped under
`sandbox/overlays/postgres.yml`. It adds a Postgres service to the
sandbox bundle and overrides `MCP_PROXY_DATABASE_URL` on both
`proxy-a` and `proxy-b`. Useful to dogfood the Postgres path locally
before targeting a real customer bundle.

Quick run:

```
./sandbox/demo-postgres.sh up
./sandbox/demo-postgres.sh down
```

That wrapper is equivalent to:

```
docker compose -f sandbox/docker-compose.yml \
  -f sandbox/overlays/postgres.yml \
  --profile full up -d --wait
```

The overlay puts Postgres on `orga-internal` and `orgb-internal`, with
healthcheck, so the Mastio containers wait for the database to be
ready before booting.

---

## 7. Operational verification

Open `psql` against the database and run:

```sql
-- Schema came up.
\dt
-- Expected: internal_agents, audit_chain, local_audit, principal_*,
-- session_keys, plus the alembic_version row.

-- Alembic is at head.
SELECT version_num FROM alembic_version;

-- Agents registered.
SELECT count(*) FROM internal_agents;

-- Audit chain tip.
SELECT max(seq) AS last_seq FROM audit_chain;

-- Sustained audit write rate (sample over a known window).
SELECT count(*) FROM local_audit
 WHERE created_at > now() - interval '60 seconds';
```

These are the four numbers SRE will care about: schema present,
alembic current, agent registry populated, audit chain advancing.

Pool health from the Postgres side:

```sql
SELECT state, count(*)
  FROM pg_stat_activity
 WHERE datname = 'mastio'
 GROUP BY state;
```

A healthy Mastio shows a small `idle` pool (under the 30 cap from
`pool_size + max_overflow`) and `active` only spikes during request
bursts.

---

## 8. Rollback

The SQLite path is always available. To roll back:

1. Stop Mastio: `./deploy.sh --down`.
2. Comment out or remove `MCP_PROXY_DATABASE_URL` from `proxy.env`.
3. Restore the previous SQLite file if you archived one
   (`cp data/mcp_proxy.db.archive-YYYY-MM-DD.bak data/mcp_proxy.db`)
   and verify ownership: the bundle's `init-permissions` step (runs
   on every `up`) will chown `/data` to UID/GID 10001 either way, so
   the restored file is readable.
4. `./deploy.sh --pull`.

The Connectors enrolled against the SQLite Org CA come back online
immediately. The Postgres database is left running but unused; drop
it at leisure.

---

## 9. Known limitations (pilot scope)

- **No in-place migration.** SQLite to Postgres is a fresh deploy.
  Out of scope for the pilot. The bundle refuses to do it silently
  (`deploy.sh:155-211`).
- **No PITR helper.** Backup and point-in-time recovery are on the
  operator. Recommended: managed Postgres (RDS / Cloud SQL / Aiven)
  with backup retention configured at the provider; or self-host with
  `pg_basebackup` + WAL archiving to object storage.
- **No replication.** Single-primary only. Read replicas, multi-AZ,
  HA failover are out of scope for the pilot; Mastio holds one
  `AsyncEngine` against one URL.
- **No connection pooler integration.** pgBouncer works in
  transaction mode; session mode is not supported. Most pilots will
  not need a pooler at the load levels that trigger the SQLite to
  Postgres move (the SQLAlchemy pool of 30 connections per worker is
  sufficient).
- **One bundle, one database.** Two Mastios cannot share a Postgres
  schema; the Org CA, audit chain seq, and agent registry are
  per-Mastio.

---

## 10. Performance baseline

Captured here post-pilot. Today this is a template; fill in once you
run k6 against the Postgres-backed Mastio under the same load profile
that informed the SQLite ceiling.

Reference SQLite numbers (Mastio standalone, 4 workers, in-memory
rate-limit, k6 health-throughput scenario):

| Scenario | VU  | Duration | p50   | p95   | p99   | Errors |
|----------|-----|----------|-------|-------|-------|--------|
| SQLite   | 500 | 5 min    | TBD   | TBD   | 8.7 s | 0      |
| Postgres | 500 | 5 min    | TBD   | TBD   | TBD   | TBD    |

The dogfood prompt for the Postgres run lives in
`imp/c2-stress-mastio-local-pyspy-prompt.md` (local-only); copy the
production-container note about `py-spy` and `SYS_PTRACE` if you plan
to profile while the load test runs.

---

## 11. References

- Persistence layer: `mcp_proxy/db.py`. Engine kwargs, alembic
  gating, advisory lock.
- Config precedence: `mcp_proxy/config.py:158-162` and `:519-524`
  (PROXY_DB_URL > MCP_PROXY_DATABASE_URL > SQLite default).
- Bundle entry point: `packaging/mastio-bundle/deploy.sh`. The
  `_check_sqlite_orphan_vs_postgres` guard is the safety net against
  silent CA loss.
- Helm chart: `deploy/helm/cullis-mastio/`. The `_helpers.tpl`
  database URL helper resolves external override, internal
  StatefulSet, then SQLite default.
- ADR-001 (intra-org routing, Phase 1.3 introduced PROXY_DB_URL).
- ADR-006 (Org CA derivation, first-boot path).
- ADR-030 (bundle persistence layout, fresh-deploy convention).
- Test reference: `tests/test_proxy_migrations.py:262-279` runs the
  alembic chain against a live Postgres when `TEST_POSTGRES_URL` is
  set.
