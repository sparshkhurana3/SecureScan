# Runbook: performance, the seeded test, and growth

Design target: **95 percent of page loads under 2 seconds with 300 applications and five years of history**; the history CSV export streams the whole filtered result (the first bytes arrive within the same 2 seconds).
`scripts/seed_history.py` creates that load on a *test* database and times the queries the portal runs. It was written without a database to run it against: the first Ubuntu run produces the numbers, and this runbook says what to do with them.

## 1. Seed a test database (never production)

History is permanent by design and the seeder deletes rows when asked to clean up, so use a **separate test stack** (a spare machine, or a throwaway Compose project on a development machine). The script refuses to run without
`--i-know-this-is-a-test-database`, refuses to seed a database that holds real applications, and names everything `SYN-...` (tag `synthetic`).

The database is reachable only on the Compose network, so run the script in a container on `securescan_backend` (the backend image has psycopg):

```
docker run --rm --network securescan_backend --read-only --tmpfs /tmp \
  -v "$PWD/scripts/seed_history.py:/seed_history.py:ro" \
  -v "$PWD/deploy/secrets/securescan_db_password:/run/secrets/pw:ro" \
  -v "$PWD/deploy/secrets/tls/ca.crt:/run/secrets/ca:ro" \
  --entrypoint python securescan/backend:dev /seed_history.py \
  --host db --dbname securescan --user securescan --password-file /run/secrets/pw --sslrootcert /run/secrets/ca \
  --i-know-this-is-a-test-database
```

Defaults: 300 applications, 5 years, about 20 scans per application and year, four tools per scan, about 30 live findings per application: roughly 30 000 scans, 110 000 jobs and **one million history rows** (a few hundred MB). Smoke run first:
add `--apps 30 --years 1 --scans-per-app-year 6`. `--dry-run` generates and checks the data without a database (no psycopg needed). Scale it to the design's sizing (100 scans a day) with `--scans-per-app-year`.

The output lists the load time per table and then the query timings, for example:

```
  [ok  ] history: critical, vendor apps, this year (page)     median    12.3 ms  p95    19.8 ms
  [ok  ] CSV export, 2 years: first byte 0.04 s, 640000 rows, 95.2 MB in 21.7 s
```

`SLOW` marks a query whose 95th percentile is over `--target-seconds` (2). The exit code is 1 when anything is slow. `--benchmark-only` times the queries again after a change; `--clean` removes the synthetic rows.

## 2. Read the numbers

Timed shapes (the portal's list, filter, count and detail queries; the exact SQL is in `queries()` of the script): the applications page, an application's scan list, a scan's findings (Critical first), the history filters (severity + vendor + this year; tool + window; one application), the
scan list in a window, the dashboard counts, and the CSV export (first byte, total). If a page of the portal is slow but these are fast, the cause is not the database: look at the API latency histogram (`SecureScanApiLatency`) and `sc logs api`.

For a slow query take its plan on the seeded database:

```
sc exec -T db psql -U securescan -d securescan -c "EXPLAIN (ANALYZE, BUFFERS) <the query>"
```

## 3. Indexes

Existing (from the initial migration): `finding_history (application_id, severity, scanned_at)`, `(scan_id)`, `(dd_finding_id)`, `(hash_code)`, `(scanned_at)`, `(tool, scanned_at)`; `scans (application_id, created_at)`, `(state)`, `(version_id)`, `(created_at)`;
`scan_jobs (state)`, `(scan_id)`, `(import_state)`; `applications (type)`, `(vendor_id)`, `(last_scan_at)`.

Candidates, **to be added only when `EXPLAIN` on the seeded database shows a sequential scan or a sort that the timings blame** (each is an Alembic revision `0003_...` created with `op.create_index(..., postgresql_concurrently=True)` in an
autocommit block; never create indexes by hand on production, and test the migration on the seeded copy first):

| Filter that may be slow | Candidate index |
| --- | --- |
| severity (and date) across all applications, for example "every critical finding this year" | `finding_history (severity, scanned_at DESC)` |
| vendor-wide history ("every finding in vendor applications") | `finding_history (vendor_id, scanned_at DESC) WHERE vendor_id IS NOT NULL` |
| open findings of one application (the application page's counts) | `finding_history (application_id) WHERE state_now = 'open'` |
| a scan's open findings, Critical first | `finding_history (scan_id, state_now)` |
| text search in titles | `pg_trgm` GIN on `lower(title)`, only if analysts use the title filter heavily; needs the extension, so discuss first |

Record the decision, the before and after timings and the migration number in `docs/decisions.md`.

## 4. PostgreSQL settings

The `db` container starts with PostgreSQL's small default memory settings (it holds three databases on a machine with tens of GB). Set them once with `ALTER SYSTEM` (stored in the data directory, applied at the next restart) and restart the `db` container in a window:

```
sc exec -T db psql -U postgres -c "ALTER SYSTEM SET shared_buffers = '4GB'"
sc exec -T db psql -U postgres -c "ALTER SYSTEM SET effective_cache_size = '16GB'"
sc exec -T db psql -U postgres -c "ALTER SYSTEM SET work_mem = '32MB'"
sc exec -T db psql -U postgres -c "ALTER SYSTEM SET maintenance_work_mem = '512MB'"
sc restart db
```

Sensible values for the recommended 64 GB machine (the container is limited to 12 GB of memory in `deploy/compose.yaml`: `shared_buffers` plus `work_mem` times concurrent sorts must stay well inside it). `shm_size` of the container is 512 MB.
Autovacuum is on by default; after a bulk load run `ANALYZE` (the seeder does).

## 5. Growth and disk

- History, reports and raw reports are never deleted automatically. Estimate from the seeded test: the size of `finding_history` per million rows, plus about 1 MB per scan of raw reports and SBOMs in the artifacts volume. Alert at 80 percent (`SecureScanDiskUsage`; for the Docker volume itself use `node_exporter` on `/var/lib/docker`).
- The three volumes that grow: `securescan_pgdata`, `securescan_artifacts`, `securescan_defectdojo_media`. Move Docker's data root to a larger disk (`data-root` in `/etc/docker/daemon.json`, stack stopped, `rsync -a`), or grow the filesystem (LVM).
- DefectDojo's findings also grow; its database is in the same PostgreSQL. Backups grow with all of it: size the off-machine target for one set per night times the retention you keep there.

## 6. Capacity steps (design, "Growing on one machine")

1. Raise the concurrency caps (`SECURESCAN_WORKER_CONCURRENCY`, the `max_parallel` of a tool in `scanners/catalogue.yaml`, and the container limits in `deploy/compose.yaml`) while CPU and memory allow.
2. Add CPU, memory and disk to the machine.
3. Move to a larger machine with the restore procedure (`docs/runbooks/restore.md`), which doubles as the migration path.
