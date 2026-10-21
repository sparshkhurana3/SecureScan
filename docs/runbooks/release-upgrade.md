# Runbook: SecureScan release upgrade

A release is a versioned Compose bundle: the repository at a tag (backend, portal, `deploy/`, `scanners/`, `docs/`). Releases are never automatic. Plan one per quarter, in a
maintenance window announced to the security team (design, "Upgrades"). DefectDojo has its own runbook (`defectdojo-upgrade.md`);
a release that also bumps it is done in two steps, each with its own backup.

Shorthand `sc`, `psql`: `docs/install.md`.

## Before the window

1. Read the release notes and the diff of what operations touch:
   `git fetch --tags && git diff <current tag>..<new tag> -- deploy/ scanners/ docs/install.md docs/runbooks/ backend/pyproject.toml`
   Look for: new variables in `deploy/.env.example` (copy them into `deploy/.env`), new secrets (`deploy/secrets/README.md`), changed Compose services, new migrations
   (`backend/securescan/db/migrations/versions/`), changed images in `deploy/images.lock.yaml`.
2. Check the last backup is good: the metric `securescan_backup_last_success_timestamp` is from last night; `ls -l /var/backups/securescan`; ideally the quarterly restore drill passed on the previous release.
3. For a new PostgreSQL, Python or Node *major* version, stop: that is its own project (dump with the backup set, new `pgdata` volume, restore); ask the code owner.

## In the window

1. **Quiet the platform.** `psql "select state, count(*) from scans where state in ('queued','running') group by 1"`. Let the running scans finish (or cancel them in the portal). Tell users not to start new ones.
2. **Take a backup now** and keep its name: `bash scripts/backup.sh` (it must end `done`, with the copy off the machine verified).
3. **Get the release.**
   ```
   git fetch --tags && git checkout <new tag>
   git status                                    # clean except deploy/.env, deploy/images.env and deploy/secrets
   ```
4. **Images.** `python3 scripts/dev.py pin-images && python3 scripts/dev.py pull-images`. Review `git diff deploy/images.lock.yaml` (digests that changed are the release's decision). Image overlays approved in Settings stay in force until you retire them (below).
5. **Start the new release.** `python3 scripts/dev.py up`. This builds the backend and gateway images, then Compose runs `migrate` (Alembic upgrade and seeders) **before** `api` starts.
   ```
   sc logs migrate                               # ends without an error; "Running upgrade ... -> ..." lines for each new revision
   sc ps                                         # db, api, worker, gateway healthy; dojo-init exited 0 again
   ```

## Verify

- Settings -> System health: no red item. `sc logs --tail 50 worker` shows `worker_started` and the host check lines; `sc exec -T api python -c "import securescan; print(securescan.__version__)"` prints the new version.
- Smoke test of `docs/install.md` section 9, steps 4 to 7 (a scan of `python-planted`, its report, the CSV export, DefectDojo).
- `sc exec worker python -m securescan.domain.regression check` parses the expectation files; run `run --kind all` if the release changed scanners or the catalogue.
- Open Historical data and a report that existed before the upgrade.

## Roll back

- **The migration failed or the release is broken before any new data was written:** `git checkout <old tag>`, `python3 scripts/dev.py up`. The old code runs against the old schema only if no migration was applied; check `sc exec -T api alembic current` against the old release's head.
- **Migrations ran:** do not downgrade by hand. Alembic downgrades exist only where the release notes say so. The reliable path is the backup of step 2: `docs/runbooks/restore.md` (restore on this machine after `python3 scripts/dev.py down --volumes`, with the **old** tag checked out). Recovery point: the moment of step 2, because the platform was quiet.

## After

- Retire image overlays that the new `deploy/images.lock.yaml` now contains: for each active row in Settings (or `psql "select tool, tag, digest from image_versions where active"`), if the lock file has the same digest, deactivate the row (`approving-image-digest.md`); the lock file is the base again.
- Record the release tag, date, who did it and any deviation in the operations log; update the yearly review list if a dependency reached end of support.
