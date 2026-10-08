# Runbook: DefectDojo release upgrade

DefectDojo holds every finding and every triage decision, so it is the most valuable data on the machine. It is upgraded **one release at a time, after the contract tests passed on a copy**
(design, "Upgrades"). The version is pinned in `deploy/.env` (`DJANGO_VERSION`, `NGINX_VERSION`), in `deploy/images.lock.yaml` (`DD_DJANGO`, `DD_NGINX`, `DD_VALKEY`) and by the
vendored upstream Compose file `deploy/defectdojo/upstream/docker-compose.yml`, which `deploy/defectdojo/override.yaml` adapts.

Shorthand `sc`, `psql`: `docs/install.md`.

## 1. Prepare (days before)

1. Read the release notes of **every** release between the current one and the target. Look for: changes to the REST API (`/api/v2/reimport-scan/`, `findings`, `users`, `system_settings`), database migrations that need manual steps, new settings, renamed Compose services, new parsers.
2. Fetch the target's Compose file and compare it with the vendored one:
   `curl -fsSL https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/<tag>/docker-compose.yml -o /tmp/dd-upstream.yml && diff deploy/defectdojo/upstream/docker-compose.yml /tmp/dd-upstream.yml`
   `override.yaml` relies on the service names `nginx`, `uwsgi`, `celerybeat`, `celeryworker`, `initializer`, `postgres`, `valkey`, the entrypoint scripts and the `defectdojo_media` volume (header of the override file). If any changed, adapt `override.yaml` first.
3. Prepare the copy: a **spare machine** with the same release of SecureScan, restored from last night's backup (`docs/runbooks/restore.md`). (The Compose project and volume names are fixed, so a copy cannot share a machine with production.)

## 2. Contract tests on the copy

1. On the copy, edit `deploy/.env` (`DJANGO_VERSION`, `NGINX_VERSION`) and `deploy/images.lock.yaml` (tags of `DD_DJANGO`, `DD_NGINX`, and `DD_VALKEY` if upstream changed it), replace `deploy/defectdojo/upstream/docker-compose.yml`, then
   `python3 scripts/dev.py pin-images && python3 scripts/dev.py pull-images && python3 scripts/dev.py up`.
2. Wait for the `initializer` to finish (`sc logs -f initializer`); `sc logs dojo-init` must end without an error.
3. Run the contract tests (they import each fixture report into DefectDojo and assert a non-zero finding count and the expected severities):
   `python3 scripts/dev.py test contract` (needs `uv` on the copy, or run the same pytest command inside a backend container).
4. Run the regression suite: `sc exec worker python -m securescan.domain.regression run --kind all`.
5. Import a real scan on the copy and compare: the number of findings per product before and after (`psql "select application_id, count(*) from finding_history group by 1"` is SecureScan's side; DefectDojo's UI shows the product counts), and that `history_state_refresh` still reads triage states.

If anything fails, stop; production is untouched. Record what broke (`docs/decisions.md`) and either fix the integration code or wait for a later DefectDojo release.

## 3. Production window

1. Quiet the platform (`release-upgrade.md`, step 1) and take a backup: `bash scripts/backup.sh`.
2. Apply exactly what you tested: the same `deploy/.env`, `deploy/images.lock.yaml` and upstream/override files (commit them on a branch and check that out).
3. `python3 scripts/dev.py pin-images && python3 scripts/dev.py pull-images && python3 scripts/dev.py up`. The `initializer` runs DefectDojo's database migrations; it can take several minutes on a large database.
4. `sc logs dojo-init`: it re-creates what it needs and says what it changed.

## Verify

- DefectDojo opens through the portal; products and findings are there; the version in the footer is the target.
- Import a scan of `python-planted`; the job reaches `imported`; the new findings appear in the product.
- Settings -> DefectDojo and imports: no failures; the import lag and dead-letter metrics are 0; SecureScan's history counts did not change.

## Roll back

DefectDojo's migrations are not reversible. Rolling back means restoring: `python3 scripts/dev.py down --volumes`, check out the old tag and bring the stack up from the backup of step 3.1 (`docs/runbooks/restore.md`).
Imports made after the upgrade are lost from DefectDojo but their raw reports are in the artifacts volume: re-import them after the restore (Settings -> DefectDojo and imports, replay).
