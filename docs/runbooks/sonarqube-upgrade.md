# Runbook: SonarQube upgrade (the December rule)

SonarQube Community Build has monthly releases and no long-term line. Sonar requires that a **year boundary is crossed only through the December build**: from `26.9` you
may go to any later 26.x build, but only from `26.12` may you go to a 27.x build, and never two calendar years at once. SecureScan encodes this: the monthly image proposals offer a SonarQube build of a later
calendar year only when the current build is the December build of its year, and approving a proposal re-checks it (`image.december_rule`). Builds are named `<YY>.<month>.<patch>.<build>-community`; the server and the scanner are separate images (`sonarqube`, `sonarsource/sonar-scanner-cli`).

The server is not a Compose service: the worker creates the `sonarqube` container from the catalogue when a scan needs it and stops it after 15 idle minutes. Its data is the `sonarqube` database
(in the shared PostgreSQL) and the volumes `securescan_sonarqube_data`, `_extensions`, `_logs`.

Shorthand `sc`, `psql`: `docs/install.md`. Approving and rolling back proposals: `docs/runbooks/approving-image-digest.md`.

## 1. Before you approve

1. Which build runs now? `psql "select tool, tag, active from image_versions where tool like 'sonarqube%' and active"`; if no row is active, the lock file's tag runs (`grep SONARQUBE deploy/images.lock.yaml`).
2. Is the proposal allowed? Proposals for `sonarqube-server` are in the monthly list (state *pending*). If the current build is not a December build you only see builds of the current year. Upgrade through December first; do not look for a way around it.
3. **Back up first**: `bash scripts/backup.sh`. The SonarQube database schema is upgraded on first start of the new version and the old version cannot read it afterwards.
4. Read Sonar's release notes for each build since the current one (breaking changes to rules, the analysis mode "Standard Experience", scanner compatibility). The scanner image proposal must match: approve the server and the scanner proposals in the same sitting.

## 2. Approve and apply

1. Approve the `sonarqube-server` proposal, then the `sonarqube` (scanner) proposal. The regression gate cannot test the **server** image (the lifecycle task creates the container, not the scan job, so the gate cannot swap it in and verify it), so that proposal is always *skipped* and the approval needs your acknowledgement, which means: **you** test it by hand (step 3). The scanner proposal is gated like any other tool, and is *skipped* too while no SonarQube expectation is `verified: true`.
2. The worker uses the new image the next time it creates the container. To apply at once, with no scan running: `docker stop sonarqube && docker rm sonarqube` (the stop takes up to 5 minutes; do not kill it).
3. Start a SonarQube scan of `java-planted` (SAST scan, profile `code-standard`, tool SonarQube only). The first start of a new build migrates the schema (slower than usual; the metric `securescan_sonarqube_start_seconds` shows it, the alert fires over 5 minutes).
   If the server reports `DB_MIGRATION_NEEDED` instead of `UP`, send the migration request from inside the Compose network (SonarQube answers it without a token):
   `sc exec -T worker python -c "import urllib.request as u; print(u.urlopen(u.Request('http://sonarqube:9000/api/system/migrate_db', method='POST', data=b'')).read())"`
   (check `docs/spikes/s3-sonarqube.md` for what spike S3 recorded about this on the pinned build).

## Verify

- The job reaches `imported`; the report's code-quality section shows the quality gate; the DefectDojo product has a SonarQube test with the issues of `java-planted`.
- `sc exec -T worker python -c "import urllib.request as u; print(u.urlopen('http://sonarqube:9000/api/system/status').read())"` (while the container runs) shows the new version.
- `docker ps` shows `sonarqube` only during and 15 minutes after the job.

## Roll back

Deactivating the proposal returns scans to the previous *image*, but the database schema is already upgraded and the old build refuses to start on it. To go back:

1. `docker stop sonarqube && docker rm sonarqube` and deactivate the image rows (`approving-image-digest.md`).
2. Restore only the SonarQube database from the backup of step 1.3:
   ```
   age -d -i <age key file> /srv/restore/<set>/db-sonarqube.dump.age | sc exec -T db pg_restore -U postgres -d sonarqube --clean --if-exists --single-transaction --exit-on-error --no-password
   ```
3. Run a SonarQube scan to confirm.

## Record

The old and new builds, the date, the backup set used, the result of the hand test (and, when you did it, the `expected-findings.yaml` entries you could mark `verified: true` for SonarQube).
