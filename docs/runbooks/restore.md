# Runbook: full restore, and the quarterly restore drill

Targets (design): recovery point **24 hours** (the nightly backup), recovery time **4 hours**. This runbook is both the emergency procedure (the machine is lost) and the drill that proves it
works: run it **every quarter on a spare machine**, and once before go-live. A backup that was never restored is a hope, not a backup.

What a backup set holds (`scripts/backup.sh`): the three PostgreSQL databases (`securescan`, `defectdojo`, `sonarqube`) in custom format, the roles, the `artifacts`, `defectdojo_media` and `data`
volumes (data without workspaces), a listing of the content volume, the configuration (`deploy/.env`, `images.env`, `images.lock.yaml`) and, unless switched off, `deploy/secrets` without the age key. Every part is
encrypted with age. **What a backup does not hold:** the rules, templates and vulnerability databases (the updaters rebuild them), SonarQube's search index (it rebuilds), the scanner images (pulled again).

You need three things that are *not* on the lost machine: the backup set (the off-machine target), the **age private key** (the vault), and a Linux machine prepared as in `docs/install.md` sections 2 and 3.

## 0. Roles and clock

Two people if possible: one operates, one writes down times. Start the clock at "machine available". Record in the table at the end.

## 1. Prepare the machine (about 30 minutes)

```
# packages and Docker: docs/install.md 2.1; kernel limits and log rotation: docs/install.md 2.2
sudo apt-get install -y ca-certificates curl git openssl python3 python3-yaml age rsync
git clone <the release repository> /opt/securescan && cd /opt/securescan && git checkout <the tag the backup came from, or newer>
bash scripts/check_host.sh                     # 0 failures
```

Which tag? `MANIFEST.txt` in the set says `release: <tag>`. A newer tag restores fine (the `migrate` container upgrades the schema), an older one may not.

## 2. Fetch the set and test it (about 15 minutes, depends on size)

```
mkdir -p /srv/restore && rsync -a backup@backuphost:/srv/securescan/securescan-backup-<timestamp> /srv/restore/
install -m 0600 /dev/stdin /srv/restore/age-key.txt        # paste the age private key from the vault, then Ctrl-D
bash scripts/restore.sh /srv/restore/securescan-backup-<timestamp> --identity /srv/restore/age-key.txt --check
```

`--check` verifies `SHA256SUMS` and decrypts every part to `/dev/null`. It must end "the set is complete and every part decrypts". If a checksum fails, fetch the set again; if decryption fails you have the wrong key.
Latest set first; if it is damaged, the previous night's set costs one more day of data.

## 3. Restore (about 1 to 2 hours)

The machine needs `deploy/secrets/tls/` for its names (the certificate is in the set's `secrets.tar.age` too, but a new machine may need a certificate for a new host name: place the new files before step 3 and run with `--keep-secrets`
if you want to keep yours) and the pulled images (`python3 scripts/dev.py pin-images && python3 scripts/dev.py pull-images`; with the restored `images.env` and `images.lock.yaml` this pulls exactly what the lost machine ran).

```
bash scripts/restore.sh /srv/restore/securescan-backup-<timestamp> --identity /srv/restore/age-key.txt
```

It asks you to type the project name, then: restores `deploy/.env`, `images.env` and the secrets (only when absent), creates the Compose project without starting it, starts `db` alone (its init script creates the roles and databases from the restored secrets),
`pg_restore`s the three databases, untars the volumes, starts the whole stack and waits for the api. Options: `--no-start` (restore and stop), `--skip-volumes`, `--keep-secrets`, `--yes` (no prompt).

If it fails: the message names the step. Fix the cause, remove the half-restored project with `python3 scripts/dev.py down --volumes`, and run it again. It refuses to run onto a project that already has containers or a PostgreSQL cluster, so it cannot overwrite a live system by accident.

## 4. Check (about 30 minutes)

1. Sign in to the portal (the host name and the Entra redirect URI must match; for a new host name add the new redirect URI to the app registration first).
2. Historical data: the scans and findings of the last day before the backup are there; the counts match what you recorded before (`psql "select count(*) from finding_history"` on the lost machine's last report, or the previous drill).
3. **Open a report that existed before the backup** (Historical data -> a scan -> its report, and download the PDF). This proves the artifacts volume and the database agree.
4. Open DefectDojo through the portal: products and findings are there; sign in with an existing DefectDojo account.
5. Settings -> System health: no red item. Settings -> GitHub connection -> Test passes (the App key is in the restored database or secrets); Settings -> credentials: the NVD key is listed.
6. Scanner content is empty after a restore: wait for the daily updates (Grype 07:30 UTC, NVD 03:00 UTC; Dependency-Check scans wait for the first NVD update, which takes hours) and the weekly rules and templates update, or start them (`content-update-failed.md`).
7. Run a scan of `python-planted`: it must reach `imported` and produce a report.
8. `bash scripts/backup.sh` on the restored machine: a new set, copied off, verified.

## 5. Real disaster, not a drill

- Point the DNS names at the new machine; the certificate must match; restore the **same host names** so cookies, the Entra redirect URI and DefectDojo's `DD_SITE_URL` stay valid.
- Tell users the recovery point (the time of the backup used): scans, reports and triage decisions made after that time are gone.
- Re-run what the lost machine did after the backup: findings triaged in DefectDojo after the backup have to be triaged again; GitHub changes since are picked up by the next poll.
- Take the lost machine's cron backup out of service; keep its last local sets until the new machine has a verified set.

## Restoring one database or one volume (not a disaster)

```
# one database (stop what uses it first; the stack stays up otherwise)
age -d -i /srv/restore/age-key.txt /srv/restore/<set>/db-sonarqube.dump.age | sc exec -T db pg_restore -U postgres -d sonarqube --clean --if-exists --single-transaction --exit-on-error --no-password
# one volume (an empty or freshly created volume; example: the artifacts)
age -d -i /srv/restore/age-key.txt /srv/restore/<set>/artifacts.tar.age | docker run --rm -i --network none --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER -v securescan_artifacts:/v --entrypoint tar "$(grep '^IMG_PYTHON=' deploy/images.env | cut -d= -f2-)" --numeric-owner -C /v -xf -
```

Restoring over a database in use replaces its content with the backup's: use it for a damaged database, not to "undo" something.

## Drill record (append a line each time)

| Date | Operator and observer | Set restored (age of the data) | Machine ready | Restore finished | Checks passed | Total time (target 4 h) | Problems and fixes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| | | | | | | | |
