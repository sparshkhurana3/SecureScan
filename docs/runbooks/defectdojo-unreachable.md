# Runbook: DefectDojo is unreachable or rejects imports

Use it when: `SecureScanImportLag` or `SecureScanImportDeadLetter` fires, Settings -> DefectDojo and imports shows failures, the portal's DefectDojo button answers
"DefectDojo is not running", or a scan finishes but its jobs stay `pending` for import.

**Nothing is lost.** The raw reports are stored first (artifacts volume), the import is queued in an outbox and retried, and a dead letter can be replayed. The history rows
are appended only after a successful import, so a long outage delays history and reports but never corrupts them.

Shorthand `sc`, `psql`: `docs/install.md`. DefectDojo's database is `defectdojo` (`sc exec -T db psql -U postgres -d defectdojo -c ...`).

## 1. Is DefectDojo up?

```
sc ps                                        # nginx, uwsgi, celerybeat, celeryworker, valkey, db; initializer exited 0
sc logs --tail 100 uwsgi
sc logs --tail 50 celeryworker
sc exec -T db pg_isready
```

| You see | Cause | Action |
| --- | --- | --- |
| `uwsgi` restarting, log mentions the database or SSL | PostgreSQL unreachable or its certificate expired / not trusted | fix the database first (`sc logs db`, `openssl x509 -in deploy/secrets/tls/server.crt -noout -enddate`); then `sc restart uwsgi celeryworker celerybeat` |
| `initializer` not `Exited (0)`, `uwsgi` waiting | a migration is running or failed | `sc logs initializer`; wait; on an error keep the log for the upgrade runbook (`defectdojo-upgrade.md`) |
| `valkey` down, `celeryworker` idle | the broker is gone | `sc up -d valkey`, then `sc restart celeryworker celerybeat` |
| everything `Up`, DefectDojo answers slowly | a large import is deduplicating | wait; `sc logs -f celeryworker`; check the disk (`df -h`) and memory (`docker stats --no-stream`) |
| disk full | `defectdojo_media`, the database volume | `docs/runbooks/stuck-scan.md` section 6, then `sc restart uwsgi` |

Restart order when in doubt: `sc restart valkey`, then `sc restart uwsgi celeryworker celerybeat`, then `sc restart nginx`.
The gateway answers a plain "DefectDojo is not running" page while `nginx:8080` is unreachable; it recovers by itself.

## 2. DefectDojo is up but imports fail

Settings -> DefectDojo and imports lists the import queue with the last error of every entry. The same data:

```
psql "select state, attempts, left(last_error, 120) as error, next_attempt_at from sync_outbox where state <> 'done' order by created_at"
```

| Error | Meaning | Action |
| --- | --- | --- |
| 401 or 403 | the service token was revoked or the account was disabled | `sc up -d dojo-init`, then `sc logs dojo-init` (it re-creates tokens and says what it changed). If it cannot, `docs/runbooks/credential-rotation.md` (DefectDojo break-glass) |
| 400 with a message about the scan type or the file | the scanner's report format changed (an image update) | roll the image back (`docs/runbooks/approving-image-digest.md`, Deactivate), then replay; investigate the new format on a copy |
| 413 or "file too large" | report over `DD_SCAN_FILE_MAX_SIZE` (100 MB) | raise it in `deploy/defectdojo/override.yaml` (maintenance window) or reduce the scan's scope |
| timeout | a very large import | wait for the retry; `SECURESCAN_DEFECTDOJO_IMPORT_TIMEOUT_SECONDS` is 900 |
| connection refused | DefectDojo down | section 1 |

## 3. Replay after the fix

Entries retry on their own (backoff). A **dead letter** (retries exhausted, or older than 7 days) needs a person: Settings -> DefectDojo and imports -> replay the entry
(audit event `import.replay`). The import is idempotent: the history rows have a unique key per job and finding, so a replay never duplicates.

## Verify and record

- `securescan_import_lag_seconds` and `securescan_import_dead_letters` are 0; the alerts resolve.
- A new scan reaches `imported` for every job; its findings appear in DefectDojo (the product of the application).
- If the cause was a release or an image update, record it in the operations log and link it to the upgrade record.
