# S1: DefectDojo import and deduplication

Status: **template, not yet run.** All cells below are empty until the script has been run on Ubuntu 24.

## Purpose

Prove that DefectDojo 3.4.0 (open source, images from docker.io) can be set up, fed and read back entirely through its API, as the design
needs: two service accounts with the right privileges, deduplication turned on, product types, `reimport-scan` with `auto_create_context`,
closing of findings that disappear, the fields and filters of the findings API, every scanner's scan type, and forced password change.

## Prerequisites

- Docker Engine and Compose; ports 8080 and 8443 free on 127.0.0.1.
- `spikes/s1/docker-compose.yml` (upstream 3.4.0 compose with the changes listed at its top) and an env file at `spikes/s1/.data/s1.env`
  (copy `spikes/s1/s1.env.example`, set `DD_ADMIN_PASSWORD`).
- Fixture reports in `backend/tests/fixtures/reports/`: `semgrep.json` is required (S7 produces it); the others for step 8 (`gitleaks.json`,
  `grype.json`, `dependency-check-report.xml`, `zap.xml`, `nuclei.json`, `spotbugs.xml` from S7, `sonarqube-issues.zip` from S3). Missing ones are skipped
  with a warning unless `S1_REQUIRE_ALL=1`.

## How to run

```
mkdir -p spikes/s1/.data && cp spikes/s1/s1.env.example spikes/s1/.data/s1.env     # edit DD_ADMIN_PASSWORD
docker compose --project-directory spikes/s1 --env-file spikes/s1/.data/s1.env -f spikes/s1/docker-compose.yml up -d
docker compose --project-directory spikes/s1 --env-file spikes/s1/.data/s1.env -f spikes/s1/docker-compose.yml logs -f initializer   # wait for it to exit
DD_ADMIN_PASSWORD='<the same password>' uv run --project backend python spikes/s1/run.py
```

Exit code 0: all as expected. 1: first unexpected result (the run stops). 2: finished, but a step-8 import was rejected or produced no findings.
Paste the printed request/response blocks into the sections below; the transcript is also in `spikes/s1/.data/transcript-*.md`.
For step 10 experiments add `-f spikes/s1/docker-compose.dedupe.yml` to the compose command and re-run.

Things the script checks that the research notes only claim (confirm each in the table): staff user cannot `POST /api/v2/users/`; the superuser can;
`system_settings` is superuser-only (so `dojo-init` cannot do step 4 with the sync token); `email` is required when creating users;
a password cannot be set through `PATCH`; `force_password_reset` lives on `user_contact_infos`, and while it is set the user cannot obtain an API token.

## What to record

| Fact (key in the script's table) | Value |
| --- | --- |
| Time until the API answers (`time_until_api_ready_s`) | |
| `securescan-sync` is staff, not superuser | |
| `securescan-accounts` is superuser | |
| Sync token: `POST /users/` status (`sync_token_create_user_status`) | |
| Accounts token: create staff user status (`accounts_token_create_staff_user_status`) | |
| Accounts token: delete staff user status | |
| Sync token: `GET` / `PATCH system_settings` status | |
| `enable_deduplication` before / after | |
| Product types: created or existed, ids | |
| Import 1: HTTP status, seconds, `test_id`, `engagement_id`, `product_id`, `product_type_id` | |
| Import 1: `statistics.after`, `statistics.delta`, `deduplication_complete` | |
| Import 2 (identical file): `delta`, same Test, active count unchanged | |
| Import 3 (one finding removed): finding removed, `is_mitigated` count before/after, `delta` | |
| Import 4 (original again): finding reopened, `delta` | |
| Finding fields present / missing (`finding_fields_present`, `finding_fields_missing`) | |
| Shape of `vulnerability_ids`, example `hash_code` | |
| `?id=1,2,3` filter works (`filter_id_supported`) | |
| `?id__in=1,2,3` filter works (`filter_id__in_supported`) | |
| Per-product paging: findings, pages, seconds | |
| Per-test `deduplication_algorithm` and `hash_code_fields` for Semgrep and every other scan type | |
| Gitleaks Scan import: status, findings total / active | |
| Anchore Grype import: status, findings total / active | |
| Dependency Check Scan import: status, findings total / active | |
| ZAP Scan import: status, findings total / active | |
| Nuclei Scan import: status, findings total / active | |
| SpotBugs Scan import: status, findings total / active | |
| SonarQube Scan (zip) import: status, findings total / active | |
| Any rejection (file, status, message) | |
| `force_password_reset`: field on `/users/`? flag set through `user_contact_infos` (status)? | |
| API token refused while a reset is owed (status) | |

## Request and response pairs

Paste here, one block per plan step (2, 3, 3b, 4, 5, 6 x4, 7, 8, 9, 10). Keep the secrets redacted as the script prints them.

## Decision

(empty)

- Service accounts and which one runs `dojo-init` for system settings:
- Import call and its parameters for production:
- Counting: `statistics.after` when `deduplication_complete` is true, else re-read through the findings API:
- State refresh by id (`id` filter or per-product paging):
- `DD_HASHCODE_FIELDS_PER_SCANNER` overrides (start with the defaults; Semgrep CE has no fingerprint):
- Forced password change for Admin and Analyst users:

## Deviations from the design

(empty)
