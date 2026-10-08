# S3: SonarQube on demand

Status: **template, not yet run.** All cells below are empty until the script has been run on Ubuntu 24.

## Purpose

Prove that SonarQube Community Build 26.9.0.129388 can be started on demand, bootstrapped through its API (admin password, service user, tokens, project),
analysed with `sonar-scanner-cli` under the M3 hardening flags, exported to a zip that DefectDojo's `SonarQube Scan` parser accepts, and stopped; and give a
go/no-go for stopping the server after 15 idle minutes.

## Prerequisites

- `vm.max_map_count >= 524288` (the script refuses below 262144), `fs.file-max >= 131072`, about 4 GB free RAM.
- Docker; network to pull `sonarqube:26.9.0.129388-community`, `postgres:18.6-alpine`, `sonarsource/sonar-scanner-cli:12.2.0.4256_8.1.0`.
- No other container named `sonarqube`; port 127.0.0.1:9000 free.
- Optional TLS run against the real `db`: `spikes/s3/docker-compose.tls.yml` (header explains the exports). The default run uses a throwaway PostgreSQL 18 without TLS.

## How to run

```
uv run --project backend python spikes/s3/run.py
```

Re-running reuses the data volumes and the admin password stored in `spikes/s3/.data/s3-secrets.json`; for a cold start run
`docker compose -f spikes/s3/docker-compose.yml down -v` first and delete that file. The script writes `backend/tests/fixtures/reports/sonarqube-issues.zip`
(disable with `S3_WRITE_FIXTURE=0`). Optional: `S3_DD_URL` and `S3_DD_TOKEN` import the zip into DefectDojo directly.

## What to record

| Fact | Value |
| --- | --- |
| `vm.max_map_count` on the host | |
| First start: seconds to `UP` (cold, volumes new) | |
| Warm restart: seconds to `UP` | |
| `docker stop` time (`stop_seconds`, second stop) | |
| Admin password change: status | |
| Service user created; global permissions granted (`provisioning`, `scan`) | |
| `USER_TOKEN` length and prefix; accepted as Bearer? | |
| Project creation by the service user: status | |
| `PROJECT_ANALYSIS_TOKEN` with `expirationDate`: status, length | |
| Scanner attempt that worked: `/usr/src` ro or rw; `/tmp` tmpfs noexec or exec | |
| Scanner uid, `HOME`, writable paths needed (`SONAR_USER_HOME=/tmp/.sonar`) | |
| `report-task.txt` keys; compute-engine task time | |
| Quality gate status; measures (bugs, vulnerabilities, hotspots, smells, coverage, duplication, ncloc, alert_status) | |
| Issues total; do issues carry `type` and `severity` (`issues_have_type_and_severity`)? | |
| Mode setting value; did `sonar.multi-quality-mode.enabled=false` work (status)? | |
| Are hotspots in `/api/issues/search`? Hotspot count from `/api/hotspots/search` | |
| Issues zip size; DefectDojo `SonarQube Scan` import: status, findings | |
| java-planted without `sonar.java.binaries`: exit code, messages, issue count | |
| If it failed: does an empty directory as `sonar.java.binaries` work? | |
| Memory use of the server while running (`docker stats`) | |
| Data survives the restart? | |

## Decision

(empty)

- Go / no-go on the 15-minute idle stop, with the timings above:
- Standard Experience: setting and who applies it (`sonar-init`):
- Whether hotspots must also be exported for the parser (and how):
- Least-privilege permissions of the service user:
- `sonar.java.binaries` handling for Java without classes:

## Deviations from the design

(empty)
