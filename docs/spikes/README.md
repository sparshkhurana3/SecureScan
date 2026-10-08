# M1 spikes: run order, prerequisites, checklist

The spike scripts are throwaway, kept for the record and never imported by production code. They were written without being able to run
them (no Docker, no network services, no credentials on the writing machine), so **no spike has a result yet**. Every findings file in this
directory is a template with empty cells: you run the spike on Ubuntu 24, paste the script's output, fill the tables, write the decision.

Each script prints every request and response in a block that can be pasted into the findings file (secrets are shown as their length),
stops with a non-zero exit code at the first unexpected result, and ends with a "Recorded facts" table whose keys match the tables below.
The transcript of every Python spike is also saved under `spikes/<spike>/.data/` (git-ignored).

## Name mapping

| Plan name | Findings file | Directory |
| --- | --- | --- |
| S1 DefectDojo import and deduplication | [s1-defectdojo.md](s1-defectdojo.md) | `spikes/s1/` |
| S2 Socket proxy allowlist | [s2-socket-proxy.md](s2-socket-proxy.md) | `spikes/s2/` |
| S3 SonarQube on demand | [s3-sonarqube.md](s3-sonarqube.md) | `spikes/s3/` |
| S4 Entra ID OIDC with app roles | [s4-entra.md](s4-entra.md) | `spikes/s4/` |
| S5 WeasyPrint in the slim image | [s5-weasyprint.md](s5-weasyprint.md) | `spikes/s5-weasyprint/` |
| S6 GitHub App | [s6-github.md](s6-github.md) | `spikes/s6/` |
| S7 Scanner container contract | [s7-scanner-contract.md](s7-scanner-contract.md) | `spikes/s7/`, `scanners/spotbugs/` |
| S8 Opengrep | [s8-opengrep.md](s8-opengrep.md) | `spikes/s8/` |

The plan's own file names (`defectdojo.md`, `scanner-contract.md`, `sonarqube.md`, `entra.md`, `github.md`, `opengrep.md`) are replaced by the
names above; update any reference you meet when you tick M1.

## Order

1. **M0 first.** `uv`, Docker and the backend lock file must work (S5 builds `deploy/backend/Dockerfile`, which copies `backend/uv.lock`).
   Build the planted jar (`sh scripts/build_planted_jar.sh`) so SpotBugs has input.
2. **Start the Dependency-Check NVD update immediately** (S7). It runs 20+ minutes in the background:
   `NVD_API_KEY=... sh spikes/s7/odc_update.sh`. Everything else can proceed while it runs.
3. **S7**: `sh spikes/s7/prefetch.sh all`, build the SpotBugs image (`sh spikes/s7/build_spotbugs.sh` after filling the checksums, see
   `scanners/spotbugs/README.md`), then `sh spikes/s7/run_all.sh`. It writes the fixture reports that S1 needs.
4. **S2** (independent of the scanners): `sh spikes/s2/run.sh all`.
5. **S3**: `uv run --project backend python spikes/s3/run.py`. It writes `sonarqube-issues.zip` into the fixture directory.
6. **S1**, after S7 and S3 so that every fixture exists: bring up `spikes/s1/docker-compose.yml`, then
   `uv run --project backend python spikes/s1/run.py`.
7. **S5**: `sh spikes/s5-weasyprint/run.sh` (commit `docs/spikes/weasyprint-sample.pdf`).
8. **S4** and **S6** need the user's credentials (Entra test tenant or the mock provider; a GitHub App). Do them when those exist.
9. **S8** (one hour, optional outcome): after S7 has fetched the Semgrep rules.

## Prerequisites (collected)

| Needed | For | Where it comes from |
| --- | --- | --- |
| Ubuntu 24, Docker Engine 29+, Compose 2.24+, `uv`, Python 3.14 via `uv`, git | all | `deploy/README.md` |
| `vm.max_map_count >= 524288` | S3 | `sudo sysctl -w vm.max_map_count=524288` (persist in `/etc/sysctl.d/99-securescan.conf`) |
| Outbound HTTPS to Docker Hub, GHCR, quay.io, `grype.anchore.io`, `services.nvd.nist.gov`, GitHub, Maven Central, Juice Shop image | S1 to S3, S5, S7, S8 | plan section 2.4 |
| Free NVD API key | S7 (Dependency-Check update) | https://nvd.nist.gov/developers/request-an-api-key |
| Entra ID test tenant with an app registration, two app roles, test users; or the mock OIDC provider | S4 | plan sections 2.2 and 8.2 |
| A GitHub App (Contents: read, Metadata: read, webhook off), its private key in `deploy/secrets/github_app_key_1`, a repository it can read | S6 | plan S6 step 1 |
| The two SHA-256 values for the SpotBugs image | S7 | `scanners/spotbugs/README.md` |
| 16 GB free RAM is comfortable; SonarQube alone wants 4 GB | S3 | |

Never put credentials into the repository. Keep them in `deploy/secrets/` (git-ignored) or in the shell environment.

## Checklist

- [ ] M0 verified on Ubuntu (uv lock, planted jar, dev.py up)
- [ ] `odc_update.sh` started; finished with exit code 0
- [ ] S7 run; `docs/spikes/s7-scanner-contract.md` filled; eight fixture reports (seven from S7, `sonarqube-issues.zip` from S3) exist in `backend/tests/fixtures/reports/`
- [ ] `expected-findings.yaml` of the four planted apps updated from the real runs (`verified: true`, rule ids filled)
- [ ] S2 `run.sh all` passes; `deploy/socket-proxy/args.env` updated from `spikes/s2/.data/enforce.env`
- [ ] S3 run; go/no-go on the 15-minute idle stop written
- [ ] S1 run; every call has a request/response pair; decision on `DD_HASHCODE_FIELDS_PER_SCANNER`
- [ ] S5 run; `docs/spikes/weasyprint-sample.pdf` committed; apt list final
- [ ] S4 run for admin, analyst, no role, denied; Entra setup steps for IT written into `deploy/README.md`
- [ ] S6 run; token length recorded
- [ ] S8 run; one line in `docs/decisions.md`
- [ ] Every deviation from `docs/design.md` found by the spikes is in `docs/decisions.md`
- [ ] `docs/progress.md` M1 ticked (only when all of the above are done)
