# SecureScan build progress

Tick a milestone only when every item of its acceptance checklist in `docs/implementation-plan.md` has been verified. Record deviations from the plan or the design under the milestone, with a date and a pointer to `docs/decisions.md`.

**Verification environment.** The code so far was written on a Windows machine with no Docker, no `uv`, Node 18 and Python 3.9, so
nothing could be executed. The user runs and verifies on Ubuntu 24. "Written" below means the files exist; "verified" means the acceptance
checklist was run on Ubuntu 24 and passed. No milestone is verified yet.

## Milestones

- [ ] M0 — Repository scaffold and tooling — **written 2026-10-07, not yet verified** (see M0 notes)
- [ ] M1 — Spikes (S1 DefectDojo, S2 socket proxy, S3 SonarQube, S4 Entra, S5 WeasyPrint, S6 GitHub App, S7 scanner contract, S8 Opengrep) — **scripts and empty findings templates written 2026-10-07, not run** (`docs/build-notes/M1.md`)
- [ ] M2 — Backend foundation — **written 2026-10-08, not yet verified** (`docs/build-notes/M2*.md`; review fixes in `FIXES.md`)
- [ ] M3 — Scan runner, workspaces, Semgrep and Gitleaks — **written 2026-10-08, not yet verified** (`docs/build-notes/M3*.md`; review fixes in `FIXES.md`)
- [ ] M4 — DefectDojo bundle, import, history, accounts — **written 2026-10-08, not yet verified** (`docs/build-notes/M4*.md`; review fixes in `FIXES.md`)
- [ ] M5 — Reports and templates — **written 2026-10-08, not yet verified** (`docs/build-notes/M5*.md`; review fixes in `FIXES.md`)
- [ ] M6 — Portal — **written 2026-10-08, not yet verified** (`docs/build-notes/M6*.md`; review fixes in `FIXES.md`)
- [ ] M7 — GitHub integration — **written 2026-10-08, not yet verified** (`docs/build-notes/M7*.md`; review fixes in `FIXES.md`)
- [ ] M8 — Remaining code scanners and SonarQube on demand — **written 2026-10-08, not yet verified** (`docs/build-notes/M8*.md`; review fixes in `FIXES.md`)
- [ ] M9 — DAST: ZAP and Nuclei — **written 2026-10-08, not yet verified** (`docs/build-notes/M9*.md`; review fixes in `FIXES.md`)
- [ ] M10 — Vendor assessment flow — **written 2026-10-08, not yet verified** (`docs/build-notes/M10*.md`; review fixes in `FIXES.md`)
- [ ] M11 — Hardening, operations, handover — **written 2026-10-08, not yet verified** (`docs/build-notes/M11*.md`; review fixes in `FIXES.md`)
- [ ] M12 — Later: build-based analysis (only when the user asks)

## M0 notes

Run on Ubuntu 24 to finish and verify M0:

1. `cd backend && uv lock && uv sync && uv run pytest && uv run ruff check . && uv run ruff format --check . && uv run mypy securescan`
   (creates `uv.lock`; the backend Dockerfile needs it). Fix whatever the first real run reports.
2. `cd frontend && npm install && npm run lint && npm run typecheck && npm test && npm run build` (creates `package-lock.json`, which the
   gateway Dockerfile needs). The frontend dependency ranges (Vite 8, vitest 3, @vitejs/plugin-react 5, etc.) were written from
   research notes and are unchecked; adjust to versions that resolve together.
3. `sh scripts/build_planted_jar.sh` builds and then commit `java-planted/target/java-planted.jar`.
4. `python3 scripts/dev.py secrets init && python3 scripts/dev.py certs && python3 scripts/dev.py pin-images && python3 scripts/dev.py up`,
   then the M0 acceptance checklist in the plan.
5. Unverified assumptions to check on first run: tag names in `deploy/images.lock.yaml` (nginx `stable-alpine`, wollomatic variable names in
   `deploy/socket-proxy/args.env`), PostgreSQL SSL entrypoint, `uv==0.8.*` in the backend Dockerfile.

## Traceability (plan section 6)

Status values: **written** = code and tests exist, nothing has been run (no Docker, `uv`, Python 3.14 or Node 24 on the build machine);
**verified** = run on Ubuntu 24 and passed. Nothing is verified yet; change the status when the check in "Test or manual step" passes.
Paths are under `backend/securescan` unless they start with `frontend/`, `deploy/`, `scripts/` or `scanners/`. Tests are under `backend/tests`.

| Requirement | Milestone | Implementing module | Test or manual step | Status |
| --- | --- | --- | --- | --- |
| FR-01 Applications with criticality, classification, tags | M2 | `api/applications.py`, `domain/inventory.py` | `unit/test_inventory_rules.py` | written |
| FR-02 Versions and targets (repo, zip, image, URL) | M2, M3, M8, M9 | `api/versions_targets.py`, `runner/sources/` | `unit/test_target_credentials.py`, `unit/test_runner_zip.py`, `unit/test_m8_image_source.py` | written |
| FR-03 Code scans (Semgrep, SonarQube, FSB, Gitleaks, Syft, Grype, Dependency-Check) | M3, M8 | `runner/tools/*.py`, `scanners/catalogue.yaml` | `unit/test_runner_tools.py`, `unit/test_m8_*.py`; `integration/test_scan_semgrep_gitleaks.py`, `integration/test_scanners_all.py` | written |
| FR-04 DAST: baseline on production; full, API, Nuclei on UAT | M9 | `runner/tools/zap.py`, `runner/tools/nuclei.py`, `domain/dast_rules.py` | `unit/test_dast_rules.py`, `unit/test_dast_builders.py`; `integration/test_dast.py` | written |
| FR-05 Authenticated DAST on UAT only | M9 | `domain/dast_rules.py`, `api/dast.py` | `unit/test_dast_api.py`, `unit/test_dast_plans.py` | written |
| FR-06 Scan profiles | M3, M8, M9 | `runner/profiles.py`, `api/profiles.py`, `scanners/profiles/` | `unit/test_runner_profiles.py` | written |
| FR-07 Start scans on demand and follow live | M3, M6 | `api/scans.py`, `domain/scans.py`, `runner/events.py`, `frontend/src/routes/sast.tsx`, `dast.tsx`, `scan-detail.tsx` | `unit/test_scans_api.py`, `unit/test_runner_events.py`; `frontend/e2e/sast.spec.ts` | written |
| FR-08 GitHub App: discovery, change and weekly scans | M7 | `integrations/github/`, `jobs/github_*.py`, `jobs/schedules.py` | `unit/test_github_*.py`; `integration/test_github_app.py` (needs the S6 test App) | written |
| FR-09 Vendor repositories by deploy key or token, zip fallback | M7, M3 | `runner/sources/github.py`, `integrations/github/git.py` | `unit/test_runner_github.py`, `unit/test_target_credentials.py` | written |
| FR-10 SonarQube on demand, stopped when idle | M8 | `jobs/sonarqube_lifecycle.py`, `runner/tools/sonarqube.py` | `unit/test_m8_sonarqube_lifecycle.py`; `integration/test_scanners_all.py` | written |
| FR-11 Automatic import into DefectDojo | M4 | `jobs/import_job.py`, `integrations/defectdojo/` | `unit/test_import_job.py`, `unit/test_dd_client.py` | written |
| FR-12 Re-import deduplication and closing | M4 | `integrations/defectdojo/factory.py`, `deploy/defectdojo/override.yaml` | `integration/test_defectdojo_history.py` | written |
| FR-13 Permanent history with state then and now | M4 | `domain/history.py`, `jobs/history_sync.py` | `unit/test_history_filters_and_csv.py`; `integration/test_defectdojo_history.py` | written |
| FR-14 History queries and CSV export | M4, M6 | `api/history.py`, `frontend/src/routes/history.tsx` | `unit/test_history_filters_and_csv.py`; `frontend/e2e/history.spec.ts` | written |
| FR-15 Automatic report, HTML and PDF | M5 | `domain/reports.py`, `reports/`, `jobs/report_job.py` | `unit/test_reports_*.py`; `frontend/e2e/report.spec.ts` | written |
| FR-16 Default template downloadable; custom templates | M5 | `reports/template_package.py`, `api/templates.py` | `unit/test_reports_templates.py`; `frontend/e2e/settings.spec.ts` | written |
| FR-17 Vendor assessment with verdict and delta | M10 | `domain/vendors.py`, `api/vendor_assessments.py`, `frontend/src/routes/vendor-assessments.tsx` | `unit/test_vendors.py`, `frontend/src/routes/operations.test.tsx`; `integration/test_vendor_flow.py`; `frontend/e2e/vendor.spec.ts` | written |
| FR-18 Verdict policy shown in reports | M4, M5 | `domain/policy.py`, `api/policies.py` | `unit/test_dd_policy.py`, `unit/test_reports_snapshot.py` | written |
| FR-19 Entra ID sign-in with Admin and Analyst roles | M2 | `auth/`, `api/auth.py` | `unit/test_oidc.py`, `unit/test_roles.py`, `unit/test_csrf_and_sessions.py`; spike S4 | written |
| FR-20 Open DefectDojo button | M6, M4 | `api/me_defectdojo.py`, `deploy/gateway/` | manual: the button opens DefectDojo signed in | written |
| FR-21 Audit log | M2 | `domain/audit.py`, `api/audit.py` | `unit/test_logging_artifacts_audit.py` | written |
| FR-22 Automatic updates behind a regression check | M8, M11 | `jobs/updaters.py`, `jobs/image_updates.py`, `domain/image_updates.py`, `domain/regression.py`, `frontend/src/routes/settings/images.tsx` | `unit/test_m8_updaters.py`, `unit/test_image_updates.py`, `unit/test_regression.py`; `python scripts/dev.py test regression` | written |
| FR-23 Block DAST outside allowlist or authorization, and beyond baseline outside UAT | M9, M10 | `domain/dast_rules.py`, `domain/vendors.py` | `unit/test_dast_rules.py`, `unit/test_vendors.py`; `integration/test_vendor_flow.py` | written |
| FR-24 Automatic setup of DefectDojo and SonarQube | M4, M8 | `integrations/defectdojo/init.py`, `integrations/sonarqube/init.py` | `unit/test_dojo_init.py`, `unit/test_m8_sonarqube_init.py` | written |
| FR-25 Secrets masked everywhere | M2, M3, M4, M5, M8, M9 | `reports/snapshot.py` (`scrub`), logging and secrets modules | `unit/test_secrets.py`, `unit/test_logging_artifacts_audit.py` | written |
| FR-26 Scanner health | M8 | `api/scanner_health.py`, `jobs/scanner_health.py`, `frontend/src/routes/settings/scanner-health.tsx` | `unit/test_m8_scanner_health.py`, `frontend/src/routes/operations.test.tsx` | written |
| NFR Deployment: one `docker compose up` | M0, M4, M8 | `deploy/compose*.yaml`, `scripts/dev.py` | manual: `python scripts/dev.py up` on Ubuntu 24 | written |
| NFR Footprint: only the always-on set permanent | M3, M7, M8, M9 | `deploy/compose.yaml`, `runner/launcher.py` | `unit/test_operations_files.py` | written |
| NFR Portal performance | M11 | `scripts/seed_history.py` | manual: the performance check in `docs/runbooks` | written |
| NFR Scan throughput | M3, M8 | `runner/executor.py`, `scanners/catalogue.yaml` | `unit/test_runner_launcher.py` | written |
| NFR Resilience | M3, M4 | `runner/recovery.py`, `jobs/import_job.py` | `unit/test_runner_recovery.py`, `unit/test_import_job.py` | written |
| NFR Security | M2, M11 | `docs/security-checklist.md`, `runner/host_check.py` | `unit/test_host_check.py`, `unit/test_operations_files.py`; checklist ticks | written |
| NFR Recoverability | M11 | `scripts/backup.sh`, `scripts/restore.sh`, `docs/runbooks/restore.md` | manual: restore drill | written |
| NFR Retention | M3, M4 | `domain/history.py`, `storage/artifacts.py` | `unit/test_logging_artifacts_audit.py` | written |
| NFR Reproducibility | M3, M5, M8 | `runner/catalogue.py` (digest resolution), `reports/snapshot.py` | `unit/test_runner_catalogue.py`, `unit/test_reports_snapshot.py` | written |
| NFR Longevity | M0, M11 | `deploy/images.lock.yaml`, `docs/runbooks/` | manual: upgrade runbooks | written |
| NFR Internet use: outbound only, allowlisted | M7, M8, M9 | `runner/egress.py`, `runner/dast_egress.py` | `unit/test_egress.py`, `unit/test_dast_egress.py` | written |
| NFR Browsers and WCAG 2.1 AA | M6 | `frontend/src/components/` | `frontend/e2e/*.spec.ts` (axe check on every page) | written |

Steps that only the user can do on Ubuntu 24 (carry these into the first real run):

1. Replace the placeholder `deploy/defectdojo/upstream/docker-compose.yml` with the real 3.4.0 file (`docs/install.md`, "Vendor the upstream DefectDojo Compose file").
2. `python scripts/dev.py up` creates the on-demand networks (`securescan_sonarqube`, `securescan_dast`, `securescan_egress`) before Compose starts.
3. Run `python scripts/dev.py test regression` after the first `up` and after every image or content update.

## Deviations

- 2026-10-07: the user develops and runs on Ubuntu 24, not Windows 11. Plan section 2.1 (Windows, WSL2) is superseded; see `docs/decisions.md`.
- 2026-10-08: M2 to M11 deviations are listed in `docs/decisions.md` (entry of that date). `deploy/defectdojo/upstream/docker-compose.yml` is a placeholder: replace it first on Ubuntu (`docs/install.md` step 8a).
