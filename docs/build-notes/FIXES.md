# Review fixes (2026-10-08)

Every finding of the three reviews (interfaces, security, coverage) with what was done. "Applied" means the change is in the tree; nothing was run (no Docker, `uv`, Python 3.14 or Node 24 here), `python scripts/check_imports.py` reports 264 files, 0 problems.

## Applied

| # | Finding | Fix |
| --- | --- | --- |
| 1 | Networks `sonarqube`, `dast`, `egress` never created (interfaces blocker, coverage blocker) | `deploy/compose.yaml` declares them `external` with fixed names; `scripts/dev.py` has `ensure_networks()` (internal for sonarqube and dast), called by `up` and by the new `dev.py networks`. New test `test_every_network_is_joined_by_a_service_or_created_by_dev_py`. |
| 2 | Backend image installed editable (blocker) | `deploy/backend/Dockerfile`: `uv sync --frozen --no-dev --no-editable`; test `test_the_backend_image_is_installed_not_editable`. |
| 3 | Worker lacks the SonarQube secrets (interfaces blocker, coverage blocker) | `sonarqube_admin_password` secret defined; worker mounts both SonarQube secrets and sets `SECURESCAN_SONARQUBE_DB_PASSWORD_FILE` and `SECURESCAN_SONARQUBE_ADMIN_PASSWORD_FILE`. |
| 4 | `syft-grype` not a component tool (interfaces major, coverage major) | `reports/snapshot.py`: `COMPONENT_TOOLS` and `TOOL_LABELS` know `syft-grype`; unit test in `test_reports_snapshot.py`. |
| 5 | known_hosts for deploy-key clones | Worker mounts `deploy/known_hosts` and sets `SECURESCAN_SSH_KNOWN_HOSTS_FILE`. |
| 6 | DAST CIDR allowlist and rate not passed (interfaces major, coverage major) | `SECURESCAN_DAST_ALLOWED_CIDRS` and `SECURESCAN_DAST_MAX_RPS` in the shared backend environment and documented in `deploy/.env.example`, with `SOCKET_PROXY_USER`, `SECURESCAN_HOST_CHECK` and the `BACKUP_*` settings; the refusal text in `domain/dast_rules.py` names the environment variable. Worker mounts `content/semgrep-rules.lock`. |
| 7 | No pages for M8 to M11 features (interfaces major, coverage major) | New: `frontend/src/api/operations.ts` (hooks), `routes/settings/scanner-health.tsx`, `content.tsx` (feeds, update now, NVD key), `images.tsx` (approve, reject, stop using), `routes/vendor-assessments.tsx` (intake, create assessment, delta, review link, vendor copy links). Registered in `router.tsx`, `SETTINGS_PAGES` and the main navigation. Tests: `routes/operations.test.tsx`; e2e: `e2e/vendor.spec.ts` and three more pages in `e2e/settings.spec.ts`. |
| 8 | `test_seeding_inserts_scan_profiles...` stale (both) | Expects the four profiles in file order. |
| 9 | Target credential of any kind (security blocker) | `api/versions_targets.py`: `_check_credential` allows only `CREDENTIAL_KINDS_BY_TARGET` (vendor_repo: deploy key or vendor token; image: registry; others none), same application and version, matching `target_id`; create and update pass the target kind. Defence in depth in `runner/sources/github.py` (`git.credential_kind`) and `runner/sources/image.py` (`image.credential_kind`). Tests in `test_target_credentials.py`. |
| 10 | Executor omitted the candidate token (security major, coverage major) | `runner/executor.py` passes `self.loaded.job.options`; `runner/tools/syft_grype.py` passes `ctx.options`. Tests: candidate resolution in `test_image_updates.py` plus a wiring check. |
| 11 | Analyst re-points an approved DAST target (security major) | `update_target` clears `host_approved` and audits `target.host_approval_cleared` when the host set or the API specification changes and the caller is not an Admin who is re-approving. |
| 12 | Request could set policy options such as `no_disclosure` (security major) | `domain/scans.py`: allow-list `REQUEST_TOOL_OPTIONS` (Semgrep `exclude`, ZAP phase minutes, each validated); everything else is `scan.option_not_allowed`. Internal callers (`requested_by` system) are trusted. Tests in `test_domain_scans.py`. |
| 13 | `test_periodic_skeleton...` fails (coverage major) | Patches `hooks._PERIODIC` to an empty dict. |
| 14 | `dev.py test regression` was a stub; approved image overlays not pulled (coverage major) | `regression` runs `check` then `run --kind all` in the worker; `pull-images` also pulls the approved overlays (`pull_approved_overlays`). |
| 15 | Two Semgrep matchers (coverage major) | `jobs/updaters.expectation_met` adapts raw results and delegates to `domain.regression.match_expectation`. Why the raw report is still read at that point: `docs/decisions.md` entry of 2026-10-08. |
| 16 | `compose.test.yaml` missing (coverage major) | Added (db on 127.0.0.1:55432, DefectDojo nginx on 127.0.0.1:8080); `dev.py` adds it for `--profile test`; the values are documented in `tests/integration/conftest.py`. |
| 17 | No FR/NFR traceability; deviations not in `decisions.md` (coverage major) | `docs/progress.md` has a Traceability table (every FR and NFR with module, test or manual step, status); `docs/decisions.md` has the dated entries for the build-note deviations. |
| 18 | Upstream DefectDojo Compose file is a placeholder (coverage major) | Cannot be fixed here (no network). `docs/install.md` section 8a gives the exact commands and the fallback; recorded in `docs/decisions.md` and in `docs/progress.md`. |
| 19 | Missing integration coverage (coverage major) | Added `tests/integration/test_github_app.py` (skips without the S6 App variables), `tests/integration/test_vendor_flow.py` (two versions, delta, report, review, vendor copy, SaaS hosting refusal) and `frontend/e2e/vendor.spec.ts`. |

## Skipped or only partly done

- **Scanner and DAST login-profile management UI, `/dast/targets/{id}/options` call from the DAST page** (interfaces major, second half): not built. The DAST page still starts scans through `POST /scans`, which enforces the same rules on the server, so nothing is bypassed; the portal just does not preview the options or manage `dast_login` profiles. Open item for a follow-up.
- **SonarQube quality gate and measures in `JobOut`/results API** (interfaces major, last sentence): not added. `JobOut` deliberately exposes no job options; the quality gate result is in DefectDojo and in the report. Open item.
- **Replacing `expectation_met` by a DefectDojo-based gate for candidate rules** (coverage, "preferred" option): not done; the minimum fix (one matcher, exception recorded) was applied instead.
- **PDF `Downloaded by` and HTML header acceptance as integration tests** (coverage, last clause): still unit-tested only (`test_reports_csv_and_watermark.py`).
- **Everything above is unverified.** Run on Ubuntu 24: `uv run ruff check . && uv run ruff format --check . && uv run mypy securescan && uv run pytest`, then `npm run lint && npm run typecheck && npm test` in `frontend/`. Expect small type and lint corrections in the new frontend files (the `operations.test.tsx` casts in particular).
