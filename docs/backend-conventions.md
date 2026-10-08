# Backend conventions (written by M2; the contract for M3 and later)

This file says where code goes and which helpers to call. The code under `backend/securescan/` is the
reference; if code and this file disagree, fix the code or this file in the same commit. Everything here was
written without being run (see `docs/build-notes/M2.md`); the first Ubuntu run may adjust details.

Python 3.14 in production, but keep every `.py` file free of syntax newer than 3.9 so that
`python scripts/check_imports.py` can byte-compile it on any machine: `from __future__ import annotations` first,
`X | Y` only in annotations, no `match`, no `type X = ...`, no `except A, B`. Use ASCII quotes and LF line endings.

## 1. Layout and auto-discovery (where files go)

| You add | Put it in | How it is picked up |
| --- | --- | --- |
| An API endpoint module | `securescan/api/<name>.py` with a module-level `router = APIRouter(tags=["..."])` (no `/api/v1` prefix) | `securescan/api/router.py` includes every module in `securescan/api/` that exposes `router` (except `router`, `problems`, `pagination`, `schemas`, `middleware`). Import errors are not swallowed. |
| A model | `securescan/db/models/<name>.py` (class on `securescan.db.base.Base`) | `securescan/db/models/__init__.py` imports every module of the package. Add the migration by hand (section 3). |
| A job or periodic task | `securescan/jobs/<name>.py` with `@app.task` / `@app.periodic` | `securescan.jobs.app.load_tasks()` imports every module of `securescan/jobs/` except `app`, `worker`, `enqueue`, `hooks` (worker and api both call it). |
| The real code of a planned periodic task | `@periodic_hook("<name>")` in your own `securescan/jobs/<name>.py` | `maintenance.py` already registers the task under its final name and calls the hook (section 7.3). Do not redefine the task. |
| A seeder (data that must exist after migration) | `securescan/db/seeds/<name>.py` with `async def seed(session)` | `python -m securescan migrate` runs all seeders after the schema is at head (section 3.3). |
| A tool command builder | `securescan/runner/tools/<tool>.py` exposing `BUILDER` | `securescan/runner/tools/__init__.py` (M3). |
| Catalogue entries | `scanners/catalogue.yaml` plus `scanners/catalogue.d/*.yaml` | `securescan/runner/catalogue.py` (M3). |
| After-sign-in work (DefectDojo account) | `@on_login` in `securescan/domain/accounts.py` | `securescan/auth/hooks.py` imports that module when it exists (section 5.4). |
| A CLI command | `python -m securescan <command>`: `migrate` -> `securescan.db.migrate:run`, `worker` -> `securescan.jobs.worker:run`, `dojo-init` -> `securescan.integrations.defectdojo.init:run`, `sonar-init` -> `securescan.integrations.sonarqube.init:run`; each `run() -> int` | `securescan/__main__.py` imports the module; a missing module prints `<command>: not implemented yet` and returns 0. |

Layers (plan 1.3): `api/` (request and response models, no business logic) calls `domain/` (rules) which uses `db/`
(models, repositories), `integrations/`, `runner/`, `storage/`. Jobs call domain services.

Files owned by M2 that you should not rewrite: `config.py`, `main.py`, `__main__.py`, `logging.py`, `util.py`,
`db/{base,engine,session,migrate,seed}.py`, `db/models/*` (add columns through a new migration), `auth/*`,
`api/{router,problems,pagination,schemas,middleware,auth,applications,versions_targets,vendors,uploads,audit,admin}.py`,
`domain/{audit,inventory,uploads,credentials}.py`, `jobs/{app,hooks,enqueue,maintenance,worker}.py`,
`security/secrets.py`, `storage/artifacts.py`, `observability/metrics.py`. If you need a one-line change there
(a field, an import), make the smallest edit and mention it in your build notes.

## 2. Settings (`securescan/config.py`)

`from securescan.config import get_settings` (cached; `get_settings.cache_clear()` in tests). Variables are
`SECURESCAN_<NAME>`; `SECURESCAN_<NAME>_FILE` reads the value from a file (whitespace and CRLF stripped; an explicit
variable wins over the file). Fields (default in brackets):

- Runtime: `env` (`production`; `dev` or `test` enable reload and `is_dev`), `log_level` (`INFO`), `docs_enabled` (false).
- Database: `database_url`, `database_password` (from `DATABASE_PASSWORD_FILE`), `database_pool_size` (10).
- URLs and cookies: `public_url`, `defectdojo_url` (`http://nginx:8080`), `defectdojo_public_url`, `cookie_domain`,
  `cookie_secure` (None = secure when `public_url` is https; property `cookies_secure`), `session_cookie_name`
  (`securescan_session`), `csrf_cookie_name` (`securescan_csrf`), `csrf_header_name` (`X-CSRF-Token`),
  `session_idle_hours` (8), `session_max_hours` (24), `trust_forwarded_for` (true).
- Identity: `oidc_issuer`, `oidc_client_id`, `oidc_client_secret` (`OIDC_CLIENT_SECRET_FILE`), `oidc_scopes`,
  `oidc_roles_claim` (`roles`), `oidc_redirect_path`; property `oidc_redirect_uri`.
- Secrets: `master_key` (`MASTER_KEY_FILE`), `master_key_previous` (rotation), `credential_expiry_alert_days` (14).
- Docker and volumes: `docker_host`, `data_root` (`/var/lib/securescan`), `data_host_root`, `artifacts_root`,
  `content_root`, `scanners_dir`, `network_backend|sonarqube|dast|egress` (`securescan_<name>`); property
  `workspaces_root` (`<data_root>/workspaces`).
- Worker: `worker_concurrency` (4), `worker_metrics_host`, `worker_metrics_port` (9100), `github_poll_interval_minutes` (10).
- Uploads: `upload_max_bytes` (2 GiB), `upload_chunk_bytes` (8 MiB, advertised), `upload_max_chunk_bytes` (32 MiB),
  `upload_stale_hours` (48).
- DefectDojo: `defectdojo_admin_username`, `defectdojo_admin_password` (`DEFECTDOJO_ADMIN_PASSWORD_FILE`),
  `defectdojo_sync_username`, `defectdojo_accounts_username`.
- SonarQube: `sonarqube_url`, `sonarqube_container`, `sonarqube_idle_minutes` (15), `sonarqube_admin_password`.
- Egress: `egress_idle_minutes` (5), `egress_proxy_url`, `egress_allow_hosts_updaters` (comma list; property
  `updater_hosts`).

Add a field here when you need one (one line, with a default); mention it in your notes and in `deploy/.env.example` or
compose if it must be set per deployment.

## 3. Database

### 3.1 Sessions

```python
from securescan.db.session import DbSession, get_session, session_scope
```

- Endpoints: `db: DbSession` (an `Annotated[AsyncSession, Depends(get_session)]`). The dependency **never commits**.
  Call `await db.commit()` before returning (FastAPI 0.118+ runs yield-dependency exit code after the response is
  sent, so a commit there would race with the client). Uncommitted work is rolled back when the session closes.
- Jobs and scripts: `async with session_scope() as db:` commits on success, rolls back on any exception.
- Do not create engines yourself: `securescan.db.engine.get_engine()`, `get_sessionmaker()`, `build_url()`,
  `psycopg_conninfo()` (libpq URI for psycopg and Procrastinate), `dispose_engine()`, `reset_engine_cache()` (tests).
- IDs are UUIDv7: `from securescan.util import new_id, utcnow, ensure_utc, sha256_hex`. Times are timezone-aware UTC.
- No ORM `relationship()` is defined anywhere. Join explicitly or load by id; this keeps async code free of lazy loads.
- JSONB columns do not track in-place mutation: assign a new dict or list.
- A column must never be called `metadata` (reserved by SQLAlchemy). The `Session` model class is the *login* session;
  alias it (`from securescan.db.models.sessions import Session as LoginSession`) next to SQLAlchemy's `Session`.

### 3.2 Models (`securescan/db/models/`)

Enums (`db/models/enums.py`, native PostgreSQL enums, labels are the member values): `AppType` (internal, vendor),
`TargetKind` (github_repo, vendor_repo, zip, image, url), `TargetEnvironment` (production, uat), `ScanKind` (sast, dast),
`ScanTrigger` (user, change, weekly, schedule), `ScanState` (queued, running, completed, completed_partial, failed,
cancelled), `JobState` (queued, preparing, running, completed, completed_partial, failed, cancelled, timed_out),
`ImportState` (pending, imported, failed), `ReportKind` (application, vendor), `Verdict` (pass, conditional, fail, pending),
`ReviewState` (automatic, reviewed), `Severity` (critical, high, medium, low, info), `UserRole` (Admin, Analyst),
`ArtifactKind` (upload, raw_report, sbom, log, report_file, snapshot, template, document), `UploadState`, `CredentialKind`
(github_app_key, deploy_key, vendor_token, registry, dast_login, nvd_key, defectdojo_token, defectdojo_admin_token,
sonarqube_token), `ScheduleKind` (weekly, dast, poll), `ContentFeed` (semgrep_rules, nuclei_templates, grype_db,
nvd_data), `OutboxState` (pending, processing, done, dead_letter). `JOB_TERMINAL_STATES` lists the final job states.

Every table has `id` (UUIDv7, `new_id`); most have `created_at` (and `updated_at`, set it yourself on change; there is no
trigger). Columns (all created by `0001_initial_schema.py`):

| Module | Model | Table | Columns |
| --- | --- | --- | --- |
| `db/models/vendors.py` | `Vendor` | `vendors` | id, name (unique), contact_name, contact_email, risk_tier, notes, archived_at, created_by_id |
| `db/models/applications.py` | `Application` | `applications` | id, name (unique), type, vendor_id, vendor_product, hosting, description, criticality, data_classification, tags (JSON list), confirmed, automatic, github_repo_id (unique), github_full_name, default_branch, github_removed_at, dd_product_id, cached_counts (JSON {critical, high, ...}), cached_counts_at, last_scan_at, last_scan_id (soft ref), last_verdict, archived_at, created_by_id |
| `db/models/versions.py` | `ApplicationVersion` | `application_versions` | id, application_id, label (unique per application), label_kind, description, commit_sha, dd_engagement_id, sonar_project_key, archived_at, created_by_id |
| `db/models/targets.py` | `Target` | `targets` | id, version_id, kind, name, locator, environment (url targets only), environment_set_by_id, environment_set_at, credential_id, login_profile_id (credential kind dast_login), upload_artifact_id, default_branch, scope_includes, scope_excludes, api_spec_type, api_spec_locator, api_spec_artifact_id, rate_limit_rps, blackout_windows, dast_cron, host_approved, vendor_authorization_artifact_id, vendor_authorized_from, vendor_authorized_until, vendor_contact, vendor_authorization_notes, archived_at, created_by_id |
| `db/models/profiles.py` | `ScanProfile` | `scan_profiles` | id, name, version (unique together), kind, description, body_yaml, body (JSON), sha256, active, created_by_id |
| `db/models/scans.py` | `Scan` | `scans` | id, application_id, version_id, target_id, profile_id, profile_name, profile_version, kind, mode, trigger, trigger_detail, state, verdict, verdict_detail, policy_id, started_by_id (NULL = system), idempotency_key (unique; store `"<user id>:<header value>"`), requested_tools, options, commit_sha, source_ref, source_digest, counts, coverage_notes, error, started_at, finished_at, cancel_requested_at, cancelled_by_id |
| `db/models/jobs.py` | `ScanJob` | `scan_jobs` | id, scan_id, tool, state, import_state, attempts, procrastinate_job_id, container_id, worker_name, heartbeat_at, image, image_digest, tool_version, content_versions (JSON), exit_code, outcome_reason, partial, counts (JSON by severity), dd_test_id, dd_imported_at, dd_import_stats, log_path, applied_exclusions, coverage_note, options, started_at, finished_at |
| `db/models/artifacts.py` | `Artifact` | `artifacts` | id, kind, storage_key (unique, relative to the artifacts root), filename, content_type, sha256, size_bytes, owner_type, owner_id, scan_id (soft ref, no FK), job_id (soft ref), created_by_id, expires_at, deleted_at |
| `db/models/artifacts.py` | `Upload` | `uploads` | id, filename, content_type, size_bytes, received_bytes, chunk_bytes, state, sha256_expected, sha256, partial_key, artifact_id, created_by_id, completed_at |
| `db/models/history.py` | `FindingHistory` | `finding_history` | id, scan_id, job_id, application_id, version_id, vendor_id, started_by_id, source_kind, tool, dd_finding_id, hash_code, dd_test_id, severity, title, cwe, cve, cvss, component, component_version, file_path, line, url, state_at_scan, flags_at_scan (JSON), state_now, flags_now (JSON), state_now_updated_at, scanned_at; unique (job_id, dd_finding_id) makes the append idempotent |
| `db/models/reports.py` | `Report` | `reports` | id, application_id, version_id, scan_id, kind, ref (unique), title, template_id, template_version, snapshot_artifact_id, snapshot_sha256, html_artifact_id, pdf_artifact_id, status (pending, ready, failed), error, review_state, proposed_verdict, verdict, verdict_overridden, override_reason, reviewer_id, reviewed_at, conditions (JSON list), vendor_copy, internal_notes, mapping_versions, previous_report_id, generated_by_id |
| `db/models/templates.py` | `ReportTemplate` | `report_templates` | id, name, version, builtin, default_for_application, default_for_vendor, zip_artifact_id, directory, entry_file, sha256, validated_at, validation_error, active, created_by_id |
| `db/models/policies.py` | `Policy` | `policies` | id, name, data_classification, application_id, is_default, thresholds (JSON), version, active, created_by_id |
| `db/models/schedules.py` | `Schedule` | `schedules` | id, name, kind, enabled, cron, poll_interval_minutes, blackout_windows, repository_set (JSON), target_id, profile_name, last_run_at, next_run_at, last_status, created_by_id |
| `db/models/credentials.py` | `Credential` | `credentials` | id, kind, name, ciphertext, key_id, public_material, application_id, version_id, extra (JSON, non-secret), expires_at, expiry_alert_sent_at, last_used_at, revoked_at, created_by_id |
| `db/models/github.py` | `GitHubConnection` | `github_connections` | id, name, org_login (unique), app_id, client_id, installation_id, api_base_url, git_host, api_version, key_1_credential_id, key_2_credential_id, active_key, enabled, last_test_*, last_sync_at, last_poll_*, rate_limit_remaining, rate_limit_reset_at |
| `db/models/github.py` | `RepositoryHead` | `repository_heads` | id, application_id, repository, branch (unique per application), last_seen_sha, last_scanned_sha, last_seen_at, last_scanned_at, last_scan_id, last_poll_error |
| `db/models/content.py` | `ContentVersion` | `content_versions` | id, feed, version (unique per feed), path, source_commit, built_at, fetched_at, regression_result, regression_detail, active (at most one active row per feed), activated_at |
| `db/models/images.py` | `ImageVersion` | `image_versions` | id, tool, image, tag, digest (unique per tool), source, regression_result, regression_detail, active, proposed_at, approved_by_id, approved_at, notes |
| `db/models/users.py` | `User` | `users` | id, oid (unique), name, email, upn, role, roles, last_login, dd_user_id, dd_username, dd_initial_secret (encrypted), dd_secret_shown_at, dd_disabled, dd_disabled_at |
| `db/models/sessions.py` | `Session` | `sessions` | id, user_id, token_hash, csrf_token, role, last_seen_at, expires_at, ip, user_agent, revoked_at |
| `db/models/outbox.py` | `SyncOutbox` | `sync_outbox` | id, job_id, state, attempts, next_attempt_at, last_error, payload (JSON), completed_at |
| `db/models/audit.py` | `AuditEvent` | `audit_events` | id, created_at, actor_id, actor_label, action, object_type, object_id, source_ip, user_agent, request_id, detail (JSON); a trigger rejects UPDATE and DELETE |

Indexes of note: history `(application_id, severity, scanned_at)`; scans `(application_id, created_at)`; `scan_jobs(state)`;
audit `(created_at)`, `(actor_id, created_at)`, `(action, created_at)`, `(object_type, object_id)`;
`sync_outbox(state, next_attempt_at)`.

Conventions: "delete" of inventory objects (applications, versions, targets, vendors) **archives** them (`archived_at`);
history, reports, artifacts and audit are never deleted automatically. `Artifact.scan_id` / `job_id` and
`Application.last_scan_id` are soft references on purpose (they avoid cycles in the schema).

### 3.3 Migrations and seeders

- Revisions live in `securescan/db/migrations/versions/` and are written by hand with explicit `op.create_table` /
  `op.add_column` / `op.create_index` calls, named like `0003_<slug>.py` with `revision = "0003"`,
  `down_revision = "0002"`. Constraint and index names follow `ix_<table>_<cols>`, `uq_<table>_<cols>`,
  `fk_<table>_<column>`, `pk_<table>` (63 characters at most) so that `alembic check` finds no drift. For a new PostgreSQL
  enum value use `op.execute("ALTER TYPE <name> ADD VALUE IF NOT EXISTS '<value>'")` (outside a transaction block if you
  also use the value in the same revision) and add the member to `db/models/enums.py`.
- `0001` creates the whole data model; `0002` applies Procrastinate's `schema.sql` read from the installed package. Each later
  Procrastinate upgrade gets its own revision applying that version's `sql/migrations/*.sql` files in order, with the
  Procrastinate version in its docstring.
- `tests/unit/test_migrations.py` compares the tables, columns, nullability, index and unique-constraint names and the enum
  types of `Base.metadata` with the **initial** migration; extend it (or add a similar test) if you add tables in a new revision.
- `python -m securescan migrate` = `alembic upgrade head` then every seeder in `securescan/db/seeds/` (idempotent, one
  transaction each). `python scripts/dev.py migrate` runs it in the `migrate` container. `alembic check` works from `backend/`
  (`alembic.ini`) with the `SECURESCAN_DATABASE_*` variables set.

## 4. API conventions

- All routes are under `/api/v1`; tag every router; response models are pydantic (`ORMModel` in `api/schemas.py` has
  `from_attributes=True`: `Out.model_validate(row)`). `GET /api/v1/openapi.json` is the document for the generated client.
- **Roles**: `from securescan.auth.roles import AnalystUser, AdminUser, AnyUser, OptionalUser, CurrentUser`. Use them as
  parameter types (`user: AnalystUser`). Admin satisfies Analyst. `CurrentUser` has `id, oid, name, email, role, session_id,
  csrf_token, is_admin, label`. `require_analyst`, `require_admin`, `require_role(Role)`, `current_user`,
  `current_user_optional`, `resolve_role(claims)`, `role_satisfies(actual, required)` are also exported. Every endpoint needs a
  role dependency; the gateway does not authenticate `/api/`.
- **CSRF**: enforced inside `current_user_optional` (so by every role dependency) for every method except GET, HEAD, OPTIONS:
  cookie `securescan_csrf` must equal header `X-CSRF-Token` and the token stored on the session.
- **Audit**: `from securescan.domain.audit import record_audit, SYSTEM_ACTOR, client_ip` and
  `await record_audit(session, actor, action, object_type, object_id, detail=None, request=None)` before `commit()`.
  `actor` is a `CurrentUser`/`User`, a user id, `SYSTEM_ACTOR` ("system") or any label string. Pass `request` in endpoints
  (source address, request id; it also marks the request as audited). Action names: `<object>.<verb>`. `detail` has no
  secrets (keys such as `password`, `token`, `secret` and known token shapes are masked anyway). Each event is also logged as
  a structlog line `event=audit`. Safety net: `RequestMiddleware` writes a generic `http.<method>` event for a successful
  state-changing request by a signed-in user that recorded none; do not rely on it, write specific events. Jobs call
  `record_audit(session, SYSTEM_ACTOR, "scan.start", "scan", scan.id, {...})`.
- **Problems** (`securescan/api/problems.py`): `raise NotFound(detail, code="x.not_found")`, `Conflict`, `Forbidden`,
  `Unauthorized`, `BadRequest`, `UnprocessableEntity`, `PayloadTooLarge`, `TooManyRequests`, `ServiceUnavailable`, or
  `Problem(detail, status=..., code=..., headers={...}, errors=[...], **extension_members)`. Detail text is plain words for a
  non-technical reader. `code` is a stable machine-readable string. Validation errors and `HTTPException` are converted too.
- **Pagination** (`securescan/api/pagination.py`): `page: PageDep` parameter, `response_model=CursorPage[ItemOut]`,
  `result = await paginate(db, select(Model).where(...), key=[Model.created_at, Model.id], params=page, descending=True)`,
  then `CursorPage(items=[ItemOut.model_validate(r) for r in result.items], next_cursor=result.next_cursor)`. Query
  parameters `after` and `limit` (1 to 200, default 50). `key` is the total order and must end in a unique column; the
  same direction for all columns. Cursors are opaque to clients.
- **Uploads**: `POST /uploads` -> `PATCH /uploads/{id}` (`Content-Range: bytes s-e/total`, raw body) -> `POST
  /uploads/{id}/complete` returns `artifact_id`; targets of kind `zip` reference `upload_artifact_id`.
- **Inventory rules**: `securescan/domain/inventory.py` (`validate_target_rules`, `validate_cron`, `validate_scope_patterns`,
  `normalise_tags`, `validate_application_rules`). The production/UAT scan-mode rule and vendor-authorization rule are enforced
  where scans are created (M3, M9, M10), using `Target.environment`, `Target.login_profile_id`, `Application.type`,
  `Application.hosting`.
- Endpoints that exist after M2: `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`, `GET /auth/check`, `GET /me`,
  `GET|POST /applications`, `GET|PATCH|DELETE /applications/{id}`, `GET|POST /applications/{id}/versions`,
  `GET|PATCH|DELETE /versions/{id}`, `GET|POST /versions/{id}/targets`, `GET /targets`, `GET|PATCH|DELETE /targets/{id}`,
  `GET|POST /vendors`, `GET|PATCH|DELETE /vendors/{id}`, `POST /uploads`, `GET|PATCH|DELETE /uploads/{id}`,
  `POST /uploads/{id}/complete`, `GET /audit-events`, `GET /admin/health`; at the root `/healthz`, `/readyz`, `/metrics`.
  Do not add `/admin/health` again; put other admin endpoints in your own module (for example `api/accounts_admin.py`).
- The gateway sends `X-Forwarded-For` (the client address) and `X-Forwarded-Proto`; `client_ip(request)` reads it.

## 5. Authentication details

- OIDC (Authlib + PyJWT), code flow with PKCE, state and nonce; the login state is an encrypted 10-minute cookie
  (`securescan_oidc`). Roles come from the `roles` claim (`SECURESCAN_OIDC_ROLES_CLAIM`); no `Admin`/`Analyst` role =
  `403` problem `auth.no_role` and an `auth.login_denied` audit event. The user row is upserted by `oid` (or `sub`).
- Session cookie `securescan_session` (`HttpOnly; Secure; SameSite=Lax; Domain=<cookie_domain>`), SHA-256 of the token in the
  `sessions` table, idle timeout 8 h, absolute 24 h, activity recorded at most every 60 s in its own transaction.
  `GET /auth/check` returns 204/401 for the gateway's `auth_request` (no CSRF there).
- 5.4 Hooks: `from securescan.auth.hooks import on_login`; `@on_login async def hook(db, user): ...` runs in a savepoint
  after the user is upserted; failures are logged and never block sign-in. Put it in `securescan/domain/accounts.py`.

## 6. Secrets and artifacts

- `from securescan.security.secrets import encrypt_secret, decrypt_secret, reencrypt_secret, current_key_id, SecretsError`.
  `encrypt_secret(plaintext, context="") -> "ss1:<kid>:<nonce>:<ciphertext>"`; `decrypt_secret(envelope, context="") -> str`.
  The `context` is authenticated (use `credential:<id>`); decrypting with another context fails. The master key is
  `SECURESCAN_MASTER_KEY(_FILE)`; for rotation put the old key in `SECURESCAN_MASTER_KEY_PREVIOUS`.
- Credentials: `securescan/domain/credentials.py`: `store_credential(session, kind=..., name=..., secret=..., expires_at=...,
  public_material=..., application_id=..., version_id=..., extra=...)`, `reveal_secret(credential)`,
  `get_active_credential_by_kind(session, kind)`, `expiring_credentials`, `run_expiry_alerts`. Never log or return a revealed
  secret; never put it on a command line (container env or a 0600 file only).
- Artifacts: `from securescan.storage.artifacts import save_bytes, save_file, artifact_path, open_artifact, read_bytes,
  verify_artifact, resolve_key, default_key, safe_filename, sha256_file, StorageError`.
  `await save_bytes(session, kind=ArtifactKind.RAW_REPORT, data=raw, filename="semgrep.json", scan_id=..., job_id=...)` and
  `await save_file(session, kind=..., source=Path, move=False, key=None, ...)` write the file under
  `SECURESCAN_ARTIFACTS_ROOT` (atomic rename), add the `Artifact` row (SHA-256, size) and flush; they do not commit. Key layout:
  `uploads/<yyyy>/<mm>/<id>`, `scans/<scan>/<job>/<file>` (raw reports, SBOMs, logs), `reports/<report or owner id>/<file>`,
  `templates/<id>/<file>`. Keys are validated (no `..`, no absolute paths, nothing outside the root).

## 7. Jobs (Procrastinate)

### 7.1 Defining tasks

```python
from procrastinate import RetryStrategy
from securescan.jobs.app import app

@app.task(name="scan_job", queue="scans", retry=RetryStrategy(max_attempts=2, exponential_wait=30))
async def scan_job(job_id: str) -> None: ...
```

Queues (the worker listens to exactly these): `scans`, `imports`, `reports`, `maintenance`, `github`. Task arguments are
JSON values (pass ids as strings). Tasks are `async def` and idempotent. `app` is `procrastinate.App` on a
`PsycopgConnector(conninfo=psycopg_conninfo())`; the worker opens it, and the api opens it in its lifespan.
Locks: `app.task(lock=...)` is set at defer time (`defer(task, lock="tool:semgrep:1", ...)` or
`task.configure(lock=...)`): jobs with the same `lock` run one at a time; `queueing_lock` lets only one job with that value wait in
the queue (a second defer raises `AlreadyEnqueued`; `securescan.jobs.enqueue.defer` turns that into `None`). Plan values: a
`queueing_lock` per (application, version, tool), `lock="tool:<name>:<slot>"` for per-tool caps, `lock="dast"` for the one-DAST rule.
Retries only for launcher and Docker exceptions (raise to retry, return normally to finish), never for tool exit codes.

### 7.2 Enqueueing

Procrastinate defers through its own connection pool, which cannot join a SQLAlchemy transaction. The pattern is **state first,
queue second**: write the row (for example `ScanJob(state=queued)`) and `await db.commit()`, then
`await defer(scan_job, queueing_lock=..., lock=..., job_id=str(job.id))` from `securescan.jobs.enqueue`
(`defer(task, *, lock=None, queueing_lock=None, schedule_at=None, schedule_in=None, priority=None, **task_kwargs) -> int | None`).
If the process dies in between, the `stalled_jobs` hook (M3) re-defers rows that are still `queued` without a live
Procrastinate job; `queueing_lock` makes that idempotent. The import outbox (`SyncOutbox`) is written in the same transaction
as the job's final state and consumed by an `imports` task.

### 7.3 Periodic tasks and hooks

`securescan/jobs/maintenance.py` registers these periodic tasks (cron, UTC) with a `queueing_lock` equal to the name, in the
`maintenance` queue unless stated: `stalled_jobs` (`*/5 * * * *`), `workspace_gc` (hourly), `history_state_refresh` (02:00),
`github_discovery` (01:00, queue `github`), `github_poll` (every `github_poll_interval_minutes`, queue `github`),
`grype_db_update` (07:30), `nvd_update` (03:00), `rules_and_templates_update` (Saturday 03:00), `image_update_proposals`
(1st of the month 04:00), `account_expiry` (04:00), `credential_expiry_alerts` (05:00; implemented in M2),
`sonarqube_idle_stop` and `egress_idle_stop` (every 5 minutes), plus `session_cleanup` (hourly; implemented in M2: expired
sessions and stale uploads). To implement one, in your own `securescan/jobs/<module>.py`:

```python
from securescan.jobs.hooks import periodic_hook

@periodic_hook("github_poll")
async def poll(timestamp: int) -> None: ...
```

Worker start-up work: `@worker_startup_hook async def f() -> None` (runs once before the worker takes jobs).

### 7.4 Worker

`python -m securescan worker` -> `securescan.jobs.worker:run`: configures logging, `load_tasks()`, starts the Prometheus server on
`worker_metrics_port`, opens the app, runs start-up hooks, `app.run_worker_async(queues=QUEUES, concurrency=...)`.

### 7.5 Tests with Procrastinate

Use `app.replace_connector(procrastinate.testing.InMemoryConnector())` (context manager) to run tasks without a database.

## 8. Logging and metrics

- `from securescan.logging import get_logger, bind_job_context, clear_job_context, scrub`; `log = get_logger(__name__)`;
  `log.info("event_name", scan_id=str(scan.id), tool="semgrep")`. JSON lines on stdout. In jobs call
  `bind_job_context(scan_id=..., job_id=..., tool=...)` first. Token shapes (`ghs_`, `ghp_`, `github_pat_`, `Bearer ...`,
  `Token ...`, private keys) and sensitive keys (`password`, `token`, `secret`, `api_key`) are masked in every line.
  Never log request bodies, tokens or file contents.
- `from securescan.observability.metrics import ...`: `QUEUE_DEPTH{queue}`, `OLDEST_QUEUED_AGE`, `JOBS_TOTAL{tool,state}`,
  `JOB_DURATION{tool}`, `IMPORT_LAG`, `IMPORT_DEAD_LETTERS`, `GITHUB_POLL_LAST_SUCCESS`, `GITHUB_RATE_LIMIT_REMAINING`,
  `SONARQUBE_START_SECONDS`, `EGRESS_PROXY_UP`, `DISK_USED_RATIO{volume}`, `FEED_AGE_SECONDS{feed}`, `BACKUP_LAST_SUCCESS`,
  `BREAK_GLASS_LOGINS{tool}`, `LOGINS_TOTAL{outcome}`, `CREDENTIALS_EXPIRING`, `PERIODIC_RUNS{task}`,
  `HTTP_REQUEST_SECONDS`, `UP{component}`; `REGISTRY`, `render_prometheus()`, `snapshot()`, `refresh_db_gauges(session)`. Call
  `.set()`, `.inc()` or `.observe()` where the event happens; add a new metric to that file (one definition). The api serves
  `/metrics`; the worker serves its own registry on its port; `GET /api/v1/admin/health` shows the API-side values and the
  gauges derived from the database.

## 9. Tests

- Unit tests: `backend/tests/unit/`, no database, no network. `tests/unit/conftest.py` gives every test a fresh `get_settings()`
  with `SECURESCAN_ARTIFACTS_ROOT`, `..._CONTENT_ROOT`, `..._DATA_ROOT` in the test's tmp dir; the `master_key` fixture sets
  a master key; `FakeSession` / `fake_session` implement `add`, `flush`, `commit`, `scalar`, `scalars`, `get`, `execute` for
  services written against `AsyncSession` (`rows=[...]` is what `scalars` returns). API tests build a small `FastAPI` app,
  call `install_problem_handlers(app)`, and use `app.dependency_overrides[current_user] = lambda: CurrentUser(...)` or
  `app.dependency_overrides[get_session]` plus `monkeypatch.setattr(securescan.auth.session, "load_active_session", fake)`.
  pytest-asyncio runs in auto mode (plain `async def test_...`).
- Integration tests: `backend/tests/integration/`, marked `@pytest.mark.integration` (`pytestmark = pytest.mark.integration`),
  skipped unless `SECURESCAN_INTEGRATION=1`. Fixtures in `tests/integration/conftest.py`: `migrated_database` (Alembic to
  head, once), `database` (fresh engine per test, tables emptied afterwards), `sign_in(role)` (user + session rows),
  `api` (in-process `httpx.AsyncClient` on the real app), `api_as(role)` (the client with that user's cookies and CSRF
  header). Extend with your own fixtures in your own `conftest.py` files below that directory.
- Contract tests go in `backend/tests/contract/`.

## 10. Gateway and dev stack

- `deploy/gateway/nginx.conf`: portal host serves the SPA and proxies `/api/` to `api:8000` (never `/healthz`, `/readyz`,
  `/metrics`); the DefectDojo host (`server_name ~^dojo\.`) uses `auth_request` against `/api/v1/auth/check`, redirects `401` to the
  portal `/login`, strips the `securescan_session` cookie, and proxies to `http://nginx:8080` resolved at request time
  (503 text while DefectDojo is down).
- `deploy/compose.dev.yaml` (profile `dev`): `mock-oidc` (navikt mock-oauth2-server, published on 8082) and an `api` override with the
  dev issuer. Sign in by typing a user name and, in the login form's claims box, `{"roles": ["Admin"]}` or
  `{"roles": ["Analyst"]}`.
