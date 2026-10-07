# SecureScan implementation plan

Written for Claude Sonnet, working as a coding agent in this repository (`c:\SecureScan`) together with the user. The design it implements is `docs/design.md` (exported from the SecureScan design doc, refined and closed on 6 October 2026). Where this plan and the design disagree, the design wins. Where both are silent, choose the simplest option that respects section 1 and record it in `docs/decisions.md`.

This revision (7 October 2026) incorporates an adversarial review of the first draft: 2 blockers, 11 majors and 28 minors were fixed. The deviations from the design that the review forced are listed in section 8.3 and must be recorded in `docs/decisions.md` at M0.

---

## 0. How to use this plan

1. **Read `docs/design.md` in full before writing any code.** It is about 86 KB. Read it in chunks. Pay particular attention to: Summary, Scan engine design (including the Scanner catalogue and Replacing CodeQL), DefectDojo integration, GitHub integration, Application security reports, Historical data, UI portal, Containerization and deployment, Security of the platform.
2. **Work one milestone at a time, in order.** Do not start a milestone until the previous milestone's acceptance checklist passes. Inside a milestone, do the tasks in the numbered order unless a task says it is independent.
3. **Definition of done for every milestone:**
   - All new code has unit tests; `uv run pytest` passes in `backend/`; `npm test` passes in `frontend/` (from M6 on).
   - `uv run ruff check . && uv run ruff format --check . && uv run mypy securescan` pass; `npm run lint && npm run typecheck` pass.
   - `python scripts/dev.py up` brings the stack up and the milestone's acceptance checklist is verified by hand or by the integration tests named in the milestone.
   - `docs/progress.md` is updated (tick the milestone, list deviations).
   - Work is committed in small commits with conventional messages (`feat(runner): ...`, `fix(dojo): ...`, `docs: ...`, `test: ...`, `chore: ...`). Never commit secrets. See 1.7.
4. **Stop and ask the user when, and only when:**
   - A real credential or tenant value is needed and is not in `deploy/.env` or `deploy/secrets/`: Entra tenant ID, client ID and secret, GitHub App ID, installation ID and private key, NVD API key, TLS certificate, the Linux machine's host name.
   - A task would change a design decision (section 8 lists the decisions). Propose the change and wait.
   - A tool behaves differently from what `docs/design.md` or this plan says (for example a flag no longer exists). Record the discrepancy in `docs/decisions.md`, propose the smallest fix, and ask only if the fix changes the design.
   - Docker Desktop, WSL2, `uv` or Node 24 cannot be installed or started on the user's machine.
   - A licence question arises that the design does not already answer.
5. **Record progress in `docs/progress.md`** (a checklist per milestone) and decisions in `docs/decisions.md` (date, decision, reason, alternatives). Both files exist already; append to them.
6. **Spikes come first and are throwaway.** Milestone M1 proves the risky integrations with scripts under `spikes/`. Their findings go into `docs/spikes/*.md`. Production code starts in M2 and may copy from the spikes, but spikes are never imported by production code.
7. **Never invent facts about a tool.** The verified facts are in `docs/design.md` (Scanner catalogue, DefectDojo integration, GitHub integration). When you need a flag or an API field that is not there, open the tool's own documentation with WebFetch, and record what you found in `docs/decisions.md`.

---

## 1. Ground rules and conventions

### 1.1 Stack and pinned versions

| Layer | Choice | Version policy |
| --- | --- | --- |
| Python runtime | `python:3.14-slim-trixie` official image; `uv` for environments and locking | Pin the exact patch tag in `deploy/images.lock.yaml` |
| Backend | FastAPI, SQLAlchemy 2.1 (async, `Mapped[]` declarative), Alembic, Pydantic 2, pydantic-settings, psycopg 3 (binary + pool), Procrastinate 3.x, httpx, Authlib (OIDC client), PyJWT + cryptography (GitHub App JWT, secret encryption), docker SDK for Python, Jinja2 (SandboxedEnvironment), WeasyPrint 70, pypdf (watermark overlay), python-multipart, structlog, prometheus-client | Pin in `backend/pyproject.toml` and `uv.lock`; upgrade only in a dedicated `chore(deps)` commit |
| Frontend | Node 24 LTS (build only), React 19, TypeScript 5 strict, Vite 8, TanStack Query 5, TanStack Router, Tailwind CSS, Radix primitives through the shadcn/ui CLI, openapi-typescript + openapi-fetch (generated client), Vitest + Testing Library, Playwright | Pin in `frontend/package.json` and `package-lock.json` |
| Database | PostgreSQL 18 official image, one container, three databases: `securescan`, `defectdojo`, `sonarqube`, TLS on | Pin by digest |
| DefectDojo | 3.4.0 open source, images `defectdojo/defectdojo-django` and `defectdojo/defectdojo-nginx` from docker.io (`DD_IMAGE_REGISTRY=docker.io`), Valkey broker | Pin `DJANGO_VERSION` and `NGINX_VERSION` to `3.4.0`; never `latest` |
| Gateway | `nginxinc/nginx-unprivileged` with the built portal copied in | Pin by digest |
| Socket proxy | `wollomatic/socket-proxy` | Pin by digest |
| Egress proxy | `ubuntu/squid` (GPL-2.0-or-later) | Pin by digest; started on demand, stopped when idle |
| Scanners | `semgrep/semgrep`, `sonarqube:<build>-community`, `sonarsource/sonar-scanner-cli`, self-built `securescan/spotbugs-fsb` (base `eclipse-temurin`, GPL-2.0 with Classpath Exception), `ghcr.io/gitleaks/gitleaks`, `anchore/syft`, `anchore/grype`, `owasp/dependency-check`, `ghcr.io/zaproxy/zaproxy`, `projectdiscovery/nuclei`, `quay.io/skopeo/stable` (image intake) | Every image pinned by exact tag AND digest in `deploy/images.lock.yaml`; ZAP by digest only (its version tag moves) |

Version numbers observed on 5–6 October 2026 (verify the current ones with `scripts/pin_images.py` when you pin): Semgrep 1.179.0, SonarQube Community Build 26.9.0.129388, sonar-scanner-cli 12.2.0.4256_8.1.0, Gitleaks v8.30.1, Syft v1.54.0, Grype v0.120.0, Dependency-Check 13.0.0, ZAP 2.17.0 (stable image dated 2026-08-07), Nuclei v3.11.1, SpotBugs 4.10.4, Find Security Bugs 1.14.0, DefectDojo 3.4.0, PostgreSQL 18.6, wollomatic/socket-proxy 1.13.1.

### 1.2 Architecture rules you must keep

- **DefectDojo is the only place findings are parsed and triaged.** SecureScan never parses a scanner report into findings. It stores the raw file, uploads it to DefectDojo through `POST /api/v2/reimport-scan/`, then reads findings back through DefectDojo's API for history and reports. The only "export" code is the SonarQube issues pager (M8), which pages a JSON API into a zip; it is not a parser.
- **Only these containers run permanently:** `gateway`, `api`, `worker`, `db`, `socket-proxy`, and DefectDojo's `nginx`, `uwsgi`, `celeryworker`, `celerybeat`, `valkey`. Everything else is started by the worker when a job needs it and removed afterwards: every scanner, the SonarQube server (started on demand, stopped after 15 idle minutes), the egress proxy (started on demand, stopped after 5 idle minutes), updaters, one-shot init containers.
- **The worker is the only component that talks to Docker**, and only through `socket-proxy`, and only with container specifications built from `scanners/catalogue.yaml`. Never build a container spec from user input.
- **Code scanners get no network.** Semgrep, Gitleaks, Syft, Grype and SpotBugs run with `network_mode: none`. The SonarQube scanner reaches only the `sonarqube` network. Dependency-Check reaches only Maven Central through the egress proxy (and nothing when the no-disclosure profile is on). DAST tools reach only their target through the egress proxy.
- **Secrets never reach scanner containers**, except the one credential a job needs (a DAST login profile, a registry credential, the NVD key for Dependency-Check), injected as an environment variable or a 0600 file in the job's `/config` mount for that container only. Never on a command line.
- **Secret values never land in findings, logs or exports.** Gitleaks runs with `--redact`. Logs scrub `ghs_`, `ghp_`, `github_pat_`, `Bearer ...` and `Token ...` patterns. CSV cells beginning with `=`, `+`, `-`, `@`, tab or carriage return are prefixed with `'`.
- **Two roles only**: `Admin` and `Analyst`, read from the Entra ID `roles` claim. No local users in SecureScan. No ownership scoping.
- **Production DAST = unauthenticated ZAP baseline only.** Full scans, API scans, Nuclei and login profiles run only against targets tagged `uat`. The API enforces this; the UI only reflects it.
- **History is append-only** and kept forever. Raw reports and logs are kept by default.
- **Concurrency caps**: a global worker concurrency, a per-tool `max_parallel` from the catalogue, and one DAST job at a time.

### 1.3 Coding standards (backend)

- Layers: `api/` (FastAPI routers, request/response models only) → `domain/` (services, policy, business rules) → `db/` (SQLAlchemy models, repositories) and `integrations/` (DefectDojo, GitHub, SonarQube, Entra clients) and `runner/` (Docker launcher, workspaces, tool command builders). Routers contain no business logic. Jobs in `jobs/` call domain services.
- Everything typed. `mypy --strict` for `securescan/` (allow `ignore_missing_imports` only for libraries without stubs, listed in `pyproject.toml`).
- Async FastAPI and async SQLAlchemy sessions. Procrastinate tasks are `async def`.
- Pydantic models for every API body and every YAML/JSON file SecureScan reads (`scanners/catalogue.yaml`, profiles, snapshots).
- Configuration only through `securescan/config.py` (pydantic-settings), env var prefix `SECURESCAN_`. Any `SECURESCAN_*_FILE` variable loads the value from that file and strips trailing whitespace and line endings (Docker secrets written on Windows may carry `\r\n`).
- Times in UTC, stored as `timestamptz`. IDs are UUIDv7 (Python 3.14 `uuid.uuid7()`; if unavailable in the pinned interpreter use the `uuid6` package and record it).
- Logging through `structlog` as JSON lines to stdout, always with `scan_id`, `job_id`, `tool` when known. Every `AuditEvent` is also emitted as a structlog line with `event=audit`, which is how the corporate SIEM receives it. Never log request bodies, tokens or file contents.
- Errors to clients use RFC 9457 problem details (`application/problem+json`). Every list endpoint uses cursor pagination (`?after=<opaque>&limit=`).
- Every Procrastinate task is idempotent and safe to retry.

### 1.4 Coding standards (frontend)

- TypeScript `strict: true`, `noUncheckedIndexedAccess: true`. ESLint (typescript-eslint recommended-type-checked) and Prettier; no warnings allowed in CI.
- API access only through the generated client in `frontend/src/api/` (regenerated from the backend's OpenAPI document by `npm run gen:api`). No hand-written fetch calls.
- Server state in TanStack Query; filter state in the URL; no global client state library.
- Components from `frontend/src/components/ui/` (shadcn/ui pattern, generated into the repo); monochrome theme tokens in `frontend/src/styles/theme.css`. Colour appears only for severity and scan status, always with a text label.
- Accessibility: every control has a label; keyboard reachable; contrast AA. Playwright tests include an `axe` check per page.

### 1.5 Testing requirements

- Unit tests next to the code they test (`backend/tests/unit/`, `frontend/src/**/*.test.tsx`).
- Integration tests in `backend/tests/integration/` run against the `test` Compose profile (`db` + DefectDojo). They are marked `@pytest.mark.integration` and skipped unless `SECURESCAN_INTEGRATION=1`.
- Contract tests in `backend/tests/contract/` import each fixture report in `backend/tests/fixtures/reports/` into DefectDojo and assert a non-zero finding count and expected severities. They run before every DefectDojo or scanner image upgrade. The fixture reports are produced in M1 (S1 step 0) by running each pinned image by hand against the planted apps, and refreshed whenever an image is bumped.
- Planted sample applications live in `backend/tests/fixtures/sample-apps/` (`java-planted` with a committed `target/*.jar`, `js-planted`, `python-planted`, `csharp-planted`), each with an `expected-findings.yaml` listing the finding titles each tool must report. They are created in M0 task 12. External repositories for the regression suite are fetched by `scripts/fetch_fixtures.py` into `fixtures/external/` (git-ignored): OWASP Juice Shop and OWASP WebGoat.
- Every scanner adapter has a unit test for its command builder and exit-code mapping, and one integration test that runs the real image against a sample app.
- End-to-end: Playwright tests in `frontend/e2e/` cover login, start a SAST scan, query history and export CSV, open a report, Settings as Admin, Settings denied as Analyst (M6); start a DAST scan and the production/UAT rule (M9); the vendor flow (M10).

### 1.6 Secrets and configuration

- Never in git: `deploy/.env`, `deploy/images.env`, `deploy/secrets/*`, any `*.pem`, any token. `deploy/.env.example` and `deploy/secrets/README.md` document every value.
- Docker secrets are files in `deploy/secrets/` mounted at `/run/secrets/<name>`; the app reads them through `SECURESCAN_<NAME>_FILE`. DefectDojo reads `DD_*_FILE` the same way. Secret files are written in binary mode without a trailing newline (`scripts/dev.py secrets init`), and every loader strips whitespace anyway.
- Stored secrets (GitHub App key, deploy keys, vendor tokens, DAST login profiles, NVD key, DefectDojo and SonarQube tokens) are encrypted at rest with AES-256-GCM under a master key from the Docker secret `securescan_master_key`; key id stored with each ciphertext for rotation.

### 1.7 Git conventions

- Branch `main` is always deployable. Work on `m<N>-<slug>` branches, squash or merge into `main` when the milestone's acceptance checklist passes.
- Conventional commits. One logical change per commit. Lock files committed. Generated API client committed.
- `.gitattributes`: `* text=auto eol=lf`; `.editorconfig` with LF and 2-space (TS, YAML) / 4-space (Python) indentation. Shell scripts must be LF.

### 1.8 Licence rules

- Semgrep rules (Semgrep Rules License v1.0): internal use only; keep licence notices with the rule bundle; do not expose rule files for download; reports are internal documents by default. Exclude the AGPL-3.0 `trailofbits.*` rules from the default bundle (the updater filters by `metadata.license`).
- SonarQube Community Build analyzers (Sonar Source-Available License): internal use; never feed SonarQube output or snippets to an external AI service.
- CodeQL: not used. Do not add it.
- Libraries and images: psycopg LGPL-3.0; SpotBugs LGPL-2.1; Find Security Bugs LGPL-3.0; Squid GPL-2.0-or-later (run unmodified as a container); Eclipse Temurin GPL-2.0 with Classpath Exception (base image only); everything else MIT, BSD or Apache-2.0. Record the inventory with sources in `docs/licences.md` (M0) and verify each entry against the project's licence file when you write it.

---

## 2. Development environment

> **Update 2026-10-07:** the user develops and runs on **Ubuntu 24** with native Docker Engine, not Windows 11. Ignore the Windows, WSL2 and winget steps below; use `deploy/README.md` for the Ubuntu host settings. Everything else in this section still applies.

### 2.1 The user's machine (Windows 11)

1. **Docker Desktop with the WSL2 backend.** Check: `docker version` (Engine 29 or later) and `docker compose version` (2.24 or later; the plan uses the Compose `include` element and repeated `--env-file`). If Docker Desktop is missing or cannot start, stop and ask the user.
2. **Kernel settings for SonarQube** (needed from M1 spike S3 on). In WSL2 the Docker Desktop VM needs `vm.max_map_count=524288`. Two ways; document both in `deploy/README.md`:
   - Temporary: `wsl -d docker-desktop sysctl -w vm.max_map_count=524288` (lost on restart).
   - Persistent: add to `%USERPROFILE%\.wslconfig` under `[wsl2]`: `kernelCommandLine = sysctl.vm.max_map_count=524288`, then `wsl --shutdown`.
3. **uv**: `winget install astral-sh.uv`, then `uv python install 3.14` and `uv sync` in `backend/`.
4. **Node 24 LTS**: `winget install OpenJS.NodeJS.LTS`, then `npm ci` in `frontend/`.
5. **Git line endings**: `git config core.autocrlf false` in this repo; `.gitattributes` enforces LF.
6. **Host names for local use**: `securescan.localtest.me` and `dojo.securescan.localtest.me` resolve to 127.0.0.1 on the public internet, so no hosts-file edits are needed. The dev gateway listens on `https://securescan.localtest.me:8443` with a self-signed certificate generated by `scripts/dev.py certs` (uses Python `cryptography`; `mkcert` optional).
7. **Runtime data and bind mounts.** All runtime data lives in named Docker volumes with fixed names (`name:` in Compose), never in bind mounts from the Windows filesystem. Scanner containers must receive bind mounts of job sub-directories, and the Docker daemon resolves bind sources on the daemon's host, not inside the worker. So the worker reads the daemon-side path of the data volume once at start (`GET /volumes/securescan_data` → `Mountpoint`, normally `/var/lib/docker/volumes/securescan_data/_data`; override with `SECURESCAN_DATA_HOST_ROOT`), and builds every `Binds` entry from that host path while itself seeing the same volume at `/var/lib/securescan`. The socket proxy restricts bind sources to that host path (`-allowbindmountfrom`). This works identically on Docker Desktop/WSL2 and on the Linux machine.
8. **Users and permissions.** The backend image runs as uid 1000 (`app`), the same uid most scanner images use (`semgrep -nonroot`, sonar-scanner-cli, ZAP, Dependency-Check). Workspace directories are created mode 0775 by the worker and need no `chown`. Images that only run as root (Gitleaks, Syft, Grype, Nuclei default tags) write into the same directories; the worker reads their output as uid 1000 because the directories are group-writable and the files are world-readable. S7 confirms this for every image.

### 2.2 Identity provider for development

- Preferred: an Entra ID test tenant and app registration the user provides (section 7 lists the values). Ask once at M2; if not available, use the mock.
- Mock for development only: `ghcr.io/navikt/mock-oauth2-server` in the `dev` Compose profile. Configure it with a JSON file `deploy/dev/mock-oidc.json` that issues ID tokens with a `roles` claim (`["Admin"]` or `["Analyst"]`) depending on the user name typed on its login page. Verify the image tag and configuration format on its GitHub README when you set it up and record the result in `docs/decisions.md`. If it does not fit, fall back to Keycloak (`quay.io/keycloak/keycloak` in `start-dev` mode) with a client role mapper that puts realm roles into a `roles` claim.
- The mock provider is never part of the production Compose files.

### 2.3 Running the stack locally

`scripts/dev.py` (Python, cross-platform) wraps everything. It always runs Compose as `docker compose --project-directory deploy --env-file deploy/.env --env-file deploy/images.env -f deploy/compose.yaml [-f deploy/compose.dev.yaml] ...`.

| Command | What it does |
| --- | --- |
| `python scripts/dev.py certs` | Generates the self-signed TLS certificate for the gateway and for PostgreSQL into `deploy/secrets/tls/` |
| `python scripts/dev.py secrets init` | Creates random secrets in `deploy/secrets/` for everything that can be generated (master key, DB passwords, DefectDojo admin password, DefectDojo secret key and AES key, SonarQube admin password); binary mode, no trailing newline |
| `python scripts/dev.py pin-images` | Resolves every tag in `deploy/images.lock.yaml` to its current digest, writes the lock and `deploy/images.env` (`IMG_<NAME>=<name>@sha256:...`) |
| `python scripts/dev.py pull-images` | Pulls every image in the lock (scanner images are pre-pulled; the socket proxy does not allow pulls) |
| `python scripts/dev.py up [--profile dev]` | Compose up with the chosen profiles |
| `python scripts/dev.py down [--volumes]` | Stops everything; `--volumes` also wipes data |
| `python scripts/dev.py migrate` | Runs the `migrate` one-shot container |
| `python scripts/dev.py logs <service>` | Follows logs |
| `python scripts/dev.py test [unit|integration|contract|e2e|regression]` | Runs the test suites |
| `python scripts/dev.py fetch-fixtures` | Clones Juice Shop and WebGoat into `fixtures/external/` |

Compose project name is fixed to `securescan` (`name: securescan` at the top of `deploy/compose.yaml`), so containers are `securescan-db-1`, `securescan-api-1`, and so on. Compose profiles: default (always-on set), `dev` (mock OIDC, hot-reload mounts), `test` (DB + DefectDojo only, random ports).

### 2.4 Deployment target (the Linux machine)

Documented in `deploy/README.md` (written in M0, completed as `docs/install.md` in M11): 64-bit Linux with systemd and cgroup v2; Docker Engine 29+ and Compose 2.24+; `vm.max_map_count=524288` and `fs.file-max=131072` persisted in `/etc/sysctl.d/99-securescan.conf`; outbound HTTPS to github.com and api.github.com, `login.microsoftonline.com`, Docker Hub, GHCR, quay.io, `grype.anchore.io`, `services.nvd.nist.gov`, `www.cisa.gov`, `raw.githubusercontent.com`, `dependency-check.github.io`, `api.pdtm.sh` (Nuclei updater), GitHub release downloads (Nuclei templates, semgrep-rules), `search.maven.org` and `repo1.maven.org`; a DNS name for the portal and one for DefectDojo under the same parent domain (for example `securescan.corp.example` and `dojo.securescan.corp.example`), and a TLS certificate from the corporate CA. Recommended machine: 16 vCPU, 64 GB RAM, 500 GB SSD (minimum 8 vCPU, 32 GB).

---

## 3. Target repository layout

```
c:\SecureScan
  CLAUDE.md                      project instructions for coding agents (exists)
  README.md                      what SecureScan is, how to start, links to docs
  .gitattributes .editorconfig .gitignore
  docs/
    design.md                    exported design (do not edit here; the Claude Doc is the original)
    implementation-plan.md       this file
    progress.md                  milestone checklist and deviations (append only)
    decisions.md                 dated decisions made during the build
    licences.md                  licence inventory
    security-checklist.md        section 5.1, ticked at M11
    spikes/                      findings of M1 spikes
    runbooks/                    operational runbooks (M11)
    install.md                   Linux installation guide (M11)
  backend/
    pyproject.toml  uv.lock  alembic.ini  README.md
    securescan/
      __main__.py                dispatch: api | worker | migrate | dojo-init | sonar-init
      main.py                    app factory, middleware, router registration
      config.py                  pydantic-settings, *_FILE loading with strip()
      logging.py                 structlog JSON config and secret scrubbing
      db/
        engine.py  session.py  base.py
        models/                  one module per aggregate: vendors, applications, versions, targets,
                                 profiles, scans, jobs, artifacts, history, reports, templates,
                                 policies, schedules, credentials, github, content, images, users,
                                 sessions, outbox, audit
        migrations/              Alembic (versions/ + env.py); Procrastinate schema and migrations applied here
        repositories/            query helpers per aggregate
      auth/
        oidc.py                  Authlib client, code flow, roles claim
        session.py               server-side sessions (table) + cookie
        roles.py                 Role enum, dependencies require_admin / require_analyst
        csrf.py
      api/
        router.py                includes all routers under /api/v1
        auth.py applications.py versions_targets.py vendors.py uploads.py scans.py results.py
        history.py reports.py templates.py github.py credentials.py profiles.py schedules.py policies.py
        content.py admin.py defectdojo.py summary.py health.py
        problems.py              RFC 9457 helpers
        pagination.py            cursor pagination helpers
      domain/
        scans.py                 create scan + jobs, state machine, cancel
        policy.py                verdict evaluation
        history.py               append rows, nightly state refresh, queries, CSV export
        reports.py               snapshot + render orchestration, watermark
        vendors.py               vendor assessment logic, deltas
        accounts.py              DefectDojo account provisioning
        mappings.py              CWE → OWASP Top 10 / CWE Top 25 lookups
      jobs/
        app.py                   Procrastinate app and worker entry point
        scan_job.py import_job.py history_sync.py report_job.py github_poll.py github_discovery.py
        updaters.py sonarqube_lifecycle.py egress_lifecycle.py image_updates.py
        maintenance.py           stalled jobs, workspace gc, account expiry, credential expiry alerts
      runner/
        catalogue.py             loads and validates scanners/catalogue.yaml, overlays approved ImageVersion rows
        launcher.py              Docker API through socket-proxy: create/start/wait/logs/inspect/stop/kill/remove, volumes/{name}
        workspace.py             per-job directories under /var/lib/securescan/workspaces, host-path mapping
        sources/                 github.py (clone with token helper, full history), zip.py (safe unpack), image.py (skopeo + rootfs extract)
        tools/                   one command builder per tool (NOT parsers): semgrep.py gitleaks.py syft_grype.py
                                 dependency_check.py spotbugs.py sonarqube.py zap.py nuclei.py
        egress.py                squid container management and per-job allowlists
        validate.py              output file exists, parses as JSON/XML, under the size cap
      integrations/
        defectdojo/client.py     httpx client: reimport, findings, users, product types, system settings
        github/app.py            JWT, installation tokens, repos, branch heads
        sonarqube/client.py      system status, users, tokens, projects, ce tasks, measures, issues export
      reports/
        renderer.py              sandboxed Jinja2 + WeasyPrint, CSS and images inlined for the HTML output
        snapshot.py              snapshot schema (Pydantic) built from DefectDojo findings + scan facts
        watermark.py             per-download PDF stamp (pypdf)
        mappings/                owasp-top10-2021.yaml  cwe-top25-2025.yaml
        templates/default-sonacomstar/   template.html style.css brand/wordmark.svg fonts/
      storage/artifacts.py       artifact volume layout, SHA-256, retention
      security/secrets.py        AES-256-GCM envelope encryption
      security/csv_safe.py
      observability/metrics.py   Prometheus metrics
    tests/
      unit/ integration/ contract/
      fixtures/reports/          one real report per scanner for contract tests (produced in M1)
      fixtures/sample-apps/      planted apps: java-planted (with target/*.jar), js-planted, python-planted, csharp-planted
  frontend/
    package.json  vite.config.ts  tsconfig.json  tailwind.config.ts  components.json
    src/
      main.tsx  router.tsx
      routes/  login.tsx  home.tsx  sast.tsx  dast.tsx  history.tsx  settings/*.tsx  scan-detail.tsx  report.tsx
      components/ui/             shadcn/ui components (generated, committed)
      components/                app components (ScanTable, SeverityBadge, Wordmark, ...)
      api/                       generated client (openapi-typescript) + query hooks
      lib/                       auth context, SSE hook, csv download, formatting
      styles/theme.css           monochrome tokens
      brand/                     wordmark.svg (logo drops in here later)
    e2e/                         Playwright
  scanners/
    catalogue.yaml               the fixed scanner catalogue (see M3 task 1 for the schema)
    profiles/                    code-standard.yaml dast-baseline.yaml dast-full.yaml dast-api.yaml
                                 zap-baseline-prod.yaml zap-full-uat.yaml zap-api-uat.yaml nuclei-uat.yaml
                                 dependency-check.yaml semgrep.yaml
    spotbugs/Dockerfile          self-built SpotBugs + Find Security Bugs image
    regression/                  expected-findings per fixture app and tool, used by updaters and image bumps
    README.md                    how to add or bump a tool
  content/
    README.md                    what lives on the content volume and how updaters fill it
    semgrep-rules.lock           pinned commit of semgrep-rules and the licence filter
  deploy/
    compose.yaml                 name: securescan; always-on services, networks, volumes, secrets
    compose.defectdojo.yaml      include of DefectDojo's compose + our override (shared db, pinned images, no postgres)
    compose.dev.yaml  compose.test.yaml
    images.lock.yaml             every image: name, tag, digest (images.env is generated, git-ignored)
    gateway/nginx.conf  gateway/Dockerfile
    backend/Dockerfile           one image for api, worker, migrate, dojo-init, sonar-init
    socket-proxy/args.env        the allowlist arguments from S2
    postgres/init/01-databases.sh  postgres/postgresql.conf (ssl on)
    defectdojo/upstream/docker-compose.yml   vendored upstream file, version noted
    defectdojo/override.yaml
    defectdojo/extra_settings/   optional local_settings.py
    dev/mock-oidc.json
    monitoring/alerts.yaml       example Prometheus alert rules (M11)
    secrets/README.md  secrets/.gitkeep
    .env.example  README.md
  scripts/
    dev.py  pin_images.py  fetch_fixtures.py  seed_history.py  backup.sh  restore.sh  check_host.sh
  spikes/                        M1 throwaway scripts (kept for the record, never imported)
```

---

## 4. Milestones

Sizes: S (a few hours of agent work), M (a day or two), L (several days). No calendar estimates.

### M0 — Repository scaffold and tooling (S/M)

**Goal:** an empty but fully wired repository where lint, tests and `docker compose up` already work, with the planted sample apps in place.

**Scope in:** layout, tooling, CI config, Compose skeleton with `db`, `gateway`, `api`, `worker` (heartbeat only), docs skeletons, planted apps. **Out:** any feature.

**Tasks**

0. The folder is not a git repository yet. Run `git init -b main` in `c:\SecureScan`, add `.gitattributes`, `.editorconfig` and `.gitignore` first (next task), then make the first commit with `CLAUDE.md` and `docs/`: `docs: add design, implementation plan, progress and decisions`. Record the section 8.3 deviations in `docs/decisions.md` in the same commit.
1. Create the layout from section 3 (empty packages with `__init__.py`, placeholder `README.md` files). Add `.gitattributes` (`* text=auto eol=lf`), `.editorconfig`, `.gitignore` (Python, Node, `deploy/.env`, `deploy/images.env`, `deploy/secrets/*` except `README.md` and `.gitkeep`, `fixtures/external/`, `*.pem`).
2. `backend/pyproject.toml`: project `securescan`, Python `>=3.14,<3.15`, dependencies from 1.1, dev group (pytest, pytest-asyncio, httpx, ruff, mypy, types-*). `uv lock`, `uv sync`. Configure ruff (line length 100, rules `E,F,I,B,UP,S,ASYNC`), mypy strict, pytest asyncio mode auto.
3. `backend/securescan/main.py` with a FastAPI app exposing `GET /healthz` (always 200) and `GET /readyz` (checks DB); `config.py` with pydantic-settings and the `*_FILE` loader that strips whitespace; `__main__.py` dispatching `api` (uvicorn), `worker` (in M0 an `asyncio` loop that logs a heartbeat every 30 s; replaced in M2), `migrate`, `dojo-init`, `sonar-init` (the last three print "not implemented" and exit 0 until their milestones). Unit tests: the `_FILE` loader with a CRLF-terminated file yields the stripped value.
4. `frontend/`: `npm create vite@latest` (react-ts), add Tailwind, shadcn/ui init (`components.json`), ESLint + Prettier, Vitest, Playwright. A single route that renders the wordmark and "SecureScan". `npm run build` must produce `frontend/dist`.
5. `deploy/backend/Dockerfile`: multi-stage; builder installs with `uv sync --frozen --no-dev` into `/app/.venv`; runtime `python:3.14-slim-trixie` with `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-liberation git openssh-client` installed, non-root user `app` with **uid 1000 and gid 1000** (`groupadd -g 1000 app && useradd -u 1000 -g 1000 -m app`), `ENTRYPOINT ["/app/.venv/bin/python", "-m", "securescan"]`, `CMD ["api"]`.
6. `deploy/gateway/Dockerfile`: `FROM node:24 AS build` builds the frontend; `FROM nginxinc/nginx-unprivileged` copies `dist/` and `nginx.conf`. `nginx.conf`: two `server` blocks (portal host, DefectDojo host), TLS from `/run/secrets/tls_*`, security headers, gzip, `/api/` proxied to `api:8000` (never `/healthz`, `/readyz` or `/metrics`), SSE-friendly settings (`proxy_buffering off` for `/api/v1/scans/*/events`), `limit_req_zone $cookie_securescan_session zone=session:10m rate=20r/s` applied to `/api/`, static assets with long cache for hashed files. The DefectDojo block returns 503 until M4.
7. `deploy/compose.yaml`: `name: securescan`. Services `db` (PostgreSQL 18, `POSTGRES_PASSWORD_FILE`, volume `pgdata` mounted at `/var/lib/postgresql` per the 18+ layout, `ssl=on` with the certificate from `deploy/secrets/tls/` via a mounted `postgresql.conf`, init script `deploy/postgres/init/01-databases.sh` creating databases `securescan`, `defectdojo` and `sonarqube` with their own roles from secret files), `gateway`, `api`, `worker`, `migrate` (one-shot), `socket-proxy` (placeholder config, finished in M3). Networks: `frontend` (gateway↔api), `backend` (api, worker, db, DefectDojo), `docker` (worker↔socket-proxy), `sonarqube` (`internal: true`), `dast` (`internal: true`), `egress` (routable; only egress proxies join it). Volumes with fixed names: `securescan_data` (`name: securescan_data`), `pgdata`, `artifacts`, `content`, `grype_db`, `odc_data`, `sonarqube_data`, `sonarqube_extensions`, `sonarqube_logs`. Secrets listed with `file:` paths under `deploy/secrets/`. The worker mounts `securescan_data` at `/var/lib/securescan` and `artifacts` at `/var/lib/securescan/artifacts`.
8. `deploy/images.lock.yaml` with every image from 1.1 and `scripts/pin_images.py` that runs `docker buildx imagetools inspect <image>:<tag>` to fill digests and writes `deploy/images.env`. Run it once and commit the lock (not `images.env`).
9. `scripts/dev.py` with the commands in 2.3, including `pull-images`. `secrets init` writes files in binary mode without a trailing newline.
10. CI: `.github/workflows/ci.yml` running ruff, mypy, pytest unit, npm lint/typecheck/test, and a Docker build of both images. (It is fine if the corporate GitHub does not run it; it documents the checks.)
11. Docs: `docs/licences.md` (table from 1.8 with licence-file links), `deploy/README.md` (host prerequisites, first start), `README.md`; append to `docs/progress.md` and `docs/decisions.md`.
12. **Planted sample apps** in `backend/tests/fixtures/sample-apps/`: `java-planted` (a small Maven project with a servlet containing SQL injection via string concatenation, a hard-coded AWS-style key, an outdated dependency in `pom.xml`; commit the built `target/java-planted.jar` so SpotBugs can run without a build), `js-planted` (Express app with `eval` on request input, a child-process command built from a query parameter, a hard-coded token, an outdated dependency in `package-lock.json`), `python-planted` (Flask app with a `subprocess` shell injection, `pickle.loads` on request data, a hard-coded secret, an outdated pinned dependency in `requirements.txt`), `csharp-planted` (minimal ASP.NET source with string-built SQL and a hard-coded connection string; no build output). Each has `expected-findings.yaml`: per tool, the finding titles or rule ids that must appear (fill the lists in M1 after the first real runs, then keep them current).

**Acceptance**

- [ ] `git log` shows the initial commits; `git status` is clean.
- [ ] `uv run pytest`, `uv run ruff check .`, `uv run mypy securescan` pass in `backend/`.
- [ ] `npm run lint && npm run typecheck && npm test && npm run build` pass in `frontend/`.
- [ ] `python scripts/dev.py secrets init && python scripts/dev.py certs && python scripts/dev.py pin-images && python scripts/dev.py up` starts `db`, `api`, `worker`, `gateway`; `https://securescan.localtest.me:8443/` shows the wordmark page; `docker exec securescan-api-1 python -c "import urllib.request;print(urllib.request.urlopen('http://localhost:8000/healthz').status)"` prints 200; the worker logs a heartbeat.
- [ ] `docker exec securescan-db-1 psql -U postgres -c '\l'` lists `securescan`, `defectdojo`, `sonarqube`; `psql "sslmode=require"` connects.
- [ ] `deploy/images.lock.yaml` has a digest for every image; `deploy/images.env` exists and is git-ignored.
- [ ] The four planted apps exist with `expected-findings.yaml` skeletons.

**Tests:** config loader (including CRLF), health endpoints. **Risks:** PostgreSQL 18 image volume path (`/var/lib/postgresql`); enabling SSL in the official image needs the cert files owned by the postgres user (uid 999) with mode 0600 — copy them in the entrypoint or use an init script. **Size:** S/M.

### M1 — Spikes (M/L)

**Goal:** prove the risky integrations with throwaway scripts and write down what was learned, before any production code depends on them.

Each spike is a script under `spikes/<name>/` plus a findings file `docs/spikes/<name>.md` with: what was tried, exact commands and responses, timings, what differs from `docs/design.md`, and the decision for production code. Spikes may use the bundled DefectDojo postgres and ad-hoc Compose files; they must not touch `deploy/compose.yaml`.

**S7 Scanner container contract (do this first)**

1. Run each scanner image by hand with the M3 HostConfig (`ReadonlyRootfs: true`, `CapDrop: ["ALL"]`, `SecurityOpt: ["no-new-privileges"]`, `NetworkMode: none`, `PidsLimit`, `Memory`, bind mounts for `src` read-only and `out` read-write, `tmpfs` for `/tmp`) against the planted apps: `semgrep/semgrep:<tag>-nonroot`, `ghcr.io/gitleaks/gitleaks`, `anchore/syft`, `anchore/grype` (with a DB volume filled first by `grype db update` in a separate run with network), `owasp/dependency-check` (with `odc_data` filled first by `--updateonly` with network; this takes 20 minutes or more; start it early), `sonarsource/sonar-scanner-cli` (against the S3 server), the SpotBugs image built from `scanners/spotbugs/Dockerfile` (write that Dockerfile now: `FROM eclipse-temurin:21-jre`, download the SpotBugs 4.10.x release zip and `findsecbugs-plugin-1.14.0.jar` from GitHub releases / Maven Central with `sha256sum -c`, non-root user uid 1000, `ENTRYPOINT ["/opt/spotbugs/bin/spotbugs"]`), `ghcr.io/zaproxy/zaproxy` (plan run against Juice Shop) and `projectdiscovery/nuclei` (against Juice Shop with templates pre-fetched).
2. For each image record: the uid it runs as; which paths must be writable (`HOME`, `~/.semgrep`, `/opt/sonar-scanner/.sonar/cache` or `SONAR_USER_HOME`, `/tmp`, `/zap/wrk`) and therefore need a tmpfs or the `out` mount; whether `/content` mounts can be read-only (Grype DB with `GRYPE_DB_AUTO_UPDATE=false`; Dependency-Check `odc_data` with `--noupdate`, and whether two concurrent Dependency-Check containers can share it read-only); the exact command line that worked; the exit code on a clean target, on findings, and on a broken input; the output file names; and for Dependency-Check the property name that carries the NVD key in `--propertyfile` (expected `nvd.api.key`; verify on the pinned image).
3. Produce one real report per scanner from these runs and commit them under `backend/tests/fixtures/reports/` (`semgrep.json`, `gitleaks.json`, `grype.json`, `dependency-check-report.xml`, `spotbugs.xml`, `sonarqube-issues.zip`, `zap.xml`, `nuclei.json`). Fill the planted apps' `expected-findings.yaml`.
4. Exit criterion: `docs/spikes/scanner-contract.md` with a table per image (uid, writable paths, read-only content ok, command, exit codes, outputs) that M3 and M8 copy into `scanners/catalogue.yaml`.

**S1 DefectDojo import and deduplication**

1. Start DefectDojo 3.4.0 from its upstream `docker-compose.yml` (copy into `spikes/s1/`) with `DD_IMAGE_REGISTRY=docker.io`, `DJANGO_VERSION=3.4.0`, `NGINX_VERSION=3.4.0`, and `DD_ADMIN_PASSWORD` set on the `initializer` service.
2. `POST /api/v2/api-token-auth/` with the admin credentials → admin token (used in the spike only; production uses the two service accounts below).
3. `POST /api/v2/users/` → `securescan-sync` (`is_staff: true`, `is_superuser: false`, `is_active: true`, random password) and `securescan-accounts` (`is_superuser: true`, random password); `api-token-auth` for each → two tokens. Confirm with the sync token that `reimport-scan` with `auto_create_context` works and that `POST /api/v2/users/` is refused; confirm with the accounts token that creating a staff user works.
4. `GET /api/v2/system_settings/` and `PATCH /api/v2/system_settings/<id>/` `{"enable_deduplication": true}` (deduplication is off by default).
5. `POST /api/v2/product_types/` for `Internal Applications` and `Vendor Applications` (GET first; create only if missing).
6. `POST /api/v2/reimport-scan/` (multipart) twice with the fixture `semgrep.json`: `scan_type=Semgrep JSON Report`, `product_type_name=Internal Applications`, `product_name=spike-app`, `engagement_name=main`, `test_title=semgrep:main`, `auto_create_context=true`, `deduplication_on_engagement=true`, `close_old_findings=true`, `deduplication_execution_mode=async_wait`, `minimum_severity=Info`. Record `test_id`, `statistics.after`, `deduplication_complete`. Then import a modified copy with one finding removed and confirm it is closed (`is_mitigated`).
7. `GET /api/v2/findings/?test=<id>&active=true&duplicate=false&false_p=false&out_of_scope=false&risk_accepted=false&limit=200` → record the fields available per finding (title, severity, cwe, vulnerability_ids, component_name, component_version, file_path, line, hash_code, active, verified, false_p, duplicate, out_of_scope, risk_accepted, is_mitigated, date). Check whether an `id__in` filter exists for batch state refresh; if not, record the per-product paging approach.
8. Import every other fixture report from S7 with its scan type (`Gitleaks Scan`, `Anchore Grype`, `Dependency Check Scan`, `ZAP Scan`, `Nuclei Scan`, `SpotBugs Scan`, `SonarQube Scan`). Record any rejection and the finding counts.
9. Check whether `force_password_reset` can be set through `POST`/`PATCH /api/v2/users/`; record the result (design wants a forced change at first login; fallback: show the password once and let the user change it in DefectDojo).
10. Exit criterion: `docs/spikes/defectdojo.md` holds working request/response pairs for every call above and a decision on `DD_HASHCODE_FIELDS_PER_SCANNER` overrides (start with the defaults; note that Semgrep CE has no fingerprint).

**S2 Socket proxy allowlist**

1. Run `wollomatic/socket-proxy` with `/var/run/docker.sock` mounted and the Python docker SDK (`DOCKER_HOST=tcp://socket-proxy:2375`) from a second container.
2. Derive the exact request paths the SDK makes for: ping, version, create container (with `NetworkingConfig.EndpointsConfig` listing two networks), start, wait, logs, inspect, stop, kill, remove, `GET /volumes/securescan_data`, `GET /containers/sonarqube/json`, `POST /containers/sonarqube/start`, `POST /containers/sonarqube/stop`. Write the allow regexes (`-allowGET`, `-allowPOST`, `-allowDELETE`) that permit exactly those (paths look like `/v1.4x/containers/create`), plus `-allowfrom <worker address>` and `-allowbindmountfrom /var/lib/docker/volumes/securescan_data/_data` (the Mountpoint from `GET /volumes/securescan_data`).
3. Confirm denied calls (`POST /containers/<id>/exec`, `GET /containers/json`, `POST /networks/create`, `POST /images/create`, `POST /volumes/create`) return HTTP 403. Images are pre-pulled by `dev.py pull-images`; pulls are not allowed through the proxy.
4. Exit criterion: the final argument list in `deploy/socket-proxy/args.env` and `spikes/s2/test_allowlist.py` asserting allow and deny behaviour (re-run in M9 after any change).

**S3 SonarQube on demand**

1. Start `sonarqube:26.9.0.129388-community` with `container_name: sonarqube` against the PostgreSQL 18 `sonarqube` database (`SONAR_JDBC_URL=jdbc:postgresql://db:5432/sonarqube?ssl=true&sslmode=verify-full&sslrootcert=/run/secrets/tls_ca`), named volumes for `/opt/sonarqube/data`, `/opt/sonarqube/extensions`, `/opt/sonarqube/logs`, `ulimits nofile 131072 / nproc 8192`, `stop_grace_period: 300s`, and `vm.max_map_count` set on the host.
2. Time `GET /api/system/status` until `UP` on first start and on a warm restart.
3. Change the admin password: `POST /api/users/change_password` with `login=admin&previousPassword=admin&password=<12+ chars, mixed>` using basic auth `admin:admin`.
4. Create a service user and `POST /api/user_tokens/generate` (`type=USER_TOKEN`); create a project (`POST /api/projects/create` with `project`, `name`); generate a `PROJECT_ANALYSIS_TOKEN` with `expirationDate`.
5. Run `sonarsource/sonar-scanner-cli:12.2.0.4256_8.1.0` against `js-planted` with `SONAR_HOST_URL`, `SONAR_TOKEN`, `-Dsonar.projectKey=...`, `-Dsonar.working.directory=/out/.scannerwork`, `SONAR_USER_HOME=/tmp/.sonar`, the source mounted at `/usr/src` writable by uid 1000; read `/out/.scannerwork/report-task.txt` → `ceTaskId`; poll `GET /api/ce/task?id=...` until `SUCCESS`.
6. `GET /api/qualitygates/project_status?projectKey=...`; `GET /api/measures/component?component=...&metricKeys=bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density,ncloc,alert_status`; page `GET /api/issues/search?components=...&ps=500&p=N` into a zip; import the zip into DefectDojo as `SonarQube Scan`. Check that the issues carry `type` and `severity` (Standard Experience mode); if not, find the setting that switches the instance to Standard Experience and record it.
7. Run `java-planted` without passing `sonar.java.binaries` and record whether the scan warns or fails.
8. Stop the container and time the stop. Exit criterion: `docs/spikes/sonarqube.md` with timings and a go/no-go on the 15-minute idle stop.

**S4 Entra ID OIDC with app roles**

1. With the user's test tenant (or the mock provider): Authlib `OAuth` client, authorization code flow with PKCE, scopes `openid profile email`, redirect `https://securescan.localtest.me:8443/api/v1/auth/callback`.
2. Decode the ID token; confirm the `roles` claim carries `Admin` or `Analyst`; confirm a user with no assigned role is rejected (Entra: "assignment required" on the enterprise application).
3. Exit criterion: the claim shapes recorded in `docs/spikes/entra.md`, and the Entra setup steps for IT written into `deploy/README.md` (app registration, redirect URIs, app roles manifest with values `Admin` and `Analyst`, assignment required, client secret or certificate).

**S5 WeasyPrint in the slim image**

1. Build `deploy/backend/Dockerfile` and render a two-page HTML (inline CSS, wordmark SVG as a `data:` URI, table, severity badges, page numbers via CSS `@page`) to PDF with WeasyPrint 70 inside the container. Confirm fonts render (Liberation Sans) and that a restricted `url_fetcher` blocks `file:` and `http:` URLs outside the template directory. Stamp the PDF with pypdf ("Downloaded by Test User on 2026-10-07 10:00 UTC") and confirm the text is extractable.
2. Exit criterion: a sample PDF checked in under `docs/spikes/weasyprint-sample.pdf` and the final apt package list.

**S6 GitHub App**

1. Register a test GitHub App on the user's organisation or a personal account (ask the user; permissions `Contents: read`, `Metadata: read`; webhook disabled). Save App ID, installation ID and private key under `deploy/secrets/` (git-ignored).
2. Mint a JWT (RS256, `iat` 60 s in the past, `exp` 9 min ahead, `iss` = client ID) and `POST /app/installations/<id>/access_tokens` with `repositories: [<one repo>]` and `permissions: {contents: read}`; header `X-GitHub-Api-Version: 2026-03-10`.
3. `GET /installation/repositories` (paginate `per_page=100`); `GET /repos/<owner>/<repo>/branches/<default>` → head SHA.
4. Clone with a credential helper, never a token in the URL, and with full history and all refs (Gitleaks needs them; a blobless or shallow clone must not be copied into production): `git -c credential.helper='!f() { echo username=x-access-token; echo password=$GH_TOKEN; }; f' clone --no-single-branch <https url>`; then `git remote remove origin`. Confirm no token in `.git/config` (`grep -r ghs_ .git` finds nothing).
5. Exit criterion: `docs/spikes/github.md` with the working calls and the token length observed (around 520 characters on github.com since October 2026; treat as opaque).

**S8 Opengrep (one hour, optional outcome)**

1. Run the Opengrep CLI release binary on `js-planted` with the same local rules as Semgrep and `--sarif`; note whether an official container image exists and whether DefectDojo's `SARIF` import accepts the output.
2. Exit criterion: one paragraph in `docs/spikes/opengrep.md` and a line in `docs/decisions.md`: deferred, fallback engine only.

**Acceptance for M1**

- [ ] Eight findings files exist under `docs/spikes/` with commands, responses and decisions; fixture reports exist under `backend/tests/fixtures/reports/`; `expected-findings.yaml` files are filled.
- [ ] `docs/decisions.md` records every deviation from `docs/design.md` found by the spikes.

**Size:** M/L. **Risks:** real tenant/App credentials; keep them in `deploy/secrets/` only. Dependency-Check's first update is slow; run it in the background while doing S1.

### M2 — Backend foundation (L)

**Goal:** the API runs with Entra sign-in, roles, sessions, audit log, the full database schema, the job queue, and CRUD for applications, versions, targets, vendors, uploads and the audit log.

**Tasks**

1. **Models and migrations.** Implement every entity from the design's Data model section in `db/models/` (Vendor, Application, ApplicationVersion, Target, ScanProfile, Scan, ScanJob, Artifact, FindingHistory, Report, ReportTemplate, Policy, Schedule, Credential, GitHubConnection, RepositoryHead, ContentVersion, ImageVersion, User, Session, SyncOutbox, AuditEvent). Enums as PostgreSQL enums: target kind (`github_repo`, `vendor_repo`, `zip`, `image`, `url`), environment (`production`, `uat`), scan trigger (`user`, `change`, `weekly`, `schedule`), job state (`queued`, `preparing`, `running`, `completed`, `completed_partial`, `failed`, `cancelled`, `timed_out`), import state (`pending`, `imported`, `failed`), report kind (`application`, `vendor`), verdict (`pass`, `conditional`, `fail`, `pending`). Indexes: history by `(application_id, severity, scanned_at)`, scans by `(application_id, created_at)`, jobs by `state`, audit by `(created_at)`. Alembic initial migration generated and reviewed by hand. A second Alembic revision applies Procrastinate's `procrastinate/sql/schema.sql` verbatim (read from the installed package at migration time); each later Procrastinate upgrade gets its own revision applying that version's `sql/migrations/*.sql` files in order. Record the Procrastinate version in each such revision's docstring.
2. **Procrastinate.** `jobs/app.py` creates the app with `PsycopgConnector` on the `securescan` database. Worker command runs `app.run_worker_async(concurrency=4, queues=[...])` with queues `scans`, `imports`, `reports`, `maintenance`, `github`. Periodic task skeletons registered (no-ops for now): `stalled_jobs` (every 5 min), `workspace_gc` (hourly), `history_state_refresh` (02:00), `github_discovery` (01:00), `github_poll` (every 10 min), `grype_db_update` (07:30 UTC daily), `nvd_update` (03:00 daily), `rules_and_templates_update` (weekly, Saturday 03:00), `image_update_proposals` (monthly), `account_expiry` (04:00), `credential_expiry_alerts` (05:00), `sonarqube_idle_stop` and `egress_idle_stop` (every 5 min).
3. **Auth.** `auth/oidc.py` (Authlib, discovery from `SECURESCAN_OIDC_ISSUER`, PKCE, state + nonce); `auth/session.py` (sessions table: id, user_id, role, created, expires, last_seen; cookie `securescan_session`, `HttpOnly; Secure; SameSite=Lax; Domain=<SECURESCAN_COOKIE_DOMAIN>` so the DefectDojo host sees it; 8 h idle expiry); `auth/roles.py` with `require_role(Role.ADMIN)` / `require_role(Role.ANALYST)` (Admin satisfies Analyst); `auth/csrf.py` double-submit token for state-changing requests. Users are upserted on sign-in from the ID token (oid, name, email, roles). Sign-in without `Admin` or `Analyst` in `roles` is refused with a problem detail. Endpoints: `GET /api/v1/auth/login`, `GET /api/v1/auth/callback`, `POST /api/v1/auth/logout`, `GET /api/v1/me`, and `GET /api/v1/auth/check` (returns 204 when the session is valid; used by the gateway's `auth_request` for the DefectDojo host).
4. **Audit log.** `AuditEvent` written by a dependency/decorator for every state-changing endpoint and by jobs for scan start/finish, imports, report generation, downloads, exports, settings changes, account provisioning. Fields: actor (user id or `system`), action, object type and id, time, source address, detail (JSON, no secrets). Each event is also emitted as a structlog line `event=audit`. `GET /api/v1/audit-events` (Admin, cursor-paged, filters actor/action/object/date).
5. **CRUD APIs** (Analyst for read and create; Admin for delete): applications (filter by type, vendor, last scan, counts), versions, targets (environment tag changes are audited), vendors. Chunked uploads: `POST /api/v1/uploads` (create, returns id and chunk size), `PATCH /api/v1/uploads/{id}` (chunk by `Content-Range`), finalise computes SHA-256 and stores the file under the artifacts volume as `uploads/<yyyy>/<mm>/<id>`. Size limit 2 GB. Cursor pagination on every list.
6. **Secrets store.** `security/secrets.py` AES-256-GCM with key id; `Credential` rows store ciphertext, kind, expiry; `credential_expiry_alerts` task sets a metric and an admin notice 14 days before expiry.
7. **Problem details, OpenAPI.** Global exception handlers emit RFC 9457. `GET /api/v1/openapi.json` is the document the frontend client is generated from; tag every router.
8. **Metrics.** `GET /metrics` (Prometheus) on the api and worker (worker exposes it on its own port); counters and gauges from the design's observability table registered now, populated in later milestones. `GET /api/v1/admin/health` (Admin) returns the same values as JSON for the Settings page, since `/metrics` is not proxied.
9. **Gateway.** Finish `nginx.conf`: the DefectDojo `server` block uses `auth_request /_securescan_auth;` → `proxy_pass http://api:8000/api/v1/auth/check` and on 401 redirects to the portal login; proxied upstream is `http://nginx:8080` (DefectDojo's nginx service, added in M4; for now return 503).

**Acceptance**

- [ ] `python scripts/dev.py migrate` creates all tables including Procrastinate's; `alembic check` reports no drift.
- [ ] Sign-in with the dev provider as `Admin` and as `Analyst` works; a user without roles gets a 403 problem detail; `GET /api/v1/me` returns the role.
- [ ] `GET /api/v1/auth/check` returns 204 with a valid cookie and 401 without; the cookie is sent to `dojo.securescan.localtest.me`.
- [ ] CRUD endpoints work through `curl` with the session cookie and CSRF token; every change creates an `AuditEvent` row and an `event=audit` log line; `GET /api/v1/audit-events` lists them.
- [ ] A 100 MB chunked upload completes and its SHA-256 matches.
- [ ] The worker starts, registers periodic tasks, and `procrastinate` tables exist.

**Tests:** unit tests for roles, session expiry, CSRF, secrets round-trip, upload chunking, problem details, cursor pagination; integration test for sign-in flow against the mock provider. **Risks:** cookie domain across the two hosts (test early). **Size:** L.

### M3 — Scan runner, workspaces, and the first two tools (L)

**Goal:** start a Semgrep or Gitleaks scan of a zip upload or a GitHub repository (using the token flow from S6 directly for now), watch it live, and find the raw report in the artifact store.

**Tasks**

1. **Catalogue.** `scanners/catalogue.yaml` validated by `runner/catalogue.py` (Pydantic). Each entry: `tool`; `image` (name, pinned digest from `images.lock.yaml`, overlaid by an approved `ImageVersion` row when one exists); `user` (uid, or `root` for images that cannot run otherwise); `network` (`none` | `sonarqube` | `dast`); `mounts` (each with `name` in {`src`, `out`, `config`, `content`}, `target` container path, `read_only`), `tmpfs` (list of container paths with size); `limits` (cpus, memory, pids, timeout minutes); `max_parallel` (per-tool cap); `command` (list template with placeholders only from the fixed set `{src}`, `{out}`, `{config}`, `{content}`, `{target_url}`, `{project_key}`); `optional_args` (an allowlist of switches the tool builder may append, each with a fixed value or a path that must resolve under the `src` or `out` mount); `outputs` (expected files, with `max_mb`); `exit_codes` (map to `completed` | `completed_partial` | `failed`); `defectdojo_scan_type`; `defectdojo_file`. Container-side mount targets are per tool because images differ (`/src` and `/out` by default; `/usr/src` for sonar-scanner; `/zap/wrk` for ZAP). Start with `semgrep` and `gitleaks`, filled from S7:
   - semgrep: image `semgrep/semgrep` (`-nonroot` variant, uid 1000), network none, tmpfs `/tmp` and the writable home path S7 found, command `semgrep scan --config /content/semgrep/rules --metrics=off --disable-version-check --json-output=/out/semgrep.json --sarif-output=/out/semgrep.sarif --timeout 30 --timeout-threshold 3 --max-memory 3000 --jobs 2 /src`; `optional_args`: `--exclude <pattern>` from `scanners/profiles/semgrep.yaml`; exit 0 → completed, ≥2 → failed; scan type `Semgrep JSON Report`, file `semgrep.json`, `max_mb` 90. Mount the resolved rules directory (`rules-<commit>`) at the fixed container path `/content/semgrep/rules`, not the symlink, so rule ids and finding titles do not change with the commit. Record both the `--exclude` patterns and Semgrep's built-in skips (`tests/`, `vendor/`, `node_modules/`, `build/`, `dist/`, `*.min.js`, files over 1 MB) in the job's "applied exclusions".
   - gitleaks: image `ghcr.io/gitleaks/gitleaks` (runs as root; S7 decides whether a non-root run works with `safe.directory`), network none, command for repositories `gitleaks git /src --redact --config /config/gitleaks.toml --ignore-gitleaks-allow --max-archive-depth 2 --report-format json --report-path /out/gitleaks.json --exit-code 2`, for zips and image filesystems `gitleaks dir /src ...` (same flags); exit 0 → completed, 2 → completed, 1 → failed, 126 → failed; scan type `Gitleaks Scan`, file `gitleaks.json`. `config/gitleaks.toml` starts with `[extend] useDefault = true`. Before the scan, the workspace step removes a `.gitleaksignore` found at the target root and records that it did so.
2. **Launcher.** `runner/launcher.py` using the docker SDK with `base_url=tcp://socket-proxy:2375`: at start, read `GET /volumes/securescan_data` → `Mountpoint` (or `SECURESCAN_DATA_HOST_ROOT`) and keep the host root; `create_container` with `HostConfig` built only from the catalogue entry (binds `<host root>/workspaces/<job>/<dir>` → target, `ReadonlyRootfs`, `CapDrop=ALL`, `SecurityOpt=no-new-privileges`, `NetworkMode`, `Memory`, `NanoCpus`, `PidsLimit`, `Tmpfs`, `User`), label `securescan.job_id`, `start`, stream `logs` into the job log file and an SSE channel (PostgreSQL `LISTEN/NOTIFY` on `job_<id>`; fall back to polling the log file if simpler, and record the choice), `wait` with the timeout from the catalogue (on timeout: `kill`, state `timed_out`), then `remove`. `socket-proxy` configured from `deploy/socket-proxy/args.env` (S2).
3. **Workspaces.** `runner/workspace.py`: per job `/var/lib/securescan/workspaces/<job_id>/{src,out,config}`, mode 0775, owned by uid 1000 (the worker's own uid; no `chown`); removed on completion; `workspace_gc` deletes orphans older than 24 h. Sources: `sources/zip.py` safe unpack (reject absolute paths and `..`, reject symlinks pointing outside, cap uncompressed size at 2 GB and ratio at 100:1, cap entry count); `sources/github.py` clone at a commit with the credential-helper pattern from S6, full history and all refs, `git remote remove origin`, record the commit SHA.
4. **Scan state machine.** `domain/scans.py`: `POST /api/v1/scans` creates a Scan and one ScanJob per tool in the profile, enqueues `scan_job` tasks in the same transaction, returns 202 with the scan id; supports `Idempotency-Key`. `jobs/scan_job.py`: `preparing` → `running` → `completed|completed_partial|failed|timed_out`; after exit, `runner/validate.py` checks each expected output exists, parses as JSON or XML (syntax only) and is under `max_mb`, else the job fails with a clear reason; raw outputs stored on the artifacts volume (`scans/<scan>/<job>/<file>`, SHA-256 recorded as Artifact rows); a SyncOutbox row is written (consumed in M4). Procrastinate `RetryStrategy(max_attempts=2)` applies only to launcher and Docker exceptions, never to tool exit codes. Locks: `queueing_lock` per (application, version, tool) so a repeated trigger collapses; `lock` `tool:<name>:<slot>` with `slot = job_id mod max_parallel` enforcing the per-tool cap. `maintenance.stalled_jobs` re-queues or fails jobs whose worker heartbeat stopped, after checking for a live container by label.
5. **Live progress.** `GET /api/v1/scans/{id}/events` as server-sent events (state changes and log lines); `POST /api/v1/scans/{id}/cancel` stops the container.
6. **Profiles.** `ScanProfile` rows seeded from `scanners/profiles/*.yaml` by `migrate` (`code-standard` with semgrep + gitleaks for now; extended in M8); `GET /api/v1/profiles`, `POST /api/v1/profiles` (Admin) with YAML validation.

**Acceptance**

- [ ] `POST /api/v1/scans` for a zip of `js-planted` with profile `code-standard` runs two containers (visible briefly in `docker ps`), both end `completed`, and `semgrep.json` and `gitleaks.json` exist under the artifacts volume with Artifact rows and non-empty content; the expected findings from `expected-findings.yaml` appear in the raw files.
- [ ] The same for a GitHub repository (test App from S6) at a given commit; `.git/config` in the workspace has no remote.
- [ ] A scan of a zip containing `../evil` is rejected with a problem detail; a 3 GB zip is rejected; a job whose output file is missing or malformed ends `failed` with the reason in the job record.
- [ ] `GET /api/v1/scans/{id}/events` streams log lines while the scan runs; cancel stops it; the container is removed.
- [ ] Two scans of the same application and tool started within a second produce one job; a third tool configured with `max_parallel: 1` never runs twice at once (check with `docker ps` during a test with three queued scans).
- [ ] Killing the worker mid-scan and restarting it leads to the job being re-queued or failed within 5 minutes, never left `running` forever.
- [ ] `docker inspect` of a scanner container shows no network, read-only rootfs, dropped capabilities, the uid from the catalogue and the job label.

**Tests:** unit tests for catalogue validation (placeholders, `optional_args` allowlist, path containment), command rendering, zip guards, exit-code mapping, output validation; integration tests running real Semgrep and Gitleaks against the planted apps. **Risks:** host-path mapping on Docker Desktop (verify the Mountpoint is usable as a bind source there; S2 covers it); SSE through nginx. **Size:** L.

### M4 — DefectDojo bundle, import, history, accounts (L)

**Goal:** every completed job is imported into the bundled DefectDojo, findings land in SecureScan's history, counts and verdicts appear, history is queryable with CSV export, and Admins/Analysts get DefectDojo accounts.

**Tasks**

1. **Compose include.** `deploy/compose.defectdojo.yaml`: top-level `include` of the vendored `deploy/defectdojo/upstream/docker-compose.yml` (DefectDojo 3.4.0, version noted in a header comment) plus `deploy/defectdojo/override.yaml` in the same `path` list. The override: `postgres: {profiles: ["disabled"]}` (the service stays defined but never starts); on `initializer`: `depends_on: !reset {}` then `depends_on: {db: {condition: service_healthy}}`; on `nginx`: `ports: !reset []`; on `uwsgi`, `celeryworker`, `celerybeat` and `initializer`: `DD_DATABASE_URL=postgresql://defectdojo:${DD_DB_PASSWORD}@db:5432/defectdojo?sslmode=verify-full&sslrootcert=/run/secrets/tls_ca`, `DD_DATABASE_HOST=db`, `DD_DATABASE_PORT=5432`, `DD_SECRET_KEY_FILE`, `DD_CREDENTIAL_AES_256_KEY_FILE`, `DD_SITE_URL=https://dojo.<host>`, `DD_ALLOWED_HOSTS`, `DD_CSRF_TRUSTED_ORIGINS`, `DD_OS_MESSAGE_ENABLED=false`, `DD_HASHCODE_FIELDS_PER_SCANNER` (JSON from S1), `DD_DEDUPLICATION_ASYNC_WAIT_TIMEOUT=120`, `DD_SCAN_FILE_MAX_SIZE=100`; on `initializer` also `DD_ADMIN_PASSWORD_FILE`; `DD_IMAGE_REGISTRY=docker.io`, `DJANGO_VERSION=3.4.0`, `NGINX_VERSION=3.4.0` in `deploy/.env`; all DefectDojo services on the `backend` network; keep the upstream volume name `defectdojo_media` (no `dd_media`). Check for service-name conflicts (ours are `gateway`, `api`, `worker`, `db`, `socket-proxy`; DefectDojo's are `nginx`, `uwsgi`, `celerybeat`, `celeryworker`, `initializer`, `valkey`, `postgres`).
2. **dojo-init.** `securescan dojo-init` (one-shot, `depends_on` DefectDojo `uwsgi` healthy): waits for `GET /api/v2/` to answer; admin token via `api-token-auth`; creates `securescan-sync` (staff) and `securescan-accounts` (superuser) if missing, takes their tokens via `api-token-auth`, stores them as `Credential(kind=defectdojo_token)` and `Credential(kind=defectdojo_admin_token)`; enables deduplication; creates the two product types; idempotent; logs what it changed; never stores the `admin` token.
3. **Client.** `integrations/defectdojo/client.py` (httpx, `Authorization: Token ...`, retries with backoff on 5xx and connection errors, timeouts): `reimport_scan(...)` with `auto_create_context=true`, `deduplication_on_engagement=true`, `close_old_findings=true`, `deduplication_execution_mode=async_wait`, `minimum_severity=Info`, `version`, `commit_hash`, `branch_tag`, `tags`; `list_findings(test_id, include_inactive)` paginated with `limit=200`; `get_finding(id)`; `create_user`, `patch_user`, `get_users` (accounts token only); `system_settings`, `product_types`.
4. **Import task.** `jobs/import_job.py` consumes SyncOutbox rows: upload, record `dd_test_id`, if `deduplication_complete` take `statistics.after` else schedule a re-read in 2 minutes; set job `import_state=imported`; on failure increment attempts, exponential backoff (1, 5, 15, 60 minutes, then every 6 hours up to 7 days), then `dead_letter`. `GET /api/v1/integrations/defectdojo` (status: reachable, version, last import, queue depth, dead letters), `GET /api/v1/integrations/defectdojo/outbox` and `POST .../outbox/{id}/replay` (Admin).
5. **History.** After import, `domain/history.py` reads the Test's findings (all, including inactive) and appends `FindingHistory` rows (one per finding per job) with state at scan time; `history_state_refresh` nightly updates `state_now` for every distinct DefectDojo finding id in history (batched by product, or by `id__in` if S1 found it), with no time window. Counts per severity (active, not duplicate, not false positive, not out of scope, not risk accepted) stored on ScanJob and rolled up to Scan and Application (`cached_counts`).
6. **Verdict.** `domain/policy.py`: default policy Fail on any Critical or more than 5 High; Conditional with 1–5 High; Pass otherwise; `pending` until all jobs imported. `GET/POST /api/v1/policies` (Admin), policies by data classification.
7. **Accounts.** `domain/accounts.py` (uses the accounts token): on first sign-in create a DefectDojo user (`username` = Entra UPN local part, `is_superuser` for Admin, `is_staff` for Analyst, random 20-char password), store the DefectDojo user id on `User`, and return the initial password once through `GET /api/v1/me/defectdojo-account` (shown by the portal once; afterwards only `POST /api/v1/me/defectdojo-account/reset` which sets a new random password through `PATCH /api/v2/users/{id}/`). If S1 found `force_password_reset` settable, set it. `account_expiry` disables (`is_active=false`) DefectDojo users whose SecureScan user has not signed in for 90 days; Admin endpoints `GET /api/v1/admin/defectdojo-accounts`, `POST .../{id}/disable|enable`. A metric and audit event fire when DefectDojo's `admin` user `last_login` changes (break-glass use), checked nightly through the accounts token.
8. **Gateway.** Enable the DefectDojo host: `auth_request` to `/api/v1/auth/check`, then `proxy_pass http://nginx:8080`.
9. **Results and summary APIs.** `GET /api/v1/scans/{id}/results` (counts by severity, import state, verdict, DefectDojo link `https://dojo.<host>/test/<id>`), `GET /api/v1/applications/{id}/results`, `GET /api/v1/summary` (running and queued scans, latest results, open-finding counts by severity) for the Home page.
10. **History API.** `GET /api/v1/history/scans`, `GET /api/v1/history/findings` (cursor-paged; filters: application, vendor, internal/vendor, source, tool, severity, CWE, triage state then/now, date range, started by), `GET /api/v1/history/findings.csv` with the same filters, streaming the whole filtered result through `security/csv_safe.py`; every export is audited.

**Acceptance**

- [ ] `python scripts/dev.py up` starts DefectDojo with its database in the shared `db` container (`\l` shows tables in `defectdojo`); the upstream `postgres` service is not running; `dojo-init` logs show the two users, deduplication and product types created; running it again changes nothing.
- [ ] A Semgrep + Gitleaks scan of `js-planted` ends with both jobs `imported`; DefectDojo shows Organization `Internal Applications`, Asset `js-planted`, Engagement, two Tests; `FindingHistory` rows match the DefectDojo finding count; counts and verdict appear in `GET /scans/{id}/results`; `GET /api/v1/summary` reflects them.
- [ ] Re-running the same scan creates no new findings in DefectDojo (deduplication on) and closes none; removing a planted issue and re-scanning closes exactly that finding and `state_now` updates after the nightly task is run by hand.
- [ ] Stopping DefectDojo's `uwsgi`, running a scan, and starting it again leads to a successful delayed import; `outbox` shows the attempts.
- [ ] `GET /api/v1/history/findings.csv?severity=High` downloads the full filtered set (test with 10 000 seeded rows), and cells starting with `=`, `+`, `-`, `@` carry the `'` prefix.
- [ ] Signing in as a new Analyst creates a DefectDojo staff user; `https://dojo.securescan.localtest.me:8443/` without a SecureScan session redirects to the portal login; with a session it shows DefectDojo's login page; the provisioned credentials work.

**Tests:** contract tests for every fixture report; unit tests for policy, backoff, history filters, CSV; integration tests for history append, state refresh and account provisioning. **Risks:** `include` override semantics (`!reset`), DefectDojo health timing, `deduplication_complete=false` paths. **Size:** L.

### M5 — Reports and templates (M/L)

**Goal:** every completed scan produces a report automatically, readable in the portal as HTML and downloadable as a SonaComstar-branded, watermarked PDF; admins can download the default template and upload custom ones.

**Tasks**

1. **Mappings and snapshot.** `reports/mappings/owasp-top10-2021.yaml` and `cwe-top25-2025.yaml` (CWE → category; cite the source URL and version inside each file) loaded by `domain/mappings.py`. `reports/snapshot.py`: Pydantic model with header (application, version, commit or image digest, scan date, tools and versions, image digests, content versions, template version, mapping versions, review state), summary (verdict, counts by severity, by tool, by OWASP Top 10 category and by CWE Top 25 presence, delta vs previous report), findings (from DefectDojo: title, severity, CWE with its OWASP and Top-25 tags, CVE, component, file and line or URL, description, mitigation, triage state), code quality (SonarQube quality gate and measures, filled from M8), components (SBOM component count and artifact link, from M8), coverage (tools run, skipped, why), known limits (the fixed text from the design's "Known limits to state in every report"). Stored as JSON artifact with SHA-256 on the Report row.
2. **Renderer.** `reports/renderer.py`: `jinja2.sandbox.SandboxedEnvironment` with `autoescape=True`, template loaded from the template's directory only; CSS inlined into a `<style>` block and images converted to `data:` URIs before rendering, so one HTML string serves both the portal (strict CSP) and WeasyPrint; WeasyPrint `HTML(string=html, base_url=template_dir, url_fetcher=restricted_fetcher)` where the fetcher allows only `data:` and files inside the template directory. Output: HTML and PDF (`write_pdf`).
3. **Default template** `reports/templates/default-sonacomstar/`: `template.html`, `style.css`, `brand/wordmark.svg` (text wordmark "SonaComstar"; a `logo.svg` placed in `brand/` later replaces it through one CSS rule), cover page, black-and-white layout, severity shown by label and weight, page numbers, the sections above including a findings-by-category bar chart as inline SVG and the "Known limits" block. `frontend/src/brand/` uses the same wordmark file (copied at build).
4. **Report job.** `jobs/report_job.py` runs after all jobs of a scan reach `imported` (or after a timeout with partial coverage noted): builds the snapshot, renders HTML and PDF, stores both as artifacts, creates the Report row (`review_state=automatic`). Endpoints: `POST /api/v1/reports` (regenerate for a scan/version with a chosen template), `GET /api/v1/reports/{id}`, `GET /api/v1/reports/{id}/html` (served with `Content-Security-Policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'` and `X-Frame-Options: SAMEORIGIN`), `GET /api/v1/reports/{id}/pdf` (stamps the stored PDF at download time with "Downloaded by <name> on <UTC time>" using pypdf; the unstamped artifact stays the record; audited), `POST /api/v1/reports/{id}/review` (Analyst: confirm or override verdict with reason, optional `conditions: [{finding_hash, deadline}]`; sets `review_state=reviewed`).
5. **Templates API** (Admin): `GET /api/v1/templates`, `GET /api/v1/templates/default/download` (zip of the default template), `POST /api/v1/templates` (upload zip; validation: only `.html`, `.css`, `.svg`, `.png`, `.ttf`, `.otf` files, size cap 20 MB, test-render with a sample snapshot in the sandbox, reject on error), `POST /api/v1/templates/{id}/preview` (returns HTML of the sample render), set default per report kind.
6. **CSV finding list** per report: `GET /api/v1/reports/{id}/findings.csv` with `security/csv_safe.py` escaping.

**Acceptance**

- [ ] After a scan completes and imports, a Report row exists within a minute; `GET .../html` renders in a browser with the wordmark, the OWASP Top 10 breakdown and the Known limits block; `GET .../pdf` downloads a PDF whose first page shows the wordmark and verdict and whose text contains "Downloaded by".
- [ ] A finding title containing `<script>alert(1)</script>` appears escaped in HTML and PDF.
- [ ] Uploading a template that uses `{{ cycler.__init__.__globals__ }}` is rejected; a benign custom template renders and can be set as default.
- [ ] Marking a report reviewed with two conditions records the analyst, verdict decision and conditions in the audit log and in the regenerated report.

**Tests:** unit tests for mappings, snapshot building, CSV escaping, template validation, watermark text extraction; a golden-file test that renders the sample snapshot to HTML and compares. **Risks:** PDF size with many findings (paginate findings, cap evidence length). **Size:** M/L.

### M6 — Portal (L)

**Goal:** the React portal with Login, Home, SAST scan, DAST scan (targets only; scans wired in M9), Historical data, Settings (the pages whose endpoints exist), scan detail and report view, in the black-and-white theme.

**Tasks**

1. **Theme and shell.** `styles/theme.css` tokens (black, white, four greys; severity colours used only on badges with text); layout with header (wordmark, page links, user name and role, sign out); route guard reading `GET /api/v1/me`; Admin-only routes return to Home for Analysts.
2. **Login** `routes/login.tsx`: wordmark, product name, one "Sign in with Microsoft" button linking to `/api/v1/auth/login`. Nothing else.
3. **Home** `routes/home.tsx`: `GET /api/v1/summary` tiles and an "Open DefectDojo" button to `https://dojo.<host>/login`. If the user has never seen their DefectDojo credentials, a one-time panel shows them (`GET /api/v1/me/defectdojo-account`) with a "reset" action.
4. **SAST scan** `routes/sast.tsx`: form with source selector (connected GitHub repository picker from `GET /api/v1/integrations/github/repositories` once M7 exists, hidden until then; GitHub URL + credential picker; zip upload with chunking and progress; Docker image reference or tar upload), application (existing or new), version label, internal/vendor toggle with vendor fields, tools checklist (applicable tools pre-ticked from the profile), Start. Below: table of running and recent code scans with state, counts, verdict, links to detail and report.
5. **DAST scan** `routes/dast.tsx`: targets table (register URL, environment tag, scope, login profile for UAT only), scan form (target, mode options filtered by environment tag: production shows only baseline; UAT shows baseline, full, API, Nuclei; the Start button is disabled until M9 ships the DAST profiles), vendor authorization fields when the target's application is a vendor SaaS; running and recent DAST scans.
6. **Historical data** `routes/history.tsx`: two tabs (scans, findings); filter bar (application, vendor, internal/vendor, source, tool, severity, CWE, state, date range, started by); server-side pagination; URL holds the filter state; "Export CSV" calls `GET /api/v1/history/findings.csv?...` and downloads; row click opens scan detail or the report.
7. **Scan detail** `routes/scan-detail.tsx`: per-tool status, live log (SSE hook), tool and content versions, counts by severity, verdict, import state, report link, DefectDojo link, cancel button.
8. **Report view** `routes/report.tsx`: sandboxed `<iframe sandbox="" src="/api/v1/reports/{id}/html">`, PDF download, review controls for Analysts.
9. **Settings** `routes/settings/*` in M6: report templates (download default, upload, preview, set default), policies, profiles, DefectDojo status and import queue (replay), DefectDojo accounts (disable/enable), audit log viewer, system health (`GET /api/v1/admin/health`). Added in M7: GitHub connection, automatic scan rules and schedules. Added in M8: scanner health and image-update approvals, content versions.
10. **Generated client.** `npm run gen:api` runs `openapi-typescript` against `backend` (dev server or exported JSON) into `src/api/schema.d.ts`; hooks in `src/api/hooks/`.
11. **E2E.** Playwright flows for M6 (1.5); run against the `dev` stack with the mock provider.

**Acceptance**

- [ ] Login page shows only the wordmark, name and one button; the theme is monochrome; axe reports no serious violations on any page.
- [ ] As Analyst: start a zip scan from the SAST page, watch the log live, open the report, download the PDF, query history and export CSV. Settings is not reachable.
- [ ] As Admin: the M6 Settings pages load and work (template upload and preview, policy edit, outbox replay, account disable, audit log paging).
- [ ] The DAST page hides full/API/Nuclei for a production target and the API refuses them if forced with `curl`.

**Tests:** Vitest for components and hooks; Playwright e2e; API client regenerated in CI and diff-checked. **Risks:** SSE through the dev proxy; iframe sandbox and CSP. **Size:** L.

### M7 — GitHub integration (M/L)

**Goal:** the corporate GitHub App is configured in Settings, repositories are discovered nightly, changes are polled every 10 minutes, weekly scans run, and vendor repositories are reachable by deploy key or vendor token.

**Tasks**

1. **Connection.** `GitHubConnection` row managed by `GET/PUT /api/v1/integrations/github` (Admin): app id, client id, installation id, API base URL (default `https://api.github.com`), git host, API version header (default `2026-03-10`), private key(s) uploaded and stored encrypted (support two keys). `POST /api/v1/integrations/github/test` mints a token, lists repositories, runs `git ls-remote` on one; returns problems in plain words. `POST /api/v1/integrations/github/sync` runs discovery now.
2. **Client.** `integrations/github/app.py`: JWT (RS256, `iat` −60 s, `exp` +9 min, `iss` client id); installation tokens per job narrowed to one repository and `contents: read`, held in memory only; `list_installation_repositories`; `get_branch_head(owner, repo, default_branch)`; rate-limit aware (serial requests, respect `Retry-After`, back off at `X-RateLimit-Remaining < 100`); token patterns scrubbed from logs.
3. **Egress for the worker's own calls.** GitHub API calls and clones go through the on-demand egress proxy: `jobs/egress_lifecycle.py` starts one squid container (`securescan-egress`, networks `egress` + `backend`) when any job or periodic task needs outbound access, refreshes its allowlist (`squid -k reconfigure`) from the union of active needs (github.com, api.github.com, codeload.github.com, and the updater hosts), and stops it after 5 idle minutes; the worker uses `HTTPS_PROXY=http://securescan-egress:3128` for these calls. Scanner DAST jobs use their own per-job proxy (M9).
4. **Discovery.** `jobs/github_discovery.py` nightly (and on `sync`): lists repositories; new ones become Applications (`type=internal`, `confirmed=false`, `automatic=false`) with a `github_repo` Target for the default branch; removed ones are flagged. Analysts confirm and toggle `automatic` in the SAST page's repository picker or Settings.
5. **Poller.** `jobs/github_poll.py` every 10 minutes for repositories with `automatic=true`: read default-branch head; if it differs from `RepositoryHead.last_scanned_sha`, enqueue a `code-standard` scan with trigger `change` under the `queueing_lock`; budget: at most N requests per run, N = min(repositories, 1200), spread over the interval; do not rely on conditional requests being free; status (last run, remaining rate limit) in Settings.
6. **Schedules.** `GET/POST/PATCH /api/v1/schedules` (Admin): repository sets with weekly full scans (default Sunday 02:00) and, from M9, DAST cron schedules per target with blackout windows; a periodic evaluator enqueues scans with trigger `weekly` or `schedule`.
7. **Vendor access.** `POST /api/v1/credentials/deploy-key` generates an ed25519 key pair for a `vendor_repo` target, stores the private key encrypted, returns the public key for the vendor to add as a read-only deploy key; `POST /api/v1/credentials/vendor-token` stores a vendor-issued token with its expiry; `sources/github.py` supports SSH clone with the deploy key (`GIT_SSH_COMMAND` with a temp key file, `StrictHostKeyChecking=yes` with GitHub's published host keys pinned in `deploy/known_hosts`) and HTTPS clone with a token through the credential helper. Expiry alerts 14 days ahead (M2 task). Credentials belong to one application version (assessment).

**Acceptance**

- [ ] Settings → GitHub test shows "token minted, N repositories, ls-remote ok"; the squid container appears during the test and disappears after 5 idle minutes.
- [ ] Discovery creates Applications for the installation's repositories; confirming one and enabling automatic scans causes a scan within 10 minutes of a push to its default branch; a second push during the scan does not queue a second scan.
- [ ] The weekly schedule enqueues scans for the automatic set.
- [ ] A vendor repository accessible by a generated deploy key is cloned and scanned; the private key never appears in logs or the workspace.
- [ ] `grep -r ghs_ /var/lib/securescan` in the worker finds nothing after a scan.

**Tests:** unit tests for JWT, token narrowing, head comparison, rate-limit backoff, key generation, schedule evaluation; integration test against the S6 test App. **Risks:** organisation IP allow lists; squid reconfigure races (serialise with a lock). **Size:** M/L.

### M8 — Remaining code scanners, SonarQube on demand, updaters (L)

**Goal:** Syft, Grype, Dependency-Check, SpotBugs with Find Security Bugs and SonarQube run in the `code-standard` profile; vulnerability databases and rules update automatically; Docker images can be scanned.

**Tasks**

1. **Image intake.** `sources/image.py`: for a registry reference, run `quay.io/skopeo/stable` in a container on the `dast`-style internal network with a per-job squid allowing only the registry host (`skopeo copy docker://<ref> docker-archive:/out/image.tar`, registry credentials passed as env for that container only); for an uploaded tar, use it directly. Extract the root filesystem for file-based tools: apply layers in order from the tar, honour whiteouts (`.wh.` files), skip device nodes and symlinks pointing outside; result under `src/rootfs`. Collect `*.jar`, `*.war`, `*.ear` paths for SpotBugs.
2. **Syft + Grype.** Catalogue entries: `syft` (`anchore/syft`, network none, tmpfs `/tmp` sized 4 GB for image scans, `syft scan dir:/src -o syft-json=/out/sbom.syft.json -o cyclonedx-json=/out/sbom.cdx.json`, or `docker-archive:/src/image.tar` for images; env `SYFT_CHECK_FOR_APP_UPDATE=false`); `grype` (`anchore/grype`, network none, `grype sbom:/out/sbom.syft.json -o json=/out/grype.json`, env `GRYPE_DB_CACHE_DIR=/content/grype-db`, `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_DB_VALIDATE_AGE=true`, `GRYPE_CHECK_FOR_APP_UPDATE=false`, read-only DB mount if S7 confirmed it, else read-write). The `syft-grype` tool runs the two in sequence as one job. Scan type `Anchore Grype`, file `grype.json`. SBOMs stored as artifacts and linked from reports. Updater: daily at 07:30 UTC (after Anchore's 06:00 build) `grype db update` container with egress to `grype.anchore.io`, writing to the `grype_db` volume (single writer); feed age recorded as `ContentVersion(feed=grype_db)`.
3. **Dependency-Check.** Catalogue entry: `owasp/dependency-check`, uid 1000, data volume `odc_data` at `/usr/share/dependency-check/data` (read-only for scans if S7 confirmed; `max_parallel: 1` regardless), `--scan /src --format XML --format HTML --out /out --project {project_key} --noupdate --disableVersionCheck --disableOssIndex --disableNodeAudit --disableYarnAudit --disablePnpmAudit --propertyfile /config/odc.properties`; the tool builder writes `nvd.api.key=<value>` (property name confirmed in S7) into `/config/odc.properties` (0600) only when an update job runs, and leaves it out for scans; `optional_args`: `--disableCentral` when the profile's `no_disclosure` flag is on (default on for vendor applications); egress proxy allowing only `search.maven.org` and `repo1.maven.org` otherwise. Exit codes: 0 → completed; 14 → completed_partial (import, flag partial); others → failed. Scan type `Dependency Check Scan`, file `dependency-check-report.xml`. Updater: daily `--updateonly --propertyfile /config/odc.properties --data /usr/share/dependency-check/data` with egress to `services.nvd.nist.gov`, `www.cisa.gov`, `raw.githubusercontent.com`, `dependency-check.github.io`; configurable `--nvdDatafeed` URL for the mirror fallback; block Dependency-Check scans until the first update succeeded.
4. **SpotBugs + Find Security Bugs.** `scanners/spotbugs/Dockerfile` from S7, built in CI and tagged `securescan/spotbugs-fsb:<spotbugs>-<fsb>`; pinned in `images.lock.yaml`; kept in the local registry only. Catalogue: network none, uid 1000, command `spotbugs -textui -pluginList /opt/findsecbugs/findsecbugs-plugin.jar -effort:max -low -xml:withMessages=/out/spotbugs.xml` with the discovered JAR and class-directory paths appended through `optional_args` (paths must resolve under `/src`; `-auxclasspath` for `lib/` jars when an app/lib split is visible); the job is skipped with coverage note "no compiled classes found" when nothing is discovered. No `-exitcode`; exit 0 → completed, non-zero → failed. Scan type `SpotBugs Scan`, file `spotbugs.xml`. `max_parallel: 1`.
5. **SonarQube on demand.** The server is a catalogue entry `sonarqube-server` (not a Compose service): image `sonarqube:<build>-community`, `container_name: sonarqube`, networks `sonarqube` + `backend`, env from secrets (`SONAR_JDBC_URL` with `ssl=true&sslmode=verify-full`, `SONAR_JDBC_USERNAME`, `SONAR_JDBC_PASSWORD`), volumes `sonarqube_data`, `sonarqube_extensions`, `sonarqube_logs`, ulimits, `stop_grace_period` 300 s. `jobs/sonarqube_lifecycle.py`: `ensure_running()` inspects `GET /containers/sonarqube/json`, creates the container from the catalogue when 404, starts it when stopped, waits for `GET /api/system/status == UP` (timeout 10 min, metric `sonarqube_start_seconds`); `sonarqube_idle_stop` every 5 minutes stops it when no SonarQube job ran for 15 minutes. `sonar-init` runs inside `ensure_running()` when the admin password is still `admin`: change it, create the service user and USER_TOKEN (stored encrypted), set Standard Experience mode (setting from S3). Catalogue entry `sonarqube` (scanner): image `sonarsource/sonar-scanner-cli`, network `sonarqube`, uid 1000, `max_parallel: 1`, env `SONAR_HOST_URL=http://sonarqube:9000`, `SONAR_TOKEN=<project analysis token minted per scan>`, `SONAR_USER_HOME=/tmp/.sonar` with a tmpfs at `/tmp`, source mounted at `/usr/src`, command `sonar-scanner -Dsonar.projectKey={project_key} -Dsonar.sources=. -Dsonar.scm.disabled=true -Dsonar.working.directory=/out/.scannerwork`, `optional_args`: `-Dsonar.java.binaries=<dir under /src>` when compiled classes exist (otherwise follow what S3 recorded: 26.8+ should only warn; if the pinned build fails, point it at an empty directory) and mark the job "analysed without bytecode, reduced precision". Post-step: read `/out/.scannerwork/report-task.txt`, poll `api/ce/task`, read quality gate and measures into the job, page `api/issues/search?components=<key>&ps=500` (split by `types` when over 10 000) into `/out/sonarqube-issues.zip`. Scan type `SonarQube Scan`, file `sonarqube-issues.zip`. Skip SonarQube for images without source and for C# sources (coverage note: "C# needs the .NET scanner and a build").
6. **Rules and templates updater (weekly).** `jobs/updaters.py`: clone `https://github.com/semgrep/semgrep-rules` at the commit pinned in `content/semgrep-rules.lock` (or the newest commit when `auto=true`), drop files whose `metadata.license` is not `Semgrep Rules License v1.0` or a company-approved licence, drop non-rule YAML (`stats/`, `.github/`), write to `/content/semgrep/rules-<commit>/`; fetch Nuclei templates with `nuclei -ut -ud /content/nuclei-templates-<date>` (without `-duc`; egress to github.com, release-download hosts and `api.pdtm.sh`); run the regression suite (`scanners/regression/`: planted apps for Semgrep, the DAST regression profile against Juice Shop for Nuclei), then switch the `/content/semgrep/rules` and `/content/nuclei-templates` symlinks and record `ContentVersion` rows; on failure keep the previous version and raise an alert metric.
7. **Profiles.** `code-standard` = semgrep, gitleaks, syft-grype, dependency-check, spotbugs (when classes exist), sonarqube (when source and no C#). Vendor applications default to `no_disclosure=true`.
8. **Scanner health and content.** `GET /api/v1/scanner-health` (Admin): per tool image digest and approved `ImageVersion`, last successful run, feed ages; `GET /api/v1/content-versions`; Prometheus gauges for feed age; alert thresholds from the design (7 days for databases, 30 days for rules and templates). Settings pages for both.
9. **Concurrency caps.** Set `max_parallel: 1` for `sonarqube`, `spotbugs`, `dependency-check`; 2 for `semgrep`; verify the lock behaviour from M3 task 4 with three queued scans.

**Acceptance**

- [ ] A scan of `java-planted` (with its committed `target/*.jar`) runs all six tools; each job reaches `imported`; DefectDojo shows six Tests; the report's components section shows the SBOM component count and its code-quality section shows the SonarQube quality gate; `expected-findings.yaml` titles appear in DefectDojo.
- [ ] A scan of a Docker image reference (a locally built image of `java-planted` pushed to a local registry, or a pinned public Java app image) runs Syft/Grype and SpotBugs on its JARs and Gitleaks/Semgrep/Dependency-Check on the extracted filesystem.
- [ ] `docker ps` shows the SonarQube container only during and 15 minutes after a SonarQube job; `docker compose up` alone is enough (no separate create step).
- [ ] With the Grype database older than 5 days (`GRYPE_DB_MAX_ALLOWED_BUILT_AGE=1h` in a test), the Grype job fails visibly with the stale-database message rather than reporting against old data.
- [ ] The weekly updater promotes a new rules version only after the regression suite passes; an injected failing rule is rejected; two Semgrep runs across a rules update produce identical finding titles for unchanged rules.
- [ ] `scanner-health` shows digests and feed ages; Prometheus exposes them; no scanner container's `docker inspect` shows the NVD key or any token in `Cmd` or `Env` except the single job credential the catalogue allows.

**Tests:** command-builder unit tests for each tool; rootfs extraction tests with whiteouts; integration tests per tool against planted apps; SonarQube lifecycle test with a shortened idle timeout. **Risks:** SonarQube start time on the dev machine; Dependency-Check first update duration; JAR discovery noise. **Size:** L.

### M9 — DAST: ZAP and Nuclei (L)

**Goal:** registered URL targets can be scanned: baseline on production, full, API and Nuclei on UAT, with login profiles on UAT only, through a per-job egress proxy.

**Tasks**

1. **Targets.** Target kind `url` with `environment` (`production` | `uat`), base URL, in-scope regexes, excluded paths, API spec (OpenAPI/GraphQL/SOAP file or URL), rate limit, blackout windows, DAST cron schedule, login profile reference (allowed only for `uat`), vendor authorization (document artifact, window, contact) required when the application is a vendor SaaS. Allowlist: a target must resolve to an address inside the Admin's allowlisted CIDRs in Settings or to an explicitly approved host.
2. **Networks and the per-job proxy.** Two static Compose networks: `dast` (`internal: true`) and `egress` (routable). For each DAST job the worker creates a squid container with `NetworkingConfig.EndpointsConfig` listing both networks and a generated `squid.conf` allowing only the target's host (and the API spec host); the scanner container joins `dast` only (`NetworkMode: dast`) and is configured to use the proxy (ZAP: `-config network.connection.httpProxy.enabled=true -config network.connection.httpProxy.host=<squid name> -config network.connection.httpProxy.port=3128`; Nuclei: `-proxy http://<squid name>:3128`); the proxy is removed with the job. DAST jobs run one at a time (Procrastinate `lock: dast`), so no job can use another job's proxy; this is stricter than the design's "one per target host" and is recorded as a decision. The socket-proxy allowlist is unchanged (no network create); re-run S2's deny test after this milestone.
3. **ZAP plans.** `scanners/profiles/zap-baseline-prod.yaml` (env: context with urls/includePaths/excludePaths; jobs: `spider` with `maxDuration: 5`, `postForm: false`, `processForm: false`; `passiveScan-wait`; `report` with `template: traditional-xml-plus`, `reportDir: /zap/wrk`, `reportFile: zap`; plus a `traditional-html` report for analysts), `zap-full-uat.yaml` (spider, `spiderAjax` or client spider with `numberOfBrowsers: 1`, `activeScan` with `maxScanDurationInMins`, `threadPerHost: 2`, `delayInMs` from the target's rate limit, reports), `zap-api-uat.yaml` (`openapi`/`graphql`/`soap` import job then `activeScan`). The tool builder renders the plan with the target's values into `/zap/wrk/plan.yaml`; login profiles (form, JSON, header via `ZAP_AUTH_HEADER*` env, browser-based with TOTP optional) are rendered into the context `authentication` and `users` sections, with a mandatory `verification` block; secrets as container env referenced by the plan. Catalogue: image `ghcr.io/zaproxy/zaproxy` by digest, uid 1000, `/zap/wrk` is the `out` mount, `/dev/shm` sized 1 GB for browser-based spiders, command `zap.sh -cmd -autorun /zap/wrk/plan.yaml -silent` plus the `-config` proxy options (verify the keys on the pinned image in the first integration run and record them), memory limit with an explicit heap through `JAVA_OPTS=-Xmx...` if the image honours it (verify; otherwise rely on the cgroup limit). Exit: 0 and 2 → completed, 1 → completed_partial (plan errors; import if the XML exists), anything else → failed. Scan type `ZAP Scan`, file `zap.xml`. The API refuses any plan containing `activeScan`, any API scan, and any login profile for a `production` target.
4. **Nuclei.** Templates on the content volume at `/content/nuclei-templates` (the weekly updater from M8 fills a dated directory and switches the symlink after the regression run; the resolved directory is mounted, not the symlink). Catalogue: image `projectdiscovery/nuclei`, command `nuclei -u {target_url} -duc -ni -dut -ud /content/nuclei-templates -etags dos,fuzz,bruteforce,local,txt-service,intrusive -severity low,medium,high,critical -rl 50 -c 10 -r /config/resolvers.txt -proxy http://<squid name>:3128 -rd Authorization,Cookie -json-export /out/nuclei.json`, env `NUCLEI_CONFIG_DIR=/content/nuclei-config`; UAT only. Scan type `Nuclei Scan`, file `nuclei.json`. Exit 0 → completed.
5. **Serialisation, schedules and safety.** `lock: dast` (one DAST job at a time); DAST cron schedules per target evaluated by the schedule task from M7 with blackout windows; a "Stop" button kills the container and the proxy; request-rate cap from the target applied to both tools.
6. **DAST profiles** seeded: `dast-baseline` (ZAP baseline), `dast-full` (ZAP full + Nuclei), `dast-api` (ZAP API + Nuclei). Enable the Start button on the DAST page and add the DAST Playwright flows.

**Acceptance**

- [ ] A production-tagged target accepts only `dast-baseline`; `curl` with `dast-full` or a login profile returns a 403 problem detail with the rule in plain words.
- [ ] Baseline against a local OWASP Juice Shop (from `fetch_fixtures`, run as a container on the `dast` network) completes, imports as `ZAP Scan`, and the ZAP log shows no POST requests to Juice Shop (form posting off).
- [ ] Full + Nuclei against the same Juice Shop tagged `uat` completes and imports both reports; the squid access log shows only Juice Shop's host; an attempt to reach `example.com` from inside the ZAP container is denied; a second DAST scan queued meanwhile waits.
- [ ] A UAT target with a form login profile shows ZAP's authentication statistics in the job output and fails the job when the logged-in regex never matches.
- [ ] Nuclei runs with `-duc -ni` and makes no connection except to the target (checked with the squid log).
- [ ] S2's deny test still passes.

**Tests:** unit tests for plan rendering and the environment rule; integration tests against Juice Shop; Playwright DAST flows. **Risks:** ZAP memory; `-config` proxy keys on the pinned image; browser-based auth needs `/dev/shm`. **Size:** L.

### M10 — Vendor assessment flow (M)

**Goal:** a scan marked as vendor produces an analyst-reviewed assessment report with a verdict, and a re-assessment shows the delta.

**Tasks**

1. Vendor fields on the SAST and DAST forms (vendor, product, version, deployable or SaaS); `Vendor` CRUD; applications of type `vendor` link to a vendor.
2. Report kind `vendor` with the design's vendor sections (cover and document control, executive summary, scope and coverage, methodology with the OWASP Top 10 and CWE Top 25 mapping, findings summary with the category chart, detailed findings, delta from last assessment, conditions with remediation deadlines, review) in the default template; verdict from the policy, confirmable or overridable with a reason by an Analyst; optional vendor copy without internal notes (`?copy=vendor`).
3. Delta: compare the two versions' DefectDojo findings by `hash_code` (fixed, remaining, new) in `domain/vendors.py`.
4. Hosting rule in the API: SaaS vendor targets are `production` unless the vendor authorizes a UAT instance; DAST on a vendor target requires the authorization record.

**Acceptance**

- [ ] Two scans of two versions of `java-planted` (second with one issue fixed and one added) produce a vendor report whose delta lists exactly those changes and whose conditions section shows the deadlines entered at review.
- [ ] A DAST scan on a vendor SaaS target without an authorization record is refused.

**Tests:** unit tests for delta and hosting rule; e2e flow. **Size:** M.

### M11 — Hardening, operations, handover (L)

**Goal:** the system is safe to run unattended for years by the security and IT team.

**Tasks**

1. **Container hardening** for the always-on set: read-only root filesystems with `tmpfs` where needed, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, non-root users, resource limits, health checks, `depends_on` conditions; `scripts/check_host.sh` verifies cgroup v2, kernel settings and Docker versions and refuses to start scans otherwise (also run by the worker at start).
2. **Regression suite** `scanners/regression/`: expected findings per planted app and per tool, plus optional Juice Shop/WebGoat runs; `python scripts/dev.py test regression` runs it; used by the updaters (M8) and by the monthly image-update proposals.
3. **Image updates.** `jobs/image_updates.py` monthly: resolve the current digest for every image tag in `images.lock.yaml` (registry manifest requests through the egress proxy), run the regression suite against each candidate, and store proposals as `ImageVersion` rows shown in Settings; an Admin approves (audited), which sets `active=true`; `runner/catalogue.py` overlays active rows at load, `dev.py pull-images` pulls them, and the lock file is updated in the next release commit. SonarQube follows the December-release rule across year boundaries (a candidate from a later calendar year is offered only when the current version is the earlier year's December build).
4. **Backups.** `scripts/backup.sh`: `pg_dump` of the three databases (custom format) plus `tar` of `artifacts`, `defectdojo_media`, `securescan_data` metadata and `content` manifests, encrypted with `age` using a key from `deploy/secrets/`, copied off the machine (rsync/scp target from `.env`); scheduled by cron on the host (documented), with a metric for last successful backup. `scripts/restore.sh` restores onto a fresh machine; `docs/runbooks/restore.md` is the drill script.
5. **Metrics and alerts** from the design's observability table, exposed on `/metrics`, plus the break-glass alert (DefectDojo `admin` login, SonarQube admin token use); an example Prometheus alert rules file in `deploy/monitoring/alerts.yaml`.
6. **Runbooks** in `docs/runbooks/`: stuck scan or orphaned container; DefectDojo unreachable or rejecting imports; content update failed and rollback; SecureScan release upgrade; DefectDojo release upgrade (contract tests first); SonarQube upgrade (December rule, backup first); full restore; credential and master-key rotation; GitHub App key rotation; approving a scanner image digest.
7. **Install guide** `docs/install.md` for the Linux machine: prerequisites, DNS and certificates, Entra app registration (from S4), GitHub App registration (from S6), secrets, `pull-images`, first start, smoke test, backups, upgrade windows.
8. **Security review**: tick `docs/security-checklist.md` (section 5.1), run the regression suite, scan SecureScan's own images with Grype (SecureScan is the first registered application), review the audit log coverage, run Playwright with axe.
9. **Performance check**: `scripts/seed_history.py` seeds 300 applications and five years of synthetic history; confirm history queries and CSV export stay under the design's targets; add indexes if not.
10. **Handover**: walk through an upgrade and a restore with the user; update `docs/progress.md` and `README.md`; tag `v1.0.0`.

**Acceptance**

- [ ] `docker inspect` of every always-on container shows read-only rootfs (except `db` and DefectDojo's where upstream forbids), dropped capabilities, no-new-privileges.
- [ ] `scripts/backup.sh` produces an encrypted archive; `scripts/restore.sh` on a clean Compose project restores it and a previous report opens.
- [ ] Regression suite passes; a deliberately broken rule file fails it; an image-update proposal appears and, once approved, the next scan uses the new digest.
- [ ] Every runbook exists and was executed at least once on the dev machine.
- [ ] Section 6 traceability has a milestone for every requirement and each is ticked in `docs/progress.md`.

**Size:** L.

### M12 — Later: build-based analysis (not part of version 1)

Only when the user asks. Maven/Gradle builds in `maven`/`gradle` official images and .NET builds in `mcr.microsoft.com/dotnet/sdk` with egress limited to Maven Central and NuGet, to run Find Security Bugs on built source, the .NET SDK security analyzers (`CA2100`, `CA3001`–`CA3012`, `CA5350`–`CA5405` enabled through `.globalconfig`, `dotnet build -p:ErrorLog=out.sarif,version=2.1`, imported as `SARIF`) with Puma Scan Community Edition, and SonarQube with compiled classes or the .NET scanner. Strictest sandbox: no Docker socket, non-root, hard time limits.

---

## 5. Cross-cutting

### 5.1 Security checklist (keep as `docs/security-checklist.md`, tick at M11)

- Entra ID only; assignment required on the app registration; roles from the `roles` claim; sessions server-side; cookies `HttpOnly; Secure; SameSite=Lax`; CSRF on every state-changing request; per-session rate limit at the gateway.
- DefectDojo reachable only through the gateway with `auth_request`; provisioned accounts; 90-day inactivity disable; break-glass admin credentials sealed in `deploy/secrets/` and their use alerted.
- Scanner containers: fixed catalogue, no network for code scanners, egress proxy for the rest, read-only rootfs, dropped capabilities, no-new-privileges, uid from the catalogue, PID and memory limits, hard timeouts, workspace removed afterwards.
- Socket proxy allowlist exactly as S2 (re-tested after M9); worker is the only client; bind mounts restricted to the data volume's host path; no image pulls through the proxy.
- Uploads validated (zip guards, size caps); image layers extracted safely; scanner outputs validated for shape and size.
- Secrets encrypted at rest; token patterns scrubbed from logs; Gitleaks `--redact`; ZAP/Nuclei header redaction; NVD key via properties file; CSV escaping; PDF watermark on download.
- TLS on the gateway and to PostgreSQL (`sslmode=verify-full` from SecureScan, DefectDojo and SonarQube).
- Audit log covers sign-ins, scan starts, target changes, credential use, verdict overrides, report downloads, exports, Settings changes, account provisioning and image approvals; every event also goes to the log stream for the SIEM.
- Dependencies scanned in CI (Grype on the built images); SBOM produced for SecureScan's own images.

### 5.2 Test strategy

Unit (fast, everywhere) → integration (compose `test` profile: DB + DefectDojo; real scanner images against planted apps) → contract (fixture reports into DefectDojo; run before any DefectDojo or scanner upgrade) → e2e (Playwright on the `dev` stack) → regression (planted apps and optional Juice Shop/WebGoat; gate for content and image updates). Fixture reports in `backend/tests/fixtures/reports/` are refreshed whenever a scanner image is bumped.

### 5.3 Observability

JSON logs with `scan_id`/`job_id`; Prometheus metrics (queue depth, oldest queued age, job duration and failure rate per tool, import lag and dead letters, GitHub poll status, SonarQube start time, egress proxy uptime, disk use, feed age, backup age, break-glass use, API latency); health endpoints; the Settings → System health page reads the same values through `GET /api/v1/admin/health`.

### 5.4 Documentation to produce

`README.md`, `docs/install.md`, `docs/runbooks/*`, `docs/decisions.md`, `docs/licences.md`, `docs/spikes/*`, `docs/security-checklist.md`, `deploy/README.md`, `content/README.md`, `scanners/README.md` (how to add or bump a tool: catalogue entry, fixture report, regression expectations, lock entry).

---

## 6. Traceability

| Requirement (design) | Milestone |
| --- | --- |
| FR-01 Register applications with criticality, classification, tags | M2 |
| FR-02 Versions and targets (GitHub repo, zip, image, URL) | M2, M3, M8, M9 |
| FR-03 Code scans with Semgrep, SonarQube, Find Security Bugs, Gitleaks, Syft, Grype, Dependency-Check | M3, M8 |
| FR-04 DAST: baseline on production; full, API, Nuclei on UAT | M9 |
| FR-05 Authenticated DAST on UAT only | M9 |
| FR-06 Scan profiles | M3 (API and seeding), M8, M9 |
| FR-07 Start scans on demand and follow live | M3, M6 |
| FR-08 GitHub App: discovery, change and weekly scans | M7 |
| FR-09 Vendor repositories by deploy key or token, zip fallback | M7, M3 |
| FR-10 SonarQube on demand, stopped when idle | M8 |
| FR-11 Automatic import into DefectDojo | M4 |
| FR-12 Re-import deduplication and closing | M4 |
| FR-13 Permanent history with state then and now | M4 |
| FR-14 History queries and CSV export | M4 task 10 (API), M6 (UI) |
| FR-15 Automatic report, HTML and PDF | M5 |
| FR-16 Default SonaComstar template downloadable; custom templates | M5 |
| FR-17 Vendor assessment with verdict and delta | M10 |
| FR-18 Verdict policy shown in reports | M4, M5 |
| FR-19 Entra ID sign-in with Admin and Analyst roles | M2 |
| FR-20 Open DefectDojo button | M6 (M4 for the gateway rule) |
| FR-21 Audit log | M2 (events, API, log stream) onwards |
| FR-22 Automatic updates behind a regression check | M8 (rules, templates, databases), M11 (images) |
| FR-23 Block DAST outside allowlist/authorization and beyond baseline outside UAT | M9 |
| FR-24 Automatic setup of DefectDojo and SonarQube | M4, M8 |
| FR-25 Secrets masked everywhere | M2 (logs), M3 (Gitleaks), M4 (history), M5 (reports), M8 (NVD key), M9 (ZAP/Nuclei) |
| FR-26 Scanner health | M8 |
| NFR Deployment: one `docker compose up` | M0, M4, M8 (SonarQube created by the worker) |
| NFR Footprint: only the always-on set permanent | M3, M7 (egress on demand), M8, M9 |
| NFR Portal performance | M11 (performance check) |
| NFR Scan throughput: 4 concurrent tool runs, heavy tools serialised | M3 task 4 (locks), M8 task 9 (caps) |
| NFR Resilience: restart loses no scan; DefectDojo outage delays imports | M3, M4 |
| NFR Security | M2, M11 |
| NFR Recoverability (24 h RPO, 4 h RTO, off-machine backups) | M11 |
| NFR Retention: everything kept | M4 (history), M3 (artifacts, no purge by default) |
| NFR Reproducibility: digests, content and template versions recorded | M3, M5, M8 |
| NFR Longevity: pinned versions, support windows, upgrade runbooks | M0, M11 |
| NFR Internet use: outbound only, allowlisted | M7, M8, M9 |
| NFR Browsers and WCAG 2.1 AA | M6 |
| Design: Scanner container contract and Phase 0 unknowns | M1 (S1, S2, S3, S7) |
| Design: OWASP Top 10 and CWE Top 25 mapping | M5, M10 |
| Design: Watermark on downloaded reports | M5 |
| Design: Upkeep calendar automation (daily/weekly/monthly tasks) | M2 (schedules), M8, M11 |

---

## 7. Configuration reference

### 7.1 SecureScan environment variables (prefix `SECURESCAN_`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql+psycopg://securescan@db:5432/securescan?sslmode=verify-full&sslrootcert=/run/secrets/tls_ca` | Main database (password from `DATABASE_PASSWORD_FILE`) |
| `PUBLIC_URL` | `https://securescan.localtest.me:8443` | Portal base URL |
| `DEFECTDOJO_URL` | `http://nginx:8080` | Internal DefectDojo URL |
| `DEFECTDOJO_PUBLIC_URL` | `https://dojo.securescan.localtest.me:8443` | Links in the portal |
| `COOKIE_DOMAIN` | `securescan.localtest.me` | Parent domain so DefectDojo's host sees the session |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET_FILE` | — | Entra ID (or the mock in dev) |
| `MASTER_KEY_FILE` | `/run/secrets/securescan_master_key` | AES-256-GCM key for stored secrets |
| `DOCKER_HOST` | `tcp://socket-proxy:2375` | Docker API through the proxy |
| `DATA_ROOT` | `/var/lib/securescan` | Where the worker sees the `securescan_data` volume |
| `DATA_HOST_ROOT` | (read from `GET /volumes/securescan_data`) | Daemon-side path of the same volume, used for bind sources |
| `ARTIFACTS_ROOT` | `/var/lib/securescan/artifacts` | Raw reports, uploads, SBOMs, PDFs |
| `WORKER_CONCURRENCY` | `4` | Procrastinate concurrency |
| `SONARQUBE_URL`, `SONARQUBE_CONTAINER` | `http://sonarqube:9000`, `sonarqube` | On-demand server |
| `SONARQUBE_IDLE_MINUTES` | `15` | Idle stop |
| `EGRESS_IDLE_MINUTES` | `5` | Idle stop of the shared egress proxy |
| `GITHUB_POLL_INTERVAL_MINUTES` | `10` | Poller |
| `EGRESS_ALLOW_HOSTS_UPDATERS` | list from 2.4 | Hosts the updaters may reach |
| `LOG_LEVEL` | `INFO` | |

### 7.2 Docker secrets (`deploy/secrets/`)

`securescan_master_key`, `securescan_db_password`, `defectdojo_db_password`, `sonarqube_db_password`, `postgres_superuser_password`, `dd_admin_password`, `dd_secret_key`, `dd_credential_aes_256_key`, `sonarqube_admin_password`, `oidc_client_secret`, `tls_cert`, `tls_key`, `tls_ca`, `pg_server_cert`, `pg_server_key`, `github_app_key_1` (and `_2`), `backup_age_key`. The NVD API key and vendor credentials are entered through the portal and stored encrypted in the database.

### 7.3 Volumes, networks, ports

Volumes (fixed names): `securescan_data` (`/var/lib/securescan` in the worker; bind sources for scanners come from its daemon-side Mountpoint), `pgdata` (`/var/lib/postgresql`), `artifacts`, `content` (rules, templates and Nuclei config as dated sub-directories with symlinks), `grype_db`, `odc_data`, `defectdojo_media` (upstream name), `sonarqube_data`, `sonarqube_extensions`, `sonarqube_logs`. Networks: `frontend`, `backend`, `docker`, `sonarqube` (internal), `dast` (internal), `egress` (routable; only squid containers join it). Ports: only the gateway publishes 443 (8443 in dev); everything else is internal.

---

## 8. Things Sonnet must not do, what needs the user, and recorded deviations

### 8.1 Must not

- Add CodeQL or any scanner outside the catalogue; add a paid or source-unavailable tool; change a scanner's image to `latest`.
- Parse scanner reports into findings in SecureScan, or write a "generic" import format for DefectDojo. DefectDojo parsers only.
- Add roles beyond Admin and Analyst, local passwords in SecureScan, or ownership scoping.
- Allow any active scan, API scan, Nuclei run or login profile against a `production` target.
- Mount the Docker socket into any container but `socket-proxy`; give scanner containers network beyond what the catalogue says; pass user input or a secret into a container command line.
- Store or print a secret value in a finding, log, report, CSV or git history.
- Replace DefectDojo, Procrastinate, PostgreSQL, FastAPI, React or Vite with something else; add Redis, Kubernetes, a message broker or a second machine.
- Use webhooks for GitHub in version 1; use CI tokens or API keys for scripts.
- Delete history rows, reports or raw artifacts automatically.
- Feed SonarQube output or scanned code to any external AI service.

### 8.2 Needs the user

- Entra ID tenant, app registration (client ID, secret or certificate), the two app roles assigned to the right groups.
- GitHub App registration on the corporate organisation (App ID, installation ID, private key).
- A free NVD API key (entered in Settings).
- The Linux machine, its DNS names and TLS certificate.
- The SonaComstar logo files, when available (drop into `frontend/src/brand/` and `reports/templates/default-sonacomstar/brand/`).
- Approval of any deviation recorded in `docs/decisions.md` that changes a design decision.

### 8.3 Deviations from the design that this plan already makes (record in `docs/decisions.md` at M0)

1. **Container paths per tool** instead of the design's fixed `/work/src`, `/work/out`, `/work/config`: images such as sonar-scanner (`/usr/src`) and ZAP (`/zap/wrk`) dictate their own paths. The design's `meta.json` is replaced by ScanJob columns (image digest, content versions).
2. **DAST jobs run one at a time** (global `lock: dast`), stricter than the design's "one active DAST job per target host", so that per-job egress proxies cannot be shared across jobs without creating networks at run time.
3. **The egress proxy for the worker's own GitHub and updater traffic is a shared on-demand squid** stopped after 5 idle minutes, while DAST jobs get their own proxy. The design describes one on-demand egress proxy; this is the same idea with two instances.
4. **SonarQube's server container is created by the worker from the catalogue**, not defined in Compose, so that one `docker compose up` still starts everything and the server never runs permanently.
5. **A second DefectDojo service account (`securescan-accounts`, superuser)** exists for account provisioning, because DefectDojo requires a superuser to create users; the import account stays a non-superuser staff user and the `admin` account stays break-glass.
6. **Scanner images are pre-pulled** (`dev.py pull-images`, install guide, after image approvals) and image pulls are not allowed through the socket proxy.
