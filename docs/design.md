<!-- Exported from the SecureScan design doc (https://claude.ai/code/artifact/86f92437-02c4-49ee-93e6-f442efd00079) on 2026-10-07, doc revision 165. The Claude Doc is the editable original; regenerate this file after design changes. Diagrams are not included in the export. -->

# SecureScan — On-Premises SAST & DAST Platform Design

Oct 5, 2026 · @Sam · Status: Refined on 6 October 2026, basis for the implementation plan

## Summary

SecureScan is a self-hosted platform that runs SAST and DAST scans on internal and vendor applications, keeps an inventory of every application and its vulnerabilities, and produces vendor assessment reports. It runs on one on-premises machine under Docker Compose. Users trigger and follow scans in a React portal, and every result loads into a bundled DefectDojo automatically. It is built once and then run for 5 to 10 years by the security and IT team.

The design rests on ten decisions, all settled in refinement on 5 and 6 October 2026.

| Decision | Choice | Reason |
| --- | --- | --- |
| Scan engines | Nine free tools, each started on demand: Semgrep, SonarQube Community Build, SpotBugs with Find Security Bugs, Gitleaks, Syft, Grype, OWASP Dependency-Check, ZAP and Nuclei. | Confirmed list. CodeQL is dropped because its terms forbid use on private or vendor code without a paid licence; Find Security Bugs takes its place for Java. |
| Isolation | Every tool run is a short-lived container with CPU, memory, time and network limits. | Vendor code is untrusted, and a crashing scanner must not take the platform down. |
| Always on | Only DefectDojo, PostgreSQL and the portal run permanently. Scanners and the SonarQube server start on demand and stop when idle. | Confirmed. A small footprint on one machine. |
| Findings | DefectDojo is the only triage tool. SecureScan keeps raw reports and an append-only history of every scan's findings for queries, CSV export and reports. | Confirmed: DefectDojo is the only triage, and all history must stay queryable. |
| DefectDojo setup | A new instance starts with SecureScan and is configured automatically at first deployment. | Confirmed. Nobody installs or connects DefectDojo by hand. Open-source DefectDojo has no single sign-on, so SecureScan provisions its local accounts behind the Entra gateway. |
| GitHub | A private, read-only GitHub App on GitHub Enterprise Cloud. Polling instead of webhooks. Nightly discovery, scans after changes and weekly. | Confirmed Enterprise Cloud. No inbound path from the internet is needed. |
| Backend | Python 3.14 and FastAPI, with one PostgreSQL 18 container holding the SecureScan, DefectDojo and SonarQube databases. | Confirmed: Python and PostgreSQL. One backup and one upgrade procedure. |
| Frontend | A React 19 single-page app: black-and-white theme, SonaComstar branding, Entra ID sign-in, five pages plus Settings. | Confirmed. Simple and basic by request. |
| Deployment | Docker Compose on a single on-premises machine. | Confirmed. One machine is simple enough for the security and IT team to run. |
| Updates | Rules, templates and vulnerability databases update over the internet on a schedule, behind a regression check. | Confirmed: egress is allowed. Stale rules are the main decay risk over a 5 to 10 year life. |

Tool facts, licences and versions were checked against each project's own documentation on 5 and 6 October 2026. Phase 0 tests them against the pinned releases.

## Goals, non-goals and assumptions

Version 1 delivers ten outcomes and deliberately leaves six things out.

### Goals

- Scan code from the corporate GitHub, from zip uploads and from Docker images with Semgrep, SonarQube, Find Security Bugs, Gitleaks, Syft, Grype and Dependency-Check.
- Scan running web applications and APIs with ZAP and Nuclei: baseline on production, full on UAT.
- Connect to GitHub Enterprise Cloud and scan repositories automatically after changes and weekly.
- Load every scan result into the bundled DefectDojo automatically, where security analysts triage.
- Produce a security report after every scan, readable in the portal and downloadable as a SonaComstar-branded PDF.
- Produce vendor assessment reports with a verdict.
- Keep every scan and finding permanently and let users query and export the history as CSV.
- Provide a small React portal with Entra ID sign-in: SAST scan, DAST scan, Historical data and a link to DefectDojo.
- Run on one on-premises machine, with only DefectDojo, PostgreSQL and the portal always on.
- Stay maintainable for 5 to 10 years by the security and IT team.

### Non-goals for version 1

- Writing custom static or dynamic analysis engines, or any tool-specific parsing of results.
- Triaging findings in SecureScan. DefectDojo does that.
- CodeQL or any other scanner that needs a paid licence.
- Ticketing, chat or CI-pipeline integrations. GitHub is reached through its API, not through pipelines.
- IAST, RASP, fuzzing, mobile binary analysis and manual penetration-test management.
- Kubernetes, multi-host or high-availability deployment.

### Assumptions to confirm

- The machine can reach github.com, Microsoft Entra and the scanner update hosts over HTTPS, directly or through the corporate proxy.
- An IT administrator can create one Entra app registration with two app roles and a GitHub App on the corporate organisation.
- Sizing basis: up to 300 applications, 100 scans a day and 4 concurrent tool runs.

## Users, roles and key use cases

Two roles use the platform, assigned as app roles in Microsoft Entra ID: Admin and Analyst. Both see everything; only Admins change Settings. There is no read-only or owner-scoped role, so anyone outside the two groups gets results as a PDF from an analyst.

| Role | Who | Can do |
| --- | --- | --- |
| Admin | Security tooling and IT team | Everything an Analyst can, plus Settings: GitHub connection, report templates, policies, scanner updates and the audit log. |
| Analyst | Security analysts | Start scans, register DAST targets and set their environment tags, read all history and reports, review vendor reports, open DefectDojo. |

### Key use cases

1. **Automatic repository scan.** A corporate GitHub repository is connected. Code scans run on a schedule or after a push, and the security report appears in the portal.
2. **On-demand code scan.** A user starts a scan of a repository, zip file or Docker image on the SAST scan page and downloads the PDF report.
3. **DAST scan.** A user scans a registered URL: baseline on production, full on UAT.
4. **Vendor assessment.** A user scans what the vendor supplied. An analyst triages in DefectDojo and issues the assessment report with a verdict.
5. **History query.** A user filters past scans and findings, for example every critical finding in vendor applications this year, and exports the result as CSV.
6. **Audit.** An admin reviews in the audit log who scanned what, when, and with which tool and rule versions.

## Requirements

The 26 functional requirements below carry IDs so the implementation plan can trace work items to them. Priorities are proposals.

### Functional

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-01 | Register internal and vendor applications with criticality, data classification and tags. | Must |
| FR-02 | Track versions per application and targets per version: GitHub repository, zip upload, Docker image, URL. | Must |
| FR-03 | Run code scans on a GitHub commit, a zip upload or a Docker image with Semgrep, SonarQube, Find Security Bugs, Gitleaks, Syft, Grype and Dependency-Check. | Must |
| FR-04 | Run DAST against a registered URL: ZAP baseline on production; ZAP full, API scans and Nuclei on UAT only. | Must |
| FR-05 | Support authenticated DAST with stored, encrypted login profiles, on UAT targets only. | Should |
| FR-06 | Define scan profiles that choose tools, rules, limits and the verdict policy. | Must |
| FR-07 | Start scans on demand from the SAST and DAST pages and follow them live. | Must |
| FR-08 | Connect to GitHub Enterprise Cloud through a GitHub App: discover repositories nightly, scan after changes and weekly. | Must |
| FR-09 | Reach vendor repositories by deploy key or vendor-issued token, with zip upload as fallback. | Must |
| FR-10 | Start the SonarQube server on demand and stop it when idle. | Must |
| FR-11 | Import every tool report into DefectDojo automatically, with no manual step. | Must |
| FR-12 | Use DefectDojo re-import to deduplicate findings and close those no longer detected. | Must |
| FR-13 | Keep every scan and its findings permanently as history, with the triage state at scan time and now. | Must |
| FR-14 | Query history by application, vendor, tool, severity, state and date, and export the result as CSV. | Must |
| FR-15 | Generate a security report automatically after each scan, readable in the portal and downloadable as PDF. | Must |
| FR-16 | Ship a SonaComstar-branded default template that admins can download, and accept custom templates. | Must |
| FR-17 | Run a vendor assessment: a scan marked as vendor, analyst review, verdict, and a delta report on re-assessment. | Must |
| FR-18 | Evaluate the verdict policy and show the result in every report. | Should |
| FR-19 | Sign in through Microsoft Entra ID only, with two Entra app roles: Admin and Analyst. | Must |
| FR-20 | Offer a home-page button to the DefectDojo login page for analysts and admins. | Must |
| FR-21 | Record every security-relevant action in an audit log. | Must |
| FR-22 | Update rules, templates and vulnerability databases automatically on a schedule, behind a regression check where logic changes. | Must |
| FR-23 | Block DAST on targets that are not allowlisted or authorized, and block anything beyond baseline outside UAT. | Must |
| FR-24 | Set up DefectDojo and SonarQube automatically at first deployment: accounts, tokens, product types and settings. | Must |
| FR-25 | Mask secret values in every finding, report and export. | Must |
| FR-26 | Show scanner health: image digests, content versions and vulnerability-database age. | Should |

### Non-functional

| Area | Proposed target |
| --- | --- |
| Deployment | One `docker compose up` on a prepared machine starts and configures everything, DefectDojo and SonarQube included. |
| Footprint | Only DefectDojo, PostgreSQL, the portal and the socket proxy run permanently. Everything else is on demand. |
| Portal performance | 95% of page loads under 2 seconds with 300 applications and five years of history. |
| Scan throughput | 4 concurrent tool runs on the recommended machine, with heavier tools serialised. |
| Resilience | A restart loses no scan. Interrupted jobs re-queue or fail with a clear reason. A DefectDojo outage delays imports and loses none. |
| Security | Entra ID sign-in, role checks on every request, TLS 1.2 or later everywhere, secrets encrypted at rest, audit log. |
| Recoverability | Recovery point 24 hours, recovery time 4 hours, from backups held off the machine. |
| Retention | History, reports and raw tool output are kept permanently by default. |
| Reproducibility | Every scan records image digests, content versions, profile version and template version. |
| Longevity | A 5 to 10 year life. Every component has a pinned version, a published support window and an upgrade runbook. |
| Internet use | Outbound only, to github.com, Microsoft Entra and an allowlist of update hosts. No code, finding or telemetry leaves the network. |
| Browsers | Current Chrome, Edge and Firefox. WCAG 2.1 AA. |

## Architecture overview

Only DefectDojo, PostgreSQL and the portal with its API and worker run all the time. Every scanner, the SonarQube server and the egress proxy exist only while a job needs them. One worker is the only component that starts containers and the only one that talks to DefectDojo.

&#91;embedded content: runtime architecture · 4 core services, 2 scanner groups, DefectDojo and 4 outside systems\]

The socket proxy and the DAST egress proxy are left out as boxes. Optional add-on scanners run in the same sandbox.

### How a scan flows

1. A user starts a scan in the portal, the GitHub poller sees a new commit, or the weekly schedule fires.
2. The API checks the role and the target's environment tag. It writes one Scan row and one ScanJob row per tool, and enqueues them in the same database transaction.
3. The worker claims a job and prepares a workspace: it clones the repository with a one-hour GitHub token, unpacks the zip, or saves the Docker image to a tarball.
4. The worker starts the scanner container through the socket proxy, with the limits from the profile. For a SonarQube job it first starts the SonarQube server if it is not running.
5. The scanner writes its native report to the output directory. The worker streams logs and stores the raw report, and for Syft the SBOM, in the artifact store.
6. The worker marks the job complete and writes an import request to the outbox table in the same transaction.
7. The import task uploads the raw report to DefectDojo, which parses it, deduplicates the findings and closes those no longer detected.
8. SecureScan reads the findings DefectDojo now holds for the scan, appends them to the history, stores the counts and evaluates the verdict policy.
9. The report task renders the security report. The portal shows progress live, then the report.

### Boundaries that matter

- **Gateway** is the only container with a published port. It serves the portal and DefectDojo on separate host names.
- **API** never touches Docker. It only reads and writes PostgreSQL and the artifact store.
- **Worker** reaches Docker only through the socket proxy, which permits container create, start, wait, logs, stop and remove, and nothing else.
- **Code scanners** get no network. **DAST containers** reach only their allowlisted target through the egress proxy.
- **SonarQube** runs on demand on an internal network. Only the worker and the SonarQube scanner reach it, and its web interface is not exposed.
- **Updater jobs and the GitHub poller** are the only paths to the internet, each to an allowlist of hosts.
- **DefectDojo** starts from the same Compose project and is configured by a one-shot setup container.

## Technology choices

Every choice below favours fewer containers and low upkeep over a 5 to 10 year life. The alternatives column records what was weighed and why it lost.

| Layer | Choice | Why | Alternative considered |
| --- | --- | --- | --- |
| Pattern SAST | Semgrep Community Edition with a pinned clone of its rules | Requested. Multi-language, fast, runs with no network, emits JSON that DefectDojo reads | CodeQL: not licensed for private or vendor code without GitHub Code Security. Opengrep: LGPL fork of Semgrep with in-file cross-function taint, kept as fallback engine. |
| Code quality and extra rules | SonarQube Community Build, started on demand | Requested. Quality gate, bugs, code smells and basic secrets for Java, JavaScript, TypeScript, Python and HTML | Commercial SonarQube editions: add taint analysis and C#, but paid |
| Secrets | Gitleaks | Requested. MIT, fast, scans git history | Betterleaks: its successor, pending a DefectDojo parser |
| Dependencies and SBOM | Syft and Grype, plus OWASP Dependency-Check | Requested. Grype covers images and every ecosystem from a pre-built database; Dependency-Check adds JAR and DLL coverage | Trivy: overlaps Grype. Dependency-Track: a second server and findings store. |
| DAST | ZAP driven by Automation Framework plans, plus Nuclei | Requested. ZAP's passive baseline and active full modes map to the production and UAT rule | Burp Suite Enterprise: commercial |
| Backend | Python 3.14, FastAPI, SQLAlchemy 2.1, psycopg 3, Alembic, Pydantic 2 | Every library declares Python 3.14 support, and 3.14 has security fixes until October 2030 | Go or NestJS: no ecosystem advantage here |
| Job queue | Procrastinate, a PostgreSQL-backed queue | Jobs enqueue in the same transaction as scan rows; locks serialise scans per target; periodic tasks; no broker | Celery with Redis: an extra container and redelivery tuning |
| Database | One PostgreSQL 18 container holding three databases: SecureScan, DefectDojo, SonarQube | The one major version all three products support today; one backup and one upgrade procedure | Three containers: independent upgrades, triple the upkeep |
| Artifact store | Local volume on the machine | Zero extra containers | Object storage service: no benefit on one machine |
| Frontend | React 19, TypeScript, Vite 8, TanStack Query, Radix primitives with Tailwind in the shadcn/ui pattern | Requested stack. Component code lives in the repository, which suits a monochrome theme and a long life | MUI: heavier, with its own visual style |
| Report rendering | Sandboxed Jinja2 templates rendered to PDF by WeasyPrint | Pure Python, BSD licence, no headless browser | Headless Chromium: better CSS, far larger image |
| Gateway | nginx | Serves the portal and proxies the API and DefectDojo in one small image | Traefik or Caddy |
| Authentication | Microsoft Entra ID over OIDC, app roles from the `roles` claim, server-side session cookie | Requested. No local user store | Tokens held in the browser |
| Scanner launch | Docker Engine API through `wollomatic/socket-proxy` | The only socket proxy that allows exactly the needed endpoints by method and path and restricts bind-mount sources | Tecnativa and linuxserver proxies: one coarse switch opens every write call. Docker-in-Docker: privileged. |
| Observability | JSON logs, Prometheus metrics | Fits common on-premises monitoring | Bundled ELK: too heavy to ship by default |
| Java taint analysis | SpotBugs with Find Security Bugs on compiled classes, in a self-built image | The closest free match to CodeQL's Java queries; works on JARs from vendor images without a build | Joern: a query platform without rule packs for these languages. Bearer: maintenance mode, C# paid. |

Licences were checked in October 2026. Semgrep's rules and SonarQube's analyzers are source-available and free for internal use. The CodeQL CLI is proprietary and excluded. Of the libraries, psycopg is LGPL-3.0 and the rest are MIT or BSD.

## Scan engine design

A Scan is one user request and a ScanJob is one tool run inside it. Adding a scanner means one container image, one profile entry and the name of its DefectDojo parser.

### Scanner catalogue

Nine tools are in version 1. All are free for internal use on the company's and vendors' code, and all but one start from their publishers' images. CodeQL is out: its terms forbid use on private or vendor code without a paid GitHub Code Security licence, which the company does not hold. Its replacement is described below. Facts were checked against each project's own documentation, licence text and image registry in October 2026.

| Tool | Finds | Image, pinned by digest | Licence | DefectDojo scan type |
| --- | --- | --- | --- | --- |
| Semgrep Community Edition | Insecure code patterns and single-function taint flaws in Java, C#, JavaScript, TypeScript, Python and HTML | `semgrep/semgrep` | Engine LGPL-2.1. Semgrep's rules: Semgrep Rules License, free for internal business use, not open source | Semgrep JSON Report |
| SonarQube Community Build | Bugs, vulnerabilities, code smells, basic secrets and the quality gate for Java, JavaScript, TypeScript, Python, HTML and CSS | `sonarqube:<build>-community` server, `sonarsource/sonar-scanner-cli` scanner | Platform LGPL-3.0. Analyzers: Sonar Source-Available License, free for non-competitive use | SonarQube Scan, from JSON pages exported from its API |
| SpotBugs with Find Security Bugs | Injection, XSS, XXE, path traversal and unsafe deserialization in compiled Java classes, with knowledge of Spring, JDBC, JPA, Hibernate and JSP | Built in this repository from pinned, checksum-verified releases: neither project publishes an official image | SpotBugs LGPL-2.1, Find Security Bugs LGPL-3.0 | SpotBugs Scan, XML with messages |
| Gitleaks | Hard-coded secrets in files and in git history | `ghcr.io/gitleaks/gitleaks` | MIT | Gitleaks Scan |
| Syft | A CycloneDX software bill of materials for a source tree or a Docker image | `anchore/syft` | Apache-2.0 | None. The SBOM is stored and feeds Grype. |
| Grype | Known vulnerabilities in the SBOM's OS and language packages | `anchore/grype` | Apache-2.0 | Anchore Grype |
| OWASP Dependency-Check | Known vulnerabilities in Java and .NET dependencies, including JAR and DLL files shipped without manifests | `owasp/dependency-check` | Apache-2.0 | Dependency Check Scan |
| ZAP | Web application and API weaknesses, passively in baseline mode or actively in full mode | `ghcr.io/zaproxy/zaproxy` | Apache-2.0 | ZAP Scan, XML report |
| Nuclei | Known CVEs, misconfigurations and exposed panels, from signed templates | `projectdiscovery/nuclei` | MIT, engine and templates | Nuclei Scan, JSON report |

### What each language gets

| Language | Semgrep | SonarQube | Taint analysis | Dependency scanners |
| --- | --- | --- | --- | --- |
| Java | Yes | Yes, with reduced precision when no compiled classes are present | Find Security Bugs on compiled classes: JARs inside images and zips now, built source in the build-based phase | Yes, from Maven and Gradle files and from JARs |
| .NET (C#) | Yes | No. The command-line scanner cannot analyse C#; Sonar's .NET scanner needs a real build | The .NET SDK's security analyzers and Puma Scan, in the build-based phase | Yes, from NuGet files and from DLLs |
| JavaScript, TypeScript | Yes | Yes | Within one function only. Opengrep is the fallback for in-file cross-function taint | Yes, from lock files |
| Python | Yes | Yes | Same as JavaScript | Yes, from requirements and lock files |
| HTML | Yes | Yes |  |  |
| SQL and NoSQL | Injection flaws are found in the application code that builds the queries | Same |  | Stand-alone SQL scripts are not analysed: PL/SQL and T-SQL are not in Community Build |

### What each input allows

| Input | Tools that run |
| --- | --- |
| GitHub repository, company or vendor | Semgrep, SonarQube, Gitleaks over the full history, Syft then Grype, Dependency-Check. Find Security Bugs after a build, in the build-based phase. |
| Zip of source code | Semgrep, SonarQube, Gitleaks over the files, Syft then Grype, Dependency-Check, and Find Security Bugs on any JARs inside |
| Docker image | Syft then Grype on the image's packages. Find Security Bugs on its JARs. Gitleaks, Semgrep and Dependency-Check on the extracted filesystem where source or binaries are present. |
| Running URL | ZAP baseline on any environment. ZAP full and Nuclei on UAT only. |

### Operating rules for the scanners

- **Pin by digest.** Every image is pinned by exact version and digest, never `latest`. ZAP's version tag is re-pointed at each monthly rebuild, so for ZAP only the digest is the pin. The one self-built image, SpotBugs with Find Security Bugs, is rebuilt from pinned releases and kept in the local registry only.
- **SonarQube runs on demand.** Its server is heavy and slow to start, but the company wants only DefectDojo, the database and the portal always on. The worker starts the SonarQube server when a SonarQube job is queued, waits until it reports up, runs the scanner, exports the issues, and stops the server after 15 idle minutes. Its data stays on named volumes and in its own database, so each start is a resume, not a rebuild.
- **No network for code scanners.** Semgrep, Gitleaks, Syft and Grype run with no network. The SonarQube scanner reaches only the SonarQube server. Dependency-Check sends file hashes to Maven Central for accuracy; its Sonatype and npm-audit lookups stay off, and a "no third-party disclosure" profile turns Maven Central off too for sensitive vendor code.
- **Updates are separate from scans.** Daily or weekly updater jobs fetch Semgrep rules from a pinned commit of `semgrep-rules`, Nuclei templates, the Grype database and Dependency-Check's NVD data, using a free NVD API key. Scan containers never download anything. Each scan records the versions it used.
- **Secrets never land in findings.** Gitleaks runs with `--redact`, with SecureScan's own rule file so a vendor's `.gitleaks.toml` cannot switch rules off, and with inline allow-comments ignored. Analysts locate a secret by file, line and rule.
- **Findings are not failures.** Every tool's exit code is mapped individually: findings mean "completed", and only a tool error fails the job. ZAP exits 1 or 2 on findings, Grype and Dependency-Check exit non-zero only when asked to.
- **DAST stays inside the network.** Nuclei runs with update checks and out-of-band callbacks disabled and with internal DNS resolvers. ZAP runs silent, without run-time add-on updates. Neither sends anything to its vendor.
- **SonarQube export is a few lines, not a parser.** SecureScan pages the SonarQube issues API into a zip that DefectDojo's SonarQube parser reads directly. DefectDojo's own pull-style SonarQube import is deprecated and leaves the open-source edition in November 2026.

### Replacing CodeQL

CodeQL's job was taint analysis across functions and files for Java, C#, JavaScript, TypeScript and Python. No single free tool does that, so the replacement is one tool per language, evaluated against licence, maintenance, images and DefectDojo support in October 2026.

| Language | Replacement | Depth | When |
| --- | --- | --- | --- |
| Java | SpotBugs with Find Security Bugs on compiled classes | Taint analysis that knows Spring, JDBC, JPA, Hibernate and JSP: SQL, command, LDAP and expression injection, XSS, XXE, path traversal, unsafe deserialization | Version 1 on JARs inside vendor images and zips. Built source follows in the build-based phase. |
| .NET | The .NET SDK's own security analyzers (CA2100, CA3001 to CA3012, CA5350 to CA5405) plus Puma Scan Community Edition, run during `dotnet build` from the official SDK image, SARIF output | Data flow within one assembly | The build-based phase, because a build is required |
| JavaScript, TypeScript, Python | Opengrep, the LGPL fork of Semgrep, running the same rules with its in-file taint mode | Taint across functions within one file | Fallback engine, tried in Phase 0. Not planned for version 1. |
| All | Nothing free and maintained traces taint across files |  | Accept the gap, or budget for Semgrep Pro or SonarQube Developer Edition later |

The build-based phase is the price of deep analysis for compiled languages. Maven, Gradle and .NET builds execute the scanned project's own build scripts, so they get the strictest sandbox: no Docker socket, non-root, egress only to the package registries through the proxy, and hard time limits. The same builds give SonarQube full Java precision and make SonarQube for .NET possible.

Rejected: Security Code Scan, Horusec and Insider are unmaintained; Joern is a query platform without rule packs for these languages; Bearer is source-available, in maintenance mode and charges for C#; Bandit, njsscan and ESLint security rules add rules at Semgrep's depth, not deeper analysis.

### Known limits to state in every report

- Semgrep CE traces taint only within one function, and SonarQube Community Build has no taint analysis. Find Security Bugs closes that gap for Java bytecode, the .NET analyzers close it for C# once builds run, and for JavaScript, TypeScript and Python no free, maintained tool traces taint across files.
- Syft and Grype see only the dependencies declared in manifests and lock files when scanning source. A zip without lock files yields a thin result.
- Dependency-Check identifies components by fuzzy matching to NVD entries and produces both false positives and false negatives by its own account.
- Gitleaks is in maintenance mode: security patches only. Its author's successor, Betterleaks, replaces it once DefectDojo ships a parser for it. The swap is a configuration change.
- Semgrep's rules and SonarQube's analyzers are free but not open source. Reports stay internal by default, and no scanner output is fed to external AI services, which the Sonar licence forbids.

### Orchestration

- **States.** A job moves through `queued`, `preparing` and `running`, then ends as `completed`, `failed`, `cancelled` or `timed_out`. Its DefectDojo import is tracked separately as `pending`, `imported` or `failed`.
- **Concurrency.** Three caps apply: a global cap, a cap per tool, and one active DAST job per target host.
- **Retries.** Infrastructure failures retry twice with backoff. Tool errors and findings never trigger a retry.
- **Timeouts.** Proposed defaults are 60 minutes for SAST, 30 minutes for DAST baseline and 8 hours for DAST full. Profiles override them.
- **Cancellation.** Cancelling stops the container and keeps partial logs.
- **Scheduling.** Each target can carry a cron schedule and blackout windows.
- **Crash recovery.** On start, the worker matches `running` jobs to live containers by label. Orphans are re-queued or failed.

### Scanner container contract

Every scanner image follows one contract, so the worker treats all tools alike.

| Aspect | Contract |
| --- | --- |
| Input | `/work/src` read-only for code, `/work/config` read-only for rules and plans, parameters as environment variables |
| Output | `/work/out/report.*` in the tool's native format, plus `/work/out/meta.json` with tool and rule versions |
| Exit code | `0` means the tool ran, whatever it found. Non-zero means the tool itself failed. |
| Identity | Label `securescan.job_id` on the container |
| Hardening | Non-root user, read-only root filesystem, all capabilities dropped, `no-new-privileges`, PID limit |
| Limits | CPU, memory and wall-clock time from the profile |

A scan profile is versioned YAML stored in the database:

```yaml
profile: code-standard
version: 4
jobs:
  - tool: semgrep
    rules: [semgrep-rules@<commit>, company-rules]
    limits: { cpus: 2, memory: 4g, timeout_min: 60 }
    network: none
  - tool: gitleaks
    limits: { cpus: 1, memory: 1g, timeout_min: 20 }
    network: none
  - tool: syft-grype
    limits: { cpus: 1, memory: 2g, timeout_min: 20 }
    network: none
  - tool: dependency-check
    analyzers: { central: true, ossindex: false, npm_audit: false }
    limits: { cpus: 2, memory: 4g, timeout_min: 60 }
    network: maven-central
  - tool: sonarqube
    limits: { cpus: 2, memory: 2g, timeout_min: 60 }
    network: sonarqube
verdict:
  fail_on: { critical: 1, high: 5 }
```

### Code scan pipeline

1. **Acquire source.** Clone the repository at the commit with a short-lived token, unpack the zip, or save the Docker image to a tarball and extract its filesystem.
2. **Validate input.** Reject archives with path traversal, symlink escapes or decompression-bomb ratios. Enforce a size limit, proposed at 2 GB.
3. **Detect languages** and pick the rule packs and the tools that apply. A Docker image without source gets the dependency scanners, and Find Security Bugs if it holds JARs.
4. **Run the independent tools in parallel.** Semgrep, Gitleaks, Syft then Grype, Dependency-Check, and Find Security Bugs on any compiled classes, each in its own container, with no network except Dependency-Check's Maven Central lookup.
5. **Run SonarQube.** Start the server if needed, create or reuse the project, run the scanner, wait for the analysis task, read the quality gate and export the issues.
6. **Hand off** every raw report for import into DefectDojo.

Every scan is a full scan of one commit, upload or image. Pull-request and diff-only scans are not in version 1.

### DAST pipeline

1. **Register the target** with base URL, environment tag, in-scope patterns, excluded paths, API specification and authentication settings.
2. **Choose a mode.** Baseline is passive and is the only mode allowed on production. Full and API modes run active attacks and are allowed only on UAT targets.
3. **Generate a ZAP automation plan** from the target settings: context, authentication, spider, AJAX spider, active-scan policy and report.
4. **Authenticate** by form, JSON, header token or browser-based login. The job fails if the logged-in indicator disappears, so a broken session never reports a false clean result.
5. **Run Nuclei** on UAT targets, against the same scope, with templates filtered by severity and tag. Out-of-band callbacks stay disabled.
6. **Hand off** each raw report for import into DefectDojo.

### DAST safety controls

- Targets must match the allowlist and belong to a registered application.
- Every target carries an environment tag, `production` or `uat`. Only analysts and admins set or change it, and each change is audited.
- Production targets accept unauthenticated ZAP baseline scans only. Full scans, API scans, Nuclei and login profiles belong to UAT targets. The API refuses anything else, with no override.
- Deployable vendor products are installed by the company in UAT, so they get full scans there.
- Vendor-hosted SaaS targets count as production unless the vendor provides and authorizes a UAT instance. Either way, the vendor's written authorization, scan window and contact come first.
- Request rate is capped per target, and scans respect blackout windows.
- DAST containers sit on a dedicated network whose only route out is a forward proxy enforcing the job's allowlist.
- Any analyst can stop a running scan from the portal.

### Results handling

- **Check the report.** The worker confirms the report exists, is well-formed JSON or XML, and is under the size cap. A missing or broken report fails the job.
- **Keep the original.** The raw report is stored with its SHA-256 for the retention period, so it can be imported again later.
- **Import.** The sync task uploads it to DefectDojo through that tool's parser, as the DefectDojo section describes.
- **No parsing in SecureScan.** Severity mapping, deduplication and finding state all happen in DefectDojo.
- **Counts.** After import, SecureScan stores the active finding counts by severity for the job.

## Data model

The inventory hangs off one chain: Vendor, Application, Version, Target, Scan, ScanJob, FindingHistory. Findings are triaged only in DefectDojo; the history rows are an append-only copy of what DefectDojo recorded.

| Entity | Key fields | Notes |
| --- | --- | --- |
| Vendor | name, contact, risk tier | Only for vendor applications |
| Application | name, type (`internal` or `vendor`), vendor, criticality, data classification, tags, GitHub repository ID, automatic-scan flag, DefectDojo product ID, cached open-finding counts | The inventory unit. Repositories discovered from GitHub arrive unconfirmed until an analyst reviews them. |
| ApplicationVersion | application, label (branch, tag, upload or image digest), DefectDojo engagement ID, SonarQube project key | Reports are scoped to a version |
| Target | version, kind (`github_repo`, `vendor_repo`, `zip`, `image`, `url`), locator, environment tag (`production` or `uat`), credential reference, DAST scope and login profile | The environment tag is set by analysts only |
| ScanProfile | name, version, YAML body | Immutable per version |
| Scan | version, profile version, trigger (`user`, `change`, `weekly`), requester, state, verdict result | One request |
| ScanJob | scan, tool, state, image digest, content versions, timings, exit code, import state, DefectDojo test ID, counts by severity | One tool run |
| Artifact | owner, kind (`upload`, `raw_report`, `sbom`, `log`, `report_file`, `template`), storage key, SHA-256, size | Files live on the artifact volume |
| FindingHistory | scan job, DefectDojo finding ID, title, severity, CWE, CVE, component, file and line or URL, tool, state at scan time, state now | Append-only. "State now" refreshes nightly. |
| Report | version, kind (`application` or `vendor`), template version, snapshot, hash, file artifact, review state, verdict, reviewer | Rendered from the frozen snapshot |
| ReportTemplate | name, version, zip artifact, default for which kind, validated date | The SonaComstar template ships built in |
| Policy | verdict thresholds, scope | Applied by classification or per application |
| Schedule | repository set, poll interval, weekly day and hour, DAST schedules, blackout windows |  |
| Credential | kind (`github_app_key`, `deploy_key`, `vendor_token`, `registry`, `dast_login`, `nvd_key`), encrypted secret, owner, expiry | Expiry raises an alert |
| GitHubConnection | app ID, client ID, installation ID, key references, API base URL, API version | One per GitHub organisation |
| RepositoryHead | repository, branch, last seen commit, last scanned commit | Poller state |
| ContentVersion | feed (`semgrep_rules`, `nuclei_templates`, `grype_db`, `nvd_data`), version, fetched date, regression result, active flag |  |
| User | Entra object ID, name, email, roles at last sign-in, DefectDojo user ID | No passwords |
| SyncOutbox | job, attempts, next attempt, state | Drives DefectDojo import |
| AuditEvent | actor, action, object, time, source address, detail | Append-only |

The schema has about 20 tables and nothing specific to any one tool, so a new scanner needs no migration. Three indexes carry most queries: history by application, severity and date; scans by application and time; jobs by state.

## DefectDojo integration

A new DefectDojo 3.4 instance starts with SecureScan, is configured automatically, and receives every scan report with no manual step. It is the only place findings are triaged. The open-source edition has had no single sign-on and no roles since version 3.0 (June 2026), so SecureScan provisions local DefectDojo accounts for its users and keeps DefectDojo behind the same Entra-protected gateway. Facts here were checked against DefectDojo's source and documentation on 6 October 2026.

### Object mapping

DefectDojo's interface now calls a Product Type an Organization and a Product an Asset. Its API keeps the old names.

| SecureScan | DefectDojo | Rule |
| --- | --- | --- |
| Portfolio: Internal or Vendor | Product Type, shown as Organization | Two, created at setup |
| Application | Product, shown as Asset | Same name, tagged with the SecureScan application ID |
| Application version, or vendor assessment | Engagement | One per version. Deduplication is scoped to the Engagement, so each one stands alone. |
| Tool, target and profile within a version | Test | Re-imported on every scan, so one Test holds the history |
| Raw tool report | The tool's own parser: Semgrep JSON Report, SonarQube Scan, SpotBugs Scan, Gitleaks Scan, Anchore Grype, Dependency Check Scan, ZAP Scan, Nuclei Scan | One parser per tool, no custom format |
| DAST target URL | Location, called Endpoint before 3.0 | Created by the import |

### Data ownership

| Data | Owner | Other side |
| --- | --- | --- |
| Applications, versions, targets, vendors | SecureScan | DefectDojo mirrors the names |
| Scan runs, logs, raw reports, SBOMs, tool versions | SecureScan | DefectDojo gets a summary in the Test description |
| Findings, deduplication, open and closed state | DefectDojo | SecureScan keeps an append-only history copy and counts |
| Triage, notes, SLA | DefectDojo | SecureScan shows the state in history and reports |
| Vendor verdicts and reports | SecureScan | Findings are read from DefectDojo at report time |

### Accounts and access

- Sign-in to DefectDojo is by local username and password. Single sign-on, LDAP and roles are DefectDojo Pro features since 3.0.
- When an Admin or Analyst first signs in to SecureScan, SecureScan creates a matching DefectDojo user through the API: Admins as superusers, Analysts as staff users, which lets them see every Asset. The portal shows the initial password once, and DefectDojo forces a change at first login.
- DefectDojo is reachable only through the gateway, and the gateway forwards a request only when it carries a valid SecureScan session. Someone who loses Entra access cannot reach the DefectDojo login page at all.
- An Admin can disable a DefectDojo account in Settings. Accounts unused for 90 days are disabled automatically.
- The import service account is a local staff user, not a superuser. Staff is enough to import with automatic creation of Organizations, Assets, Engagements and Tests. Its token comes from `POST /api/v2/api-token-auth/` at setup and is stored encrypted.

### Setup at deployment

1. `docker compose up` starts DefectDojo's services, nginx, uwsgi, celeryworker, celerybeat and valkey, at a pinned release, from the same Compose project. Images are pulled from Docker Hub rather than DefectDojo's own registry, which logs every pull. The database lives in the shared PostgreSQL through `DD_DATABASE_URL`.
2. DefectDojo's initializer creates the schema and the admin account from `DD_ADMIN_PASSWORD`, supplied as a Docker secret.
3. `dojo-init` waits until DefectDojo answers, creates the `securescan-sync` staff user and takes its token.
4. It turns deduplication on in system settings, which is off by default, and creates the Internal and Vendor product types. Per-parser deduplication fields are set through `DD_HASHCODE_FIELDS_PER_SCANNER` in the Compose file.
5. It runs on every start and changes only what is missing, so restarts and upgrades are safe.

### Import flow

1. When a job completes, the worker writes a SyncOutbox row in the same transaction as the job state.
2. The import task calls `POST /api/v2/reimport-scan/` with the raw report, the tool's `scan_type`, `auto_create_context`, the product type, product, engagement and test names, `close_old_findings`, `deduplication_on_engagement` and `deduplication_execution_mode=async_wait`. The first call creates the hierarchy.
3. DefectDojo parses the report, deduplicates against earlier findings, closes findings no longer detected and reopens those that return. The response carries the Test ID, per-severity statistics and a `deduplication_complete` flag.
4. When the flag is true, SecureScan takes the counts from the response. Otherwise it re-reads them later from `GET /api/v2/findings/`, filtered by test, active, not duplicate, not false positive, not out of scope and not risk accepted.
5. SecureScan reads the findings for the Test, appends them to the history, saves the counts and evaluates the verdict policy.
6. Failures retry with exponential backoff. Rows that exhaust retries land in a dead-letter view where an admin can replay them.

A scan never fails because DefectDojo is down. Its verdict stays `pending` until the import succeeds.

### Design points

- **DefectDojo's parsers, not custom ones.** Eight tools import through DefectDojo's own parsers; Syft's SBOM is stored, not imported. The cost is that finding quality depends on those parsers.
- **Deduplication needs tuning.** Semgrep CE emits no fingerprint, so DefectDojo hashes title, CWE, line, file and description, and a shifted line becomes a new finding. Phase 0 settles the hash fields per tool.
- **Version pinning.** DefectDojo 3.4.0 is pinned. It ships weekly patches and a minor release every month, and 3.5.0 in November 2026 removes Tool Configurations and API pull parsers, none of which SecureScan uses. Contract tests run setup, import and count read-back against a new release before any upgrade.
- **Links for both roles.** Every scan, application and assessment page links to the matching DefectDojo view. The portal shows findings only inside reports and history.
- **Reports and deltas.** Report generation reads findings from DefectDojo at that moment. A re-assessment delta compares two Engagements by DefectDojo's finding hash.
- **Exit route.** Raw reports stay in the artifact store, so history can be imported again into a rebuilt system, or into DefectDojo Pro if the company ever buys it for single sign-on.

## GitHub integration

A private GitHub App owned by the company's organisation connects SecureScan to GitHub Enterprise Cloud, read-only. Scans start from a poller rather than from webhooks, so nothing on the internet needs to reach the machine.

### Connection

| Item | Choice |
| --- | --- |
| Identity | One private GitHub App, installed on the corporate organisation. No personal access token, no machine user. GitHub recommends this for server integrations, and it takes no licence seat. |
| Permissions | Contents: read and Metadata: read. Nothing else. Permissions are fixed at registration, because any later change needs re-approval by the organisation owner. |
| Credentials | The App's private key is a file-based Docker secret; two keys are kept so rotation needs no downtime. For each scan job the worker mints a one-hour installation token scoped to that one repository and keeps it in memory only. |
| Cloning | The worker clones with a git credential helper, never with a token in the URL, and removes the remote before the checkout is mounted read-only into scanner containers. Scanners never see GitHub credentials. |
| Endpoints | API base URL, git host and the pinned `X-GitHub-Api-Version` header are configuration. GitHub retires API versions after about two years, so the header is reviewed in the yearly upkeep. |
| Network | Outbound HTTPS to github.com only. If the organisation uses a GitHub IP allow list, the machine's egress address must be on it. |

### Discovery and triggers

1. **Nightly discovery.** SecureScan lists the repositories the App can reach and adds new ones to the inventory as internal applications. An analyst confirms each one and chooses whether it joins the automatic set.
2. **Change polling.** Every 10 minutes the poller reads the default-branch head of each repository in the automatic set. A new commit enqueues one code scan; repeated triggers for the same repository collapse into one.
3. **Weekly full scan.** Every repository in the automatic set is scanned once a week whether or not it changed, so rule updates reach old code.
4. **On demand.** Any user can start a scan of any reachable repository from the SAST scan page.

Polling was chosen over webhooks for three reasons: it needs no inbound path from github.com, GitHub does not retry failed webhook deliveries, and a poller doubles as the reconciliation a webhook design would need anyway. The App's webhook stays switched off. The poller is budgeted to stay inside GitHub's rate limit even if no request is cached, which keeps several hundred repositories comfortably within reach. If push-to-scan latency matters later, a reverse proxy in the DMZ that accepts only GitHub's published hook addresses can be added without changing the scan path.

### Vendor repositories

| Access | How it works | Notes |
| --- | --- | --- |
| Public repository | URL only |  |
| Read-only deploy key, the default | SecureScan generates an SSH key pair per vendor repository and shows the public key in the portal. The vendor adds it to the repository as a read-only deploy key. | No secret crosses company lines. One key per repository. The vendor's organisation may first need to allow deploy keys. |
| Vendor-issued token | The vendor creates a fine-grained token limited to that repository with Contents: read and hands it over. SecureScan stores it encrypted with its expiry date. | Tied to a vendor employee and usually valid for at most a year. |
| Zip upload | Fallback when neither is possible |  |

Vendor credentials belong to one assessment, are encrypted at rest and raise an alert before they expire. GitHub removes keys and tokens unused for a year, so a yearly re-assessment should expect to re-establish access. Vendor repositories hosted in the company's own GitHub organisation need none of this: the App already reaches them.

## Application security reports

Every completed scan produces a security report automatically. Users read it in the portal and download it as a PDF, so nobody outside the security team needs DefectDojo.

### How a report is made

1. A scan finishes and its tool reports are imported into DefectDojo.
2. The report task reads that version's active findings from DefectDojo and freezes them as a snapshot with a hash.
3. It adds the scan facts SecureScan holds: tools run, tool and rule versions, coverage and gate result.
4. One HTML template renders the snapshot. The portal shows that HTML, and WeasyPrint turns the same HTML into the PDF.
5. The report is stored with the scan. Earlier reports stay available as a record.

### What it contains

| Section | Content |
| --- | --- |
| Header | Application, version, commit, scan date, tools with versions, report hash, review state |
| Summary | Gate result, finding counts by severity and by tool, change since the previous report |
| Findings | Title, severity, CWE, file and line or URL, description, remediation, triage status |
| Code quality | SonarQube quality gate and its key measures |
| Components | Component count from the Syft SBOM, with the SBOM file attached |
| Coverage | What was scanned, what was skipped and why |

### Rules

- **Review state is explicit.** A report made straight after a scan holds findings no analyst has reviewed. Its header says "Automatic, not yet reviewed" until an analyst marks it reviewed.
- **Regenerate after triage.** A new report reads the current state from DefectDojo, so false positives drop out. The old report stays.
- **One template, two outputs.** The portal view and the PDF come from the same template, so they never drift and only one thing needs upkeep.
- **Access.** Both roles see every report. Every download is audited.
- **Secrets stay masked.** A leaked-credential finding shows its file, line and rule, never the secret value.
- **Hostile text is contained.** Scanner output can carry markup from scanned code. The template escapes it, and the portal shows the report in a sandboxed frame.

### Templates

- **Default template.** SecureScan ships one SonaComstar-branded template: a text wordmark now and the logo when it arrives, a black-and-white layout, a cover page and the sections above.
- **Downloadable.** An admin can download the default template as a zip of its HTML, CSS and logo files, as the starting point for a new one.
- **Custom templates.** An admin uploads a template zip in Settings. SecureScan test-renders it with sample data and shows a preview before it can be used.
- **Choice per report.** Each report kind has a default template, and a user can pick another when generating.
- **Safe rendering.** A template is code, so it runs in a sandboxed template engine with no file or network access.
- **Versioned.** Every report records the template version it used, so an old report can be reproduced.

Reports map findings to OWASP Top 10 and CWE Top 25. No other standard is required. Vendor assessment reports use the same engine and add the verdict and coverage sections described below.

## Historical data

Every scan and every finding it produced is kept permanently in SecureScan's PostgreSQL database. The Historical data page queries that history and exports it as CSV.

The requirement named a "backup Postgres DB". This design reads that as the platform's own PostgreSQL container acting as the permanent history store, which is itself backed up nightly off the machine.

### What is kept

| Record | Content |
| --- | --- |
| Scans | Who started it, when, the source, commit or image digest, tools, tool and rule versions, duration and outcome |
| Findings per scan | One row per finding as DefectDojo recorded it after import: title, severity, CWE, CVE, component, file and line or URL, tool, and triage state at that time |
| Triage state now | The same finding's state in DefectDojo today, refreshed nightly |
| Reports | Every generated report with its snapshot, template version and hash |
| Raw tool reports and logs | The files each scanner wrote. Kept by default, with an optional age limit if disk becomes a concern. |
| Audit events | Every security-relevant action |

### How history is written

1. A tool report is imported into DefectDojo, which parses and deduplicates it.
2. SecureScan reads the findings DefectDojo holds for that scan and appends them as history rows.
3. History rows are never edited. A nightly task updates only the "state now" column from DefectDojo.

No tool-specific parsing is needed, because DefectDojo has already put every tool's findings into one shape. Triage still happens only in DefectDojo.

### Querying and CSV export

- **Two views:** scans and findings.
- **Filters:** application, vendor, internal or vendor, source, tool, severity, CWE, triage state, date range and who started the scan.
- **Export:** one button exports the whole filtered result as CSV, not only the visible page.
- **Shareable:** a query is a URL, so it can be bookmarked or sent to a colleague.
- **Access:** both roles see all rows. Every export is audited.
- **Safe CSV:** cell values that begin with `=`, `+`, `-` or `@` are escaped, because finding text comes from scanned code and could carry a spreadsheet formula.

## Vendor assessment and reports

A vendor assessment is a scan marked as vendor, followed by an analyst-reviewed report with a verdict. The report is rendered from a frozen snapshot of the DefectDojo findings, so it can be reproduced exactly later.

### Workflow

1. **Start.** On the SAST or DAST scan page, the user marks the scan as vendor and names the vendor, product and version, and whether it is deployable or SaaS. Vendors supply a Docker image, zipped source code or a GitHub repository URL.
2. **Hosting and authorization.** The company installs a deployable product in its UAT environment, where full DAST is allowed. A SaaS product stays vendor-hosted: DAST needs the vendor's written authorization, scan window and contact, and is baseline only unless the vendor provides a UAT instance.
3. **Scan.** Every tool the supplied artefacts allow is run. The report's coverage section records what was tested and what could not be.
4. **Triage.** An analyst reviews the findings in DefectDojo and marks false positives.
5. **Report.** The analyst generates the vendor assessment report. The policy proposes Pass, Conditional pass or Fail. The analyst confirms it, or overrides it with a recorded reason, and marks the report reviewed.
6. **Re-assessment.** A scan of a new version of the same product produces a report that includes the delta.

### Default verdict policy

| Verdict | Proposed rule |
| --- | --- |
| Fail | Any open Critical finding, or more than 5 open High findings |
| Conditional pass | 1 to 5 open High findings, each with a remediation date agreed with the vendor |
| Pass | No open Critical or High findings |

Thresholds are configurable per data classification. Findings marked false positive or risk accepted in DefectDojo do not count as open.

### Report contents

| Section | Content |
| --- | --- |
| Cover and document control | Vendor, product, version, report ID, dates, classification label, report hash |
| Executive summary | Verdict, overall risk rating, finding counts by severity, top risks in plain language |
| Scope and coverage | Artefacts supplied, techniques applied, what was not tested and why |
| Methodology | Tools with versions, rule content version, mapping to OWASP Top 10 and CWE Top 25 |
| Findings summary | Counts by severity and by category, with a chart |
| Detailed findings | Title, severity, CWE, location or URL, evidence, impact, remediation, triage status |
| Delta from last assessment | Fixed, remaining and new findings |
| Conditions | Remediation deadlines attached to a conditional pass |
| Review | Reviewing analyst, verdict decision and date |

### Output formats

- **PDF** from the default SonaComstar template or a custom one.
- **HTML** view in the portal, from the same template.
- **CSV** finding list, for the vendor's remediation tracking.

## UI portal

The portal is deliberately small: a login page, a home page, three working pages and an admin settings page. It uses a black-and-white minimalist theme with SonaComstar branding.

### Pages

| Page | Who sees it | What it does |
| --- | --- | --- |
| Login | Everyone | The SonaComstar wordmark, the product name and one "Sign in with Microsoft" button on a plain background. No other fields. |
| Home | Both roles | Running scans, latest results and open-finding counts. An "Open DefectDojo" button leads to the DefectDojo login page. |
| SAST scan | Both roles | Start a code scan and follow it. Lists running and recent code scans. |
| DAST scan | Both roles | Start a scan of a registered URL and follow it. Register targets and set environment tags here. |
| Historical data | Both roles | Query all past scans and findings with filters, export the result as CSV, open any report or download its PDF. |
| Settings | Admins | GitHub connection, automatic scan rules, report templates, policies, scanner updates, import queue, audit log and system health. |

A scan detail view opens from any scan list. It shows each tool's status, the live log, tool versions, finding counts and the report.

### Scan forms

| Form | Fields |
| --- | --- |
| SAST scan | Source: a connected GitHub repository, a GitHub URL, a zip upload or a Docker image. Application and version. Internal or vendor, with the vendor name. Tools, with every applicable one ticked by default. |
| DAST scan | Target, chosen from registered URLs. Mode: baseline always, full and API only when the target is tagged UAT. Optional login profile. |

### Look and feel

- **Monochrome.** Black, white and greys, one typeface, generous spacing, no decoration.
- **Colour means something.** Colour appears only for severity and scan status, always with a text label beside it.
- **Branding.** "SonaComstar" appears as a text wordmark on the login page, the header and report covers. The logo files come later and replace the wordmark in one place: a single brand asset folder.
- **Accessible.** WCAG 2.1 AA contrast and full keyboard use.

### Frontend stack and conventions

- **Build:** React, TypeScript in strict mode, Vite, route-level code splitting.
- **Components:** Radix primitives styled with Tailwind, in the shadcn/ui pattern. The component code lives in the repository, which suits a monochrome theme and a long life.
- **Data:** TanStack Query for server state. The API client is generated from the backend's OpenAPI document, so types never drift.
- **Tables:** server-side filtering and pagination. Filter state lives in the URL, so a history query can be shared as a link.
- **Live updates:** server-sent events for scan progress and logs, with polling as fallback.
- **Quality:** Vitest and Testing Library for units, Playwright for the main flows.
- **Delivery:** static files with hashed names, compressed and cached by nginx. No calls to external CDNs.

## API

One versioned REST API under `/api/v1` serves the portal and CI pipelines alike. FastAPI generates the OpenAPI 3.1 document that the frontend client is built from.

| Resource | Endpoints | Notes |
| --- | --- | --- |
| Session | `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`, `GET /me` | Entra ID code flow. The session is an HttpOnly cookie. |
| Applications | `GET, POST /applications`, `GET, PATCH /applications/{id}` | Filter by type, vendor, last scan, open-finding counts |
| Versions and targets | `GET, POST /applications/{id}/versions`, `GET, POST, PATCH /versions/{id}/targets` | Only analysts may set a target's environment tag |
| Vendors | `GET, POST /vendors`, `GET, PATCH /vendors/{id}` |  |
| Uploads | `POST /uploads`, `PATCH /uploads/{id}` | Chunked and resumable for large zips and image tarballs |
| Scans | `POST /scans`, `GET /scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /scans/{id}/events` | The API refuses modes the target's environment tag forbids. Events are server-sent. |
| Results | `GET /scans/{id}/results` | Counts by severity, import state, report link, and the DefectDojo link for analysts |
| History | `GET /history/scans`, `GET /history/findings`, `GET /history/findings.csv` | Filters as query parameters. The CSV streams the whole filtered result. |
| Reports | `POST /reports`, `GET /reports/{id}`, `GET /reports/{id}/html`, `GET /reports/{id}/pdf`, `POST /reports/{id}/review` | Review records the verdict decision and the analyst |
| Templates | `GET /templates`, `GET /templates/default/download`, `POST /templates`, `POST /templates/{id}/preview` | Admins only |
| GitHub | `GET, PUT /integrations/github`, `POST /integrations/github/test`, `GET /integrations/github/repositories`, `POST /integrations/github/sync` | The test mints a token and lists repositories, so permission problems show before a scan |
| Vendor access | `POST /credentials/deploy-key`, `POST /credentials/vendor-token` | Returns the public key to hand to the vendor |
| Administration | `/profiles`, `/schedules`, `/policies`, `/content-versions`, `/scanner-health`, `/audit-events` | Admins only |
| DefectDojo | `GET /integrations/defectdojo`, `GET /integrations/defectdojo/outbox`, `POST /integrations/defectdojo/outbox/{id}/replay` | Health, import queue and dead-letter replay |
| Health | `GET /healthz`, `GET /readyz`, `GET /metrics` | Not exposed through the gateway |

### Conventions

- **Pagination** is cursor-based on every list endpoint.
- **Errors** use the RFC 9457 problem-details format.
- **Authorization** is by role from Entra: Analyst or Admin.
- **Rate limits** apply at the gateway per session.
- **Compatibility:** breaking changes go to `/api/v2`. Additive changes stay in `/api/v1`.

The portal is the only client in version 1. There are no API tokens for scripts or pipelines; GitHub is reached from the inside through its API, not the other way round.

## Containerization and deployment

One Compose project runs everything on a single machine, and one `docker compose up` starts and configures all of it. Only DefectDojo, PostgreSQL, the portal and the small socket proxy run all the time. Every scanner, the SonarQube server, the egress proxy and the updaters run only while a job needs them.

### Containers

| Container | Runs | Image | Purpose | Data |
| --- | --- | --- | --- | --- |
| `gateway` | Always | nginx unprivileged, with the built portal copied in | TLS, static files, reverse proxy to the API and to DefectDojo | Certificates are mounted |
| `api` | Always | SecureScan backend image | REST API and server-sent events | None |
| `worker` | Always | Same image, different command | Scan orchestration, GitHub polling, DefectDojo import, history, reports, updates | Workspace and content volumes |
| `db` | Always | PostgreSQL 18 | Three databases: SecureScan, DefectDojo and SonarQube | Database volume |
| `socket-proxy` | Always | `wollomatic/socket-proxy` | Lets the worker create, start, wait on, read logs of, stop and remove containers. Nothing else. | None |
| DefectDojo services | Always | Upstream images at a pinned release: web application, Celery worker and beat, message broker | Findings store and triage | Media volume; database in `db` |
| `migrate`, `dojo-init` | At start, one-shot | Backend image | Schema migrations; DefectDojo setup | None |
| `sonarqube` | On demand | `sonarqube:<build>-community` | Code quality server, started for SonarQube jobs and stopped after 15 idle minutes | Data, extensions and logs volumes; database in `db` |
| `egress-proxy` | On demand | Small forward proxy | Allowlisted egress for DAST, updater and poller jobs | None |
| `scanner-*` | On demand | Publisher images, pinned by digest | One tool run each, then removed | Read-only content volume |
| `updater-*` | Scheduled | The same scanner images | Fetch rules, templates and vulnerability databases | Content volume |

### Image optimization

- **Multi-stage builds.** The backend builder stage installs dependencies into a virtual environment. The runtime stage copies only that environment and the application code.
- **One backend image** serves `api`, `worker` and `migrate`. That means shared layers, one image to patch and one to scan.
- **Frontend build stage.** Node builds the portal. Only the static output reaches the nginx image.
- **Layer order.** Lockfiles are copied and installed before source code, so code changes reuse the dependency layer.
- **Build caching.** BuildKit cache mounts hold the package caches. `.dockerignore` keeps tests, docs and Git history out of the context.
- **Small bases.** Slim Debian-based Python for the backend, so WeasyPrint's native libraries install cleanly. Alpine-based nginx for the gateway.
- **Pinned inputs.** Base images and scanner images are pinned by digest. `uv.lock` and `package-lock.json` pin dependencies.
- **Hardened runtime.** Non-root user, read-only root filesystem, `tmpfs` for scratch space, all capabilities dropped, `no-new-privileges`.
- **Health and limits.** Every service has a health check, CPU and memory limits, and starts only after its dependencies are healthy.
- **Scanner start-up.** Scanner images are pre-pulled. Rules, templates and vulnerability databases mount read-only from a shared volume, so no run downloads anything.
- **Disk hygiene.** Each job's workspace volume is deleted on completion. A nightly task removes orphans.

### Repository layout

```text
securescan/
  backend/      FastAPI app, worker tasks, DefectDojo client, Alembic migrations
  frontend/     React portal
  scanners/     Thin wrapper images and regression fixtures
  content/      Rule packs, ZAP policies, report templates
  deploy/       Compose files, nginx config, DefectDojo setup, environment templates
  docs/         Runbooks and architecture records
```

### Updates over the internet

- **What updates.** Semgrep rules from a pinned commit of `semgrep-rules`, Nuclei templates, the Grype vulnerability database daily, and Dependency-Check's NVD data daily with a free NVD API key.
- **Safety check.** New rules and templates must pass the regression scan before they become active, and a failed check keeps the previous version and raises an alert. Vulnerability databases update daily without a gate, because they carry data rather than logic.
- **Scanner images.** The updater proposes a new image digest each month. It goes live after the regression scan passes and an admin approves it. The self-built SpotBugs image is rebuilt from new SpotBugs and Find Security Bugs releases the same way. SonarQube follows its own monthly releases, and a year boundary is crossed only through the December release, as Sonar requires.
- **Narrow egress.** Only the updaters, the GitHub poller and the API's sign-in calls to Microsoft Entra reach the internet, through the egress proxy, to an allowlist of hosts.
- **Privacy.** No source code, finding or telemetry leaves the network. Scanner metrics, update checks and cloud features are off in every scan container.
- **Traceability.** Each scan records the content versions and image digests it used. An alert fires when a feed is older than its limit: 7 days for vulnerability databases, 30 days for rules and templates.
- **Platform and DefectDojo releases** are never automatic. An admin applies them in a maintenance window.

### Sizing

The always-on footprint is small because scanners and SonarQube run only on demand. The peak sets the machine size. These are starting figures; a Phase 0 load test replaces them with measurements.

| Load | What is running | Starting estimate |
| --- | --- | --- |
| Always on | DefectDojo, which itself recommends 2 vCPU and 8 GB with a separate database, plus PostgreSQL, portal, worker and socket proxy | 4 vCPU, 12 GB RAM |
| Typical peak | Always-on set plus the SonarQube server, two code scanners and one ZAP scan | 10 vCPU, 26 GB RAM |
| Recommended machine | Headroom for larger repositories and parallel scans | 16 vCPU, 64 GB RAM, 500 GB SSD, with 8 vCPU and 32 GB as the minimum |

### Host prerequisites

- A 64-bit Linux host with systemd and cgroup v2, so container CPU, memory and process limits are enforced.
- Docker Engine 29 or later and Docker Compose 2.20.3 or later, for the `include` element that pulls in DefectDojo's Compose file.
- Kernel settings for SonarQube's embedded search engine: `vm.max_map_count` at least 524288 and `fs.file-max` at least 131072, set persistently.
- Outbound HTTPS to the update, GitHub and Microsoft Entra hosts on the egress allowlist.
- A DNS name and a TLS certificate from the corporate authority for the portal and for DefectDojo.

### Growing on one machine

The platform stays on a single machine by decision. Capacity grows in three steps.

1. Raise the concurrency caps while CPU and memory allow.
2. Add CPU, memory and disk to the machine.
3. Move to a larger machine with the restore procedure, which doubles as the migration path.

## Security of the platform

SecureScan holds source code, credentials and a map of every weakness in the estate, so it is itself a high-value target. Six control groups protect it.

### Access

- Sign-in is through Microsoft Entra ID only, using OIDC. Multi-factor authentication and conditional access are enforced by Entra.
- Two Entra app roles, Admin and Analyst, are read from the `roles` claim at sign-in. SecureScan stores no passwords and has no user administration of its own.
- The Entra app registration requires assignment, so only assigned users can sign in.
- DefectDojo has local accounts that SecureScan provisions, and the gateway lets a request reach DefectDojo only with a valid SecureScan session.
- One local break-glass admin account exists in each tool, with its use alerted.
- Session cookies are `HttpOnly`, `Secure` and `SameSite=Lax`. State-changing requests carry a CSRF token.

### Secrets

- Git, registry, DAST and DefectDojo credentials are encrypted at rest with envelope encryption.
- The DefectDojo admin password and API token are generated at first start. Nobody types or sees them in normal operation.
- The master key comes from a Docker secret, or from the corporate vault where one exists.
- A secret is injected only into the one job container that needs it, and is masked in logs.

### Scanner isolation

- SecureScan never executes scanned code. Source is parsed, and images are unpacked rather than run.
- The worker reaches Docker only through the socket proxy. No container mounts the Docker socket directly, except the proxy.
- For stronger isolation, the machine can run rootless Docker, or scanners can run under gVisor.
- Uploaded archives are validated before unpacking, as described in the code scan pipeline.

### Data protection

- TLS on every hop, including API to database.
- Database and artifact volumes sit on encrypted disks. Backups are encrypted.
- Downloaded reports carry a watermark naming the downloader.
- Retention jobs delete uploads and raw artefacts on schedule.

### Audit

- An append-only audit table records logins, scan launches, target and scope changes, credential use, verdict overrides, report downloads and admin changes.
- Audit events also stream as JSON to the corporate SIEM.

### Supply chain

- All images are pinned by digest. A digest changes only through the update process.
- Updates come only from an allowlist of hosts over TLS, through the egress proxy.
- New scanner content and images must pass the regression scan before use.
- SecureScan's own images are scanned and get an SBOM in CI.
- SecureScan is the first application registered in SecureScan.

## Observability and operations

The platform exposes logs, metrics and health endpoints that plug into existing monitoring. Nothing here needs a new monitoring stack.

### Signals

- **Logs:** JSON on stdout from every container, tagged with scan and job IDs, shipped by the host's log driver.
- **Metrics:** a Prometheus endpoint on `api` and `worker`.
- **Health:** liveness and readiness endpoints used by Compose health checks.

| Metric | Proposed alert |
| --- | --- |
| Queue depth and oldest queued job age | Oldest job queued over 30 minutes |
| Job duration and failure rate per tool | Failure rate over 20% in an hour |
| DefectDojo import lag and dead-letter count | Lag over 1 hour, or any dead letter |
| GitHub poller | No successful poll in 1 hour |
| SonarQube start time | Server not up within 5 minutes of a request |
| Disk use on workspace, artifact and database volumes | Over 80% |
| Feed age | Vulnerability databases over 7 days, rules or templates over 30 days |
| API latency and error rate | 95th percentile over 2 seconds |

### Backup and restore

- SecureScan database: nightly base backup with continuous WAL archiving, which meets the 24-hour recovery point with margin.
- DefectDojo database and media: backed up in the same nightly job. It holds every finding and triage decision, so it is the most valuable data on the machine.
- Artifact volume: nightly snapshot, taken after the database backups.
- Every backup is encrypted and copied off the machine, because one machine is a single point of failure.
- A restore drill runs every quarter on a spare machine.

### Upgrades

- Each release is a versioned Compose bundle. The `migrate` container applies schema changes before `api` starts.
- DefectDojo upgrades follow its release notes, one release at a time, after the contract tests pass on a copy.
- Scanner upgrades are separate from platform upgrades. A new scanner digest must pass a regression run first.
- The regression run scans known-vulnerable applications, such as OWASP Juice Shop and WebGoat, and compares findings with the previous digest.

### Runbooks to write

- Scan stuck or scanner container orphaned.
- DefectDojo unreachable or rejecting imports.
- Scanner content update failed, and rollback to the previous version.
- SecureScan release upgrade.
- DefectDojo release upgrade.
- Full restore on a new machine.
- Credential or master-key rotation.

## Running it for 5 to 10 years

The platform is built once and then run by the security and IT team, so upkeep must be routine work, not development. Five rules follow from that.

| Rule | What it means here |
| --- | --- |
| Little custom code | SecureScan orchestrates. DefectDojo parses, stores and triages. There are no parsers, deduplication logic or findings database to maintain. |
| Long-supported parts | Python, PostgreSQL, nginx, React and Docker Compose have large communities and published support windows. |
| Nothing changes silently | Every image is pinned by digest. Scanner content passes a regression scan before use. Platform changes wait for a maintenance window. |
| Operable without developers | Updates, health, the import queue and the audit log are portal screens. Every recurring task has a runbook. |
| Replaceable parts | Scanners sit behind one container contract. Raw reports are kept, so history survives a rebuild or a change of tool. |

### Upkeep calendar

| Cadence | Task | Done by |
| --- | --- | --- |
| Daily, automatic | Refresh the Grype and NVD vulnerability databases. Poll GitHub for changes. Refresh triage state in history. | The platform |
| Weekly, automatic | Fetch Semgrep rules and Nuclei templates, run the regression scan, promote or alert. Weekly scans of the automatic repository set. | The platform |
| Monthly | Approve proposed scanner image updates, including the new SonarQube build. Review alerts, the import queue and the DefectDojo accounts. | Security team |
| Quarterly | Apply SecureScan and DefectDojo releases, operating-system and Docker patches. Run the restore drill. | IT team |
| Yearly | Review rule packs, scan profiles, verdict policy, role assignments, scanner licence terms and the pinned GitHub API version. | Security team |
| Every 3 to 4 years | Move to newer Python, PostgreSQL and Node build versions before their support ends. | Code owner |

### What still needs an owner

Three jobs cannot be automated away and need a named owner before go-live:

- Source-code changes when a dependency reaches end of support.
- DefectDojo upgrades that change its API or data model.
- Replacing a scanner whose project is abandoned or relicensed.

The build ends with a handover: runbooks, an architecture record, and a walked-through upgrade and restore with the security and IT team.

## Delivery roadmap

Delivery runs in five phases, each closed by a gate. Phase 1 is the first usable release: a GitHub repository is scanned by the seven code tools, the findings land in DefectDojo and the report appears in the portal.

&#91;embedded content: delivery roadmap · 5 phases, 5 gates\]

Phase 0 retires the three biggest unknowns before feature work starts: the scanner container contract, the DefectDojo import path, and starting and stopping SonarQube on demand. Phase 4 ends with the handover to the security and IT team. Durations are left out until the build team and its size are known.

## Risks and mitigations

Eighteen risks could undermine the platform. The first four decide whether teams trust its results.

| Risk | Impact | Mitigation |
| --- | --- | --- |
| No free tool does cross-file taint analysis, so some injection flaws stay unfound | False sense of security | Find Security Bugs covers Java, the .NET analyzers cover C# once builds run, Opengrep is the fallback for in-file taint; state the limit in every report and benchmark against known-vulnerable applications |
| C# gets pattern scanning only, because SonarQube's command-line scanner cannot analyse it | Weaker coverage for .NET applications | Semgrep and Dependency-Check cover C# now; the build-based phase adds the .NET SDK's security analyzers, Puma Scan and SonarQube for .NET |
| False-positive volume overwhelms analysts | Findings get ignored | Curated rule packs, DefectDojo deduplication and triage, reports that show their review state |
| Vendor zips arrive without lock files or source | Thin dependency results | Coverage section in the report; ask vendors for lock files or the Docker image |
| A DAST scan damages a target | Outage or data loss | Baseline only on production with form posting off, full scans only on UAT, allowlist, rate caps, stop button |
| SonarQube Community Build has no long-term release line | Monthly releases and a strict upgrade path across years | Pinned builds mirrored locally, quarterly upgrade task with the December rule, contract test after each upgrade |
| Grype retires a database schema about a year after a new one ships | Scans fail on stale data | Quarterly Grype image bump; the health page shows database schema and build date |
| NVD API outages stall Dependency-Check updates | Stale vulnerability data | Configurable NVD source with a mirror fallback; feed-age alert |
| Gitleaks receives security patches only | The secret scanner goes stale | Swap to Betterleaks once DefectDojo parses it; the swap is configuration |
| GitHub rate limits or token rotation slow the poller | Scans start late | Poller budgeted without caching, serial requests, status shown in Settings |
| One machine is a single point of failure | Scanning and triage stop until restore | Off-machine backups, quarterly restore drill, 4-hour recovery target |
| Knowledge fades over a 5 to 10 year life | Nobody can upgrade or fix the platform | Little custom code, runbooks, the upkeep calendar, named owners, a handover |
| Docker API access equals root on the machine | Full platform compromise | Per-endpoint allowlist and bind-mount restriction in the socket proxy, a fixed scanner catalogue, no other workloads on the machine |
| Scanner licence terms change again | Forced swap | Yearly licence review; one adapter per tool; Opengrep and Betterleaks as fallbacks |
| DefectDojo parser or API changes on upgrade | Imports break | Pinned release, contract tests before each upgrade, one client module to change |
| One PostgreSQL couples three upgrade schedules | A major upgrade waits for the slowest product | SonarQube's support matrix sets the pace; dump-and-restore runbook; three containers remain an option |
| A secret value leaks through a tool report | Credential exposure | Gitleaks redaction, ZAP header redaction, token-pattern scrubbing in logs, CSV escaping |
| Open-source DefectDojo has no single sign-on or roles since 3.0 | A second login, and accounts that could outlive Entra access | Accounts provisioned by SecureScan, forced password change, gateway requires a SecureScan session, 90-day inactivity disable, DefectDojo Pro restores SSO if ever bought |

## Open questions for refinement

Every question is answered or closed. Nothing blocks the implementation plan.

### Architecture: answered on 5 October 2026

- [x] Is DefectDojo an existing instance or a new one deployed with SecureScan? Which release and edition?
- [x] Is DefectDojo confirmed as the only place for triage, or must version 1 offer triage in the portal?
- [x] Is a single Docker host acceptable, or is Kubernetes or OpenShift mandated? Is high availability required?
- [x] Is internet egress allowed for rule and database updates, or is the environment fully isolated?
- [x] What team will build this, and with which skills? This confirms the Python stack and sets phase durations.

| Question | Answer | Effect on the design |
| --- | --- | --- |
| DefectDojo instance | A new instance, initialised with the application at deployment | DefectDojo joins the Compose project. A setup container configures it. |
| Triage | DefectDojo only | SecureScan stores no findings and has no triage screens. The portal shows counts and links. |
| Deployment | Docker Compose on a single on-premises machine | Kubernetes and scale-out design removed. Backups leave the machine. |
| Internet egress | Allowed | Offline bundles replaced by scheduled updates behind a regression check. |
| Team and lifespan | Built once in Python, then run 5 to 10 years by the security and IT team. The portal triggers and follows scans. Results flow into DefectDojo automatically. | Custom parsing and deduplication dropped. Upkeep section and calendar added. |

### Scope: answered on 5 and 6 October 2026

- [x] Are dependency, secret, container and infrastructure-as-code scanning in scope for version 1, or strictly SAST and DAST?
- [x] Which languages and frameworks do internal applications use?
- [x] What do vendors usually supply: source, binaries, images, or only a URL?
- [x] Who hosts a test instance when a vendor ships an on-premises product for DAST?
- [x] Is DAST against production allowed at all, and who approves it?
- [x] Which CI systems must integrate first?
- [x] Does the company already license commercial scanners that should plug in?
- [x] Is ticketing integration needed? If so, it is configured in DefectDojo.
- [x] Do application owners get DefectDojo access to their own applications, or do only security analysts use it?

| Question | Answer | Effect on the design |
| --- | --- | --- |
| Scanners | Semgrep, Syft, Grype, Gitleaks, SonarQube, CodeQL and OWASP Dependency-Check for code; ZAP and Nuclei for DAST | A catalogue of eight tools. CodeQL removed for licence reasons; a free alternative is under evaluation. |
| Languages | Java, .NET, JavaScript, TypeScript, HTML, SQL, NoSQL, Python | A coverage table per language. C# gets pattern scanning only. |
| Vendor inputs | Docker images, zipped code, GitHub URLs from vendors and from the company's own GitHub | Three intake paths. Deploy keys and vendor tokens for private vendor repositories. |
| Vendor hosting | The company hosts deployable products, not SaaS | Full DAST in UAT for deployable products. SaaS gets baseline only, with written authorization. |
| DAST on production | Baseline only; full scans only on UAT | A hard rule in the API. Analysts set the environment tag. |
| Automation | Corporate GitHub on github.com, automatic repository scans, a report in the portal downloadable as PDF | GitHub App, poller, automatic reports. |
| Commercial scanners | None | No paid engines. |
| Ticketing | None | Removed. |
| DefectDojo users | Security analysts only | Both roles get a provisioned local DefectDojo account; the gateway requires a SecureScan session first. |

### Detail: answered on 6 October 2026

- [x] Which identity provider is in use, and does it issue group claims?
- [x] Which standards must reports map to, beyond OWASP Top 10 and CWE Top 25?
- [x] Is PDF enough for reports, or is an editable format required? Is there a corporate template?
- [x] What are the real figures for application count, scans per day, largest repository and retention periods?
- [x] Who builds the platform, and how many people? This sets phase durations and who owns code changes afterwards.

| Question | Answer | Effect on the design |
| --- | --- | --- |
| Identity provider | Microsoft Entra ID, with app roles assigned directly | Two app roles, Admin and Analyst. One app registration with assignment required. DefectDojo accounts are local, behind the gateway. |
| Standards | OWASP Top 10 and CWE Top 25 are enough | No further mapping. |
| Report format | A downloadable SonaComstar default template, plus custom templates | Template management in Settings, sandboxed rendering. |
| Retention | All historical data kept in the PostgreSQL database and queryable in the portal as CSV | The Historical data section and the FindingHistory table. Permanent retention. |
| Portal | Simple: Entra SSO, a minimalist black-and-white login with SonaComstar branding, pages for SAST, DAST and Historical data, a DefectDojo button on the home page | The portal is cut to five pages plus Settings. |
| Who builds it | Built in this repository | The implementation plan is written for Claude Code working with the user here. |
| Machine | Only DefectDojo, the database and the portal run constantly; scans spin up on demand | On-demand model including SonarQube. Sizing by always-on and peak load. |

### Closed on 6 October 2026

| Point | Decision |
| --- | --- |
| Authenticated scans | Login profiles belong to UAT targets only. Production gets unauthenticated baseline scans. |
| Branding | The portal is SonaComstar-branded in black and white with a text wordmark. Logo files come later and drop into one brand folder. |
| Entra roles | Two: Admin and Analyst. No read-only or owner-scoped role. |
| OWASP Dependency-Check | Kept beside Grype, as requested. |
| Everything else | Declared irrelevant by the company. The defaults stand: ZAP form posting off on production, the no-disclosure profile for vendor code, polling instead of webhooks, verdict thresholds as proposed, builds of vendor code in a later phase, and source requested from .NET vendors. |
