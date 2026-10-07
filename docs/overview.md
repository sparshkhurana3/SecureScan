# SecureScan: overview, setup and features

SecureScan is an on-premises platform that scans your applications and your vendors' applications for security weaknesses, keeps a permanent record of every scan, and produces SonaComstar-branded reports. It runs on one Ubuntu 24 machine under Docker Compose and signs users in with Microsoft Entra ID.

> **Status (7 October 2026).** The design is complete and the build plan is written (`docs/implementation-plan.md`). Only milestone M0, the repository scaffold, exists so far, and it has not yet been run. Everything under "Features" describes what the finished platform will do, not what you can use today. Progress is tracked in `docs/progress.md`.

## What it does

1. **Scans code** from your corporate GitHub, from zip files, or from Docker images.
2. **Scans running web applications and APIs** (DAST).
3. **Sends every result to DefectDojo**, where security analysts triage findings.
4. **Keeps all history** in a database you can query and export as CSV.
5. **Writes a report after every scan**, readable in the portal and downloadable as a PDF.
6. **Supports vendor assessments**: scan what a vendor supplies, review the findings, issue a report with a verdict.

## Features

**Code scanning (SAST and dependencies).** Nine free tools, each started on demand and removed afterwards:

| Tool | What it finds |
| --- | --- |
| Semgrep | Insecure code patterns in Java, C#, JavaScript, TypeScript, Python, HTML |
| SonarQube Community Build | Bugs, vulnerabilities, code smells, quality gate |
| SpotBugs with Find Security Bugs | Injection, XSS, deserialisation flaws in compiled Java |
| Gitleaks | Hard-coded secrets in files and git history (secret values are masked) |
| Syft and Grype | Software bill of materials and known-vulnerable packages |
| OWASP Dependency-Check | Known-vulnerable Java and .NET dependencies, including JARs and DLLs |

**Web scanning (DAST).** ZAP and Nuclei. Production targets get unauthenticated ZAP baseline scans only. Full scans, API scans, Nuclei and login profiles run only against targets tagged UAT. The platform enforces this; it cannot be overridden from the screen.

**GitHub integration.** A read-only GitHub App discovers repositories each night, checks the default branch every 10 minutes and scans after changes, and runs a weekly full scan. Vendor repositories are reached with a read-only deploy key or a vendor-issued token; a zip upload always works as a fallback.

**Portal.** Black-and-white, SonaComstar branded. Pages: Login (Microsoft only), Home (running scans, latest results, counts, a button to DefectDojo), SAST scan, DAST scan, Historical data (filters, CSV export), scan detail with live log, report view, and Settings for admins.

**Reports.** HTML in the portal and PDF to download, with a downloader watermark. A default SonaComstar template can be downloaded, and custom templates uploaded. Findings are mapped to OWASP Top 10 and CWE Top 25. Every report states its known limits and whether an analyst has reviewed it.

**Vendor assessments.** Mark a scan as vendor, review in DefectDojo, issue a report with a Pass, Conditional pass or Fail verdict (default: Fail on any Critical or more than 5 High; the analyst can override with a reason). A re-assessment of a new version shows what was fixed, what remains and what is new.

**Roles.** Two Entra app roles: Admin (everything, plus Settings) and Analyst (everything except Settings). Both see all data. DefectDojo accounts are created automatically on first sign-in; open-source DefectDojo has no single sign-on, so those are local accounts reachable only through the SecureScan gateway.

**Automation and upkeep.** Scanner rules, templates and vulnerability databases update on a schedule behind a regression check. Image updates are proposed monthly and approved by an admin. A scanner health page shows image versions and data age.

**Security of the platform.** Scanners run in locked-down containers with no network (code scanners) or an allowlisted proxy (DAST), the worker reaches Docker only through a filtered socket proxy, secrets are encrypted at rest, every action is audited, and all history and raw reports are kept permanently.

## What is always running

Only DefectDojo, PostgreSQL, the portal gateway, the API and worker, and the Docker socket proxy. Scanners, the SonarQube server and the proxies start when needed and stop afterwards.

## Setup and deployment

**Machine.** Ubuntu 24.04, 64-bit, cgroup v2. Recommended 16 vCPU, 64 GB RAM, 500 GB SSD (minimum 8 vCPU, 32 GB). Docker Engine 29+ with Compose 2.24+, Python 3.14 via `uv`, Node 24, `openssl`, `git`.

**Host settings** (in `/etc/sysctl.d/99-securescan.conf`, then `sudo sysctl --system`): `vm.max_map_count=524288`, `fs.file-max=131072`.

**Network.** Outbound HTTPS to GitHub, Microsoft Entra, Docker Hub, GHCR, quay.io and the scanner update sources (list in the plan, section 2.4). Two DNS names under one parent domain, for example `securescan.corp.example` and `dojo.securescan.corp.example`, and a TLS certificate covering both.

**What IT must provide.**

- One Entra app registration with app roles `Admin` and `Analyst`, "assignment required" on, groups assigned. Steps are in `deploy/README.md`.
- A GitHub App on the corporate organisation with Contents: read and Metadata: read, webhook off.
- A free NVD API key for Dependency-Check, entered in Settings.
- The SonaComstar logo files, when available. Until then a text wordmark is used.

**Install and start.**

```
cd backend && uv lock && uv sync && cd ..
cd frontend && npm install && cd ..
python3 scripts/dev.py secrets init     # generates random secrets
python3 scripts/dev.py certs            # self-signed, development only; use your CA in production
python3 scripts/dev.py pin-images       # pins every container image by digest
python3 scripts/dev.py pull-images
python3 scripts/dev.py up
```

Then open `https://<portal host>/`. First-time setup of DefectDojo and SonarQube is automatic. Backups, upgrades, restores and the other routines will be documented in `docs/install.md` and `docs/runbooks/` in milestone M11.

## Where to read more

- Design: `docs/design.md`
- Build plan and milestones: `docs/implementation-plan.md`
- Progress and decisions: `docs/progress.md`, `docs/decisions.md`
