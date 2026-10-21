# SecureScan: overview, setup and features

SecureScan is an on-premises platform that scans your applications and your vendors' applications for security weaknesses, keeps a permanent record of every scan, and produces SonaComstar-branded reports. It runs on one Ubuntu 24 machine under Docker Compose and signs users in with Microsoft Entra ID.

> **Status (8 October 2026).** Milestones M0 to M11 are written: backend, portal, scanner catalogue, deployment files, runbooks and tests. None of it has been run yet; it is verified on Ubuntu 24 milestone by milestone (`docs/progress.md`). The M1 spikes, which confirm scanner flags and DefectDojo, Entra and GitHub behaviour, must run first.

## What it does

1. **Scans code** from your corporate GitHub, from zip files, or from Docker images.
2. **Scans running web applications and APIs** (DAST).
3. **Sends every result to DefectDojo**, where security analysts triage findings.
4. **Keeps all history** in a database you can query and export as CSV.
5. **Writes a report after every scan**, readable in the portal and downloadable as a PDF.
6. **Supports vendor assessments**: scan what a vendor supplies, review the findings, issue a report with a verdict.

## Features

**Code scanning (SAST and dependencies).** Free tools, each started on demand and removed afterwards, one at a time:

| Tool | What it finds |
| --- | --- |
| Semgrep | Insecure code patterns in Java, C#, JavaScript, TypeScript, Python, HTML |
| SpotBugs with Find Security Bugs | Injection, XSS, deserialisation flaws in compiled Java |
| Gitleaks | Hard-coded secrets in files and git history (secret values are masked) |
| Syft and Grype | Software bill of materials and known-vulnerable packages |

SonarQube and OWASP Dependency-Check were removed so the platform fits a 4 vCPU / 8 GB machine (`docs/decisions.md`, 2026-10-21).

**Web scanning (DAST).** ZAP and Nuclei. Production targets get unauthenticated ZAP baseline scans only. Full scans, API scans, Nuclei and login profiles run only against targets tagged UAT. The platform enforces this; it cannot be overridden from the screen.

**GitHub integration.** A read-only GitHub App discovers repositories each night, checks the default branch every 10 minutes and scans after changes, and runs a weekly full scan. Vendor repositories are reached with a read-only deploy key or a vendor-issued token; a zip upload always works as a fallback.

**Portal.** Black-and-white, SonaComstar branded. Pages: Login (Microsoft only), Home (running scans, latest results, counts, a button to DefectDojo), SAST scan, DAST scan, Historical data (filters, CSV export), scan detail with live log, report view, and Settings for admins.

**Reports.** HTML in the portal and PDF to download, with a downloader watermark. A default SonaComstar template can be downloaded, and custom templates uploaded. Findings are mapped to OWASP Top 10 and CWE Top 25. Every report states its known limits and whether an analyst has reviewed it.

**Vendor assessments.** Mark a scan as vendor, review in DefectDojo, issue a report with a Pass, Conditional pass or Fail verdict (default: Fail on any Critical or more than 5 High; the analyst can override with a reason). A re-assessment of a new version shows what was fixed, what remains and what is new.

**Roles.** Two Entra app roles: Admin (everything, plus Settings) and Analyst (everything except Settings). Both see all data. DefectDojo accounts are created automatically on first sign-in; open-source DefectDojo has no single sign-on, so those are local accounts reachable only through the SecureScan gateway.

**Automation and upkeep.** Scanner rules, templates and vulnerability databases update on a schedule behind a regression check. Image updates are proposed monthly and approved by an admin. A scanner health page shows image versions and data age.

**Security of the platform.** Scanners run in locked-down containers with no network (code scanners) or an allowlisted proxy (DAST), the worker reaches Docker only through a filtered socket proxy, secrets are encrypted at rest, every action is audited, and all history and raw reports are kept permanently.

## What is always running

Only DefectDojo, PostgreSQL, the portal gateway, the API and worker, and the Docker socket proxy. Scanners and the proxies start when needed and stop afterwards.

## Setup and deployment

**Machine.** Ubuntu 24.04, 64-bit, cgroup v2. 4 vCPU, 8 GB RAM, 500 GB SSD; scans run one at a time. Docker Engine 29+ with Compose 2.24+, Python 3.14 via `uv`, Node 24, `openssl`, `git`.

**Network.** Outbound HTTPS to GitHub, Microsoft Entra, Docker Hub, GHCR, quay.io and the scanner update sources (list in the plan, section 2.4). Two DNS names under one parent domain, for example `securescan.corp.example` and `dojo.securescan.corp.example`, and a TLS certificate covering both.

**What IT must provide.**

- One Entra app registration with app roles `Admin` and `Analyst`, "assignment required" on, groups assigned. Steps are in `deploy/README.md`.
- A GitHub App on the corporate organisation with Contents: read and Metadata: read, webhook off.
- The official SonaComstar vector logo, when available. The portal uses logo files traced from an existing image (`frontend/public/brand/`); replace them there.

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

Then open `https://<portal host>/`. First-time setup of DefectDojo is automatic. The production installation is `docs/install.md`; backups (`scripts/backup.sh`), the restore drill, upgrades, key rotation and the other routines are the runbooks in `docs/runbooks/`; the security controls and how to check them are `docs/security-checklist.md`.

## Where to read more

- Design: `docs/design.md`
- Build plan and milestones: `docs/implementation-plan.md`
- Progress and decisions: `docs/progress.md`, `docs/decisions.md`
