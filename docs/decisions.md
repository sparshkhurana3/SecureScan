# Decisions made during the build

Append one entry per decision. Never rewrite or delete an entry; add a new one that supersedes it.

Format:

```
## YYYY-MM-DD — <short title>
Decision: ...
Reason: ...
Alternatives considered: ...
Affects: <design section or plan milestone>
```

## 2026-10-07 — Plan written directly, design exported to the repo
Decision: `docs/design.md` is an export of the SecureScan design doc (Claude Doc) at revision 165; `docs/implementation-plan.md` was written from it and from the fact-checked research of 5–6 October 2026.
Reason: the design doc is the editable original; coding agents need a file in the repository.
Alternatives considered: keeping the design only in the Claude Doc (agents could not read it offline).
Affects: all milestones.

## 2026-10-07 — Deviations from the design taken by the implementation plan (after review)
Decision: six implementation-level deviations, listed in `docs/implementation-plan.md` section 8.3: per-tool container paths instead of fixed `/work/*` paths (and `meta.json` replaced by ScanJob columns); DAST jobs run one at a time; a shared on-demand egress proxy for the worker's own GitHub and updater traffic beside per-job DAST proxies; the SonarQube server container is created by the worker from the catalogue rather than defined in Compose; a second DefectDojo superuser service account for account provisioning; scanner images pre-pulled and image pulls not allowed through the socket proxy.
Reason: an adversarial review of the first plan draft found two blockers (bind-mount paths from a named volume; uid mismatch between the worker and uid-1000 scanner images) and several majors; these choices resolve them without changing any user-facing decision.
Alternatives considered: run-time Docker network creation per DAST job (needs a wider socket-proxy allowlist); defining SonarQube in Compose with a separate `create` step (breaks "one `docker compose up`"); using the DefectDojo `admin` token for provisioning (break-glass account would be in routine use).
Affects: M1 S2/S7, M3, M4, M7, M8, M9.

## 2026-10-07 — Development and deployment machine is Ubuntu 24
Decision: the user develops, runs and verifies on Ubuntu 24 (native Docker Engine), not Windows 11 with Docker Desktop/WSL2. Plan section 2.1 (WSL2 kernel settings, winget installs, Docker Desktop volume quirks) no longer applies; use the Ubuntu host settings in `deploy/README.md`. The coding session itself ran on a Windows machine without Docker, `uv`, Node 24 or Python 3.14, so code is written but unverified until the user runs it on Ubuntu.
Reason: stated by the user when asking for the plan to be implemented.
Alternatives considered: installing the toolchain on the Windows machine (declined by the user).
Affects: plan section 2, M0 acceptance, every milestone's verification.

## 2026-10-08 — Deviations taken while building M2 to M11 (from docs/build-notes/)
Decision: the build of M2 to M11 deviates from the plan and the design in the ways below. Each is small and local; none changes a user-facing decision. The detail and the reasons are in `docs/build-notes/M2.md` to `M11.md`.
- DefectDojo runs on its own `dojo` network (the `db` service joins `backend` and `dojo`; DefectDojo's services do not join `backend`), so the DefectDojo services cannot reach the SecureScan API or its secrets.
- The CWE Top 25 mapping is the 2024 edition (`cwe-top25-2024`); the 2025 list is not published in a machine-readable form we could pin.
- There is no generated API client. The frontend has hand-written typed hooks in `frontend/src/api/*.ts`; the OpenAPI document stays the contract.
- The Grype database and the Dependency-Check/NVD data live in the `content` volume (versioned directories, an `active` pointer), not in separate named volumes.
- Image intake (skopeo) and the GitHub clones use the shared on-demand squid egress proxy (`runner/egress.py`); DAST jobs get a per-job proxy (`runner/dast_egress.py`). The on-demand networks `securescan_sonarqube`, `securescan_dast` and `securescan_egress` are created by `python scripts/dev.py up` (`dev.py networks`) and declared `external` in Compose, because Compose does not create a network that no service joins.
- The ZAP automation plan is written to `/zap/config` of the job (not `/zap/wrk`).
- Vendor condition rules: conditions are required for High findings only, and only on a conditional verdict (`domain/vendors.py`).
- The host check (cgroup v2, kernel limits) refuses to start the worker in production (`SECURESCAN_HOST_CHECK=auto`); development only warns.
- Backups are per-part files (database dumps, volumes, secrets) with a `MANIFEST.txt`; there is no WAL archiving, so the RPO is the backup interval (24 h).
- A scan request may set only the job options listed per tool in `domain/scans.REQUEST_TOOL_OPTIONS` (Semgrep `exclude`, ZAP phase minutes). Policy switches such as Dependency-Check `no_disclosure` come only from the scan profile or from SecureScan's own callers.
- A target may carry only a credential of its own kind, application and version: `vendor_repo` takes a deploy key or vendor token, `image` takes a registry login, nothing else takes one. The sources refuse any other kind as defence in depth.
- Approval of a DAST host (`Target.host_approved`) is cleared when an Analyst changes the host or the API specification of the target.
- The content updaters match candidate Semgrep rules against the regression expectations on the raw report (`jobs/updaters.expectation_met`) because the candidate rules are not yet imported anywhere; it delegates to the one matcher `domain.regression.match_expectation`. Findings of real scans are still DefectDojo's business.
Reason: each came out of an implementation constraint found while writing the milestone; see the build notes.
Alternatives considered: see the build notes of the milestone.
Affects: M2 to M11.

## 2026-10-08 — The vendored DefectDojo Compose file is a placeholder until the first Ubuntu run
Decision: `deploy/defectdojo/upstream/docker-compose.yml` was written without network access (M4 deviation 5). The first step of the first run on Ubuntu 24 is to replace it with the verbatim upstream 3.4.0 file (`docs/install.md`, section 8a) and run `docker compose config`; if nested `include` is refused, list both Compose files with `-f` in `scripts/dev.py` and record it here.
Reason: the build machine had no network access to fetch it.
Alternatives considered: none; a placeholder is the only way to write `override.yaml` ahead of the first run.
Affects: M4 acceptance and every later milestone that needs DefectDojo.

## 2026-10-21 — Portal branding from the SonaComstar brand kit, adapted
Decision: the portal uses the logo files from `sonacomstar-ehs-brand-kit/` (written for a different app, "EHS"). Adaptations: the kit's JSX/CSS became `BrandMark.tsx` and `CompanyLogo.tsx` with Tailwind classes; strings and paths live in `frontend/src/brand/brand.ts`; the company name stays "SonaComstar" (one word, as in `docs/design.md` and the existing UI), not the kit's "Sona Comstar"; the ink of the logos, favicon, app icons and manifest was recoloured from the kit's `#101828` to the portal theme's `#0a0a0a`, so the portal stays black and white. Placed: the ink brand tile with the emblem beside "SecureScan / SonaComstar" in the header, the stacked logo on the login page, favicon, app icons, manifest and tab title. Only the ink and white variants of the stacked logo and emblem are copied; the horizontal lockup (derived by the kit's authors, not official), wordmark-only and black print variants are not shipped. Not applied because the portal has no such element: sidebar, home footer, auth info panel, SSO hint, per-route document titles, and the spreadsheet header (the PDF report template keeps its text wordmark).
Reason: `docs/design.md` says the logo files drop into one brand folder and replace the text wordmark; the kit's own traced vectors are not Sona Comstar's master artwork.
Alternatives considered: copying the kit's React files and `brand.css` as they are (wrong language and styling system, EHS strings); keeping `#101828` (a navy tint on a black-and-white theme).
Affects: `frontend/` only. Replace `frontend/public/brand/` with the official vector logo from corporate communications when available.
