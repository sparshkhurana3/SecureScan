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
