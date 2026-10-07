# SecureScan build progress

Tick a milestone only when every item of its acceptance checklist in `docs/implementation-plan.md` has been verified. Record deviations from the plan or the design under the milestone, with a date and a pointer to `docs/decisions.md`.

**Verification environment.** The code so far was written on a Windows machine with no Docker, no `uv`, Node 18 and Python 3.9, so
nothing could be executed. The user runs and verifies on Ubuntu 24. "Written" below means the files exist; "verified" means the acceptance
checklist was run on Ubuntu 24 and passed. No milestone is verified yet.

## Milestones

- [ ] M0 — Repository scaffold and tooling — **written 2026-10-07, not yet verified** (see M0 notes)
- [ ] M1 — Spikes (S1 DefectDojo, S2 socket proxy, S3 SonarQube, S4 Entra, S5 WeasyPrint, S6 GitHub App, S7 scanner contract, S8 Opengrep)
- [ ] M2 — Backend foundation
- [ ] M3 — Scan runner, workspaces, Semgrep and Gitleaks
- [ ] M4 — DefectDojo bundle, import, history, accounts
- [ ] M5 — Reports and templates
- [ ] M6 — Portal
- [ ] M7 — GitHub integration
- [ ] M8 — Remaining code scanners and SonarQube on demand
- [ ] M9 — DAST: ZAP and Nuclei
- [ ] M10 — Vendor assessment flow
- [ ] M11 — Hardening, operations, handover
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

## Deviations

- 2026-10-07: the user develops and runs on Ubuntu 24, not Windows 11. Plan section 2.1 (Windows, WSL2) is superseded; see `docs/decisions.md`.
