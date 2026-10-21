# SecureScan — instructions for coding agents

SecureScan is an on-premises SAST and DAST scanning platform for Sona Comstar. It orchestrates free scanners as on-demand containers, loads every result into a bundled open-source DefectDojo, keeps a permanent history, and renders SonaComstar-branded reports. One Linux machine, Docker Compose.

## Read first, in this order

1. `docs/design.md` — the design. It is the source of truth. Do not edit it here; the editable original is a Claude Doc (see `docs/implementation-plan.md`, header).
2. `docs/implementation-plan.md` — the milestone plan you follow, one milestone at a time.
3. `docs/progress.md` — where we are. Tick what you finish; list deviations.
4. `docs/decisions.md` — decisions made during the build. Append; never rewrite history.

## Rules that are not negotiable

- DefectDojo is the only place findings are parsed and triaged. SecureScan never parses scanner output into findings; it uploads raw reports and reads findings back.
- Only `gateway`, `api`, `worker`, `db`, `socket-proxy` and DefectDojo's services run permanently. Scanners, egress proxies and updaters run on demand.
- The platform is sized for 4 vCPU and 8 GB RAM: one scanner container at a time (catalogue lock `scanner`), scanners within 2 CPUs and 3 GB, always-on memory limits within 5.5 GB (`tests/unit/test_operations_files.py` checks it). No SonarQube, no Dependency-Check.
- The worker is the only component that talks to Docker, only through `socket-proxy`, only with specs built from `scanners/catalogue.yaml`.
- Two roles: `Admin` and `Analyst`, from the Entra ID `roles` claim. No local users, no ownership scoping.
- Production DAST targets get unauthenticated ZAP baseline scans only. Everything else is UAT only.
- No CodeQL. No scanner outside the catalogue. Every image pinned by digest, never `latest`.
- Secrets never in git, logs, findings, reports or exports.
- Semgrep rules are for internal use only; no scanner output to external AI services.

## Working conventions

- Backend: Python 3.14, `uv`, FastAPI, SQLAlchemy 2.1, Alembic, Procrastinate; `uv run ruff check . && uv run ruff format --check . && uv run mypy securescan && uv run pytest` must pass.
- Frontend: Node 24, React 19, TypeScript strict, Vite, Tailwind + Radix (shadcn/ui pattern); `npm run lint && npm run typecheck && npm test` must pass.
- Conventional commits, small commits, lock files committed. LF line endings (`.gitattributes`).
- `python scripts/dev.py` is the entry point for running, testing and pinning images.
- When a tool behaves differently from the design or the plan, record it in `docs/decisions.md` and propose the smallest fix. Ask the user only for credentials, tenant values, hardware, or a change to a design decision.
