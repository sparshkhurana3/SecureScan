# SecureScan backend

FastAPI + Procrastinate backend. See `docs/implementation-plan.md` for the milestones.

```
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy securescan
```
