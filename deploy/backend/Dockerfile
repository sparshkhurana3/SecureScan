# One image for api, worker, migrate, dojo-init and sonar-init. Build context: repository root.
ARG PYTHON_IMAGE=python:3.14-slim-trixie
FROM ${PYTHON_IMAGE} AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/app/.venv
RUN pip install --no-cache-dir uv==0.8.*
WORKDIR /src
COPY backend/pyproject.toml backend/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-project
COPY backend/securescan ./securescan
COPY backend/README.md ./README.md
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev

FROM ${PYTHON_IMAGE} AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-liberation git openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 1000 app && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin app \
 && install -d -o app -g app -m 0775 /var/lib/securescan /var/lib/securescan/artifacts /var/lib/securescan/content
COPY --from=builder /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1
USER app
WORKDIR /home/app
ENTRYPOINT ["/app/.venv/bin/python", "-m", "securescan"]
CMD ["api"]
