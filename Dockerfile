# Container image for acr. Built to pass its own rules: pinned base, non-root user, clean package cache.
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

# git is needed to compute what a change touches.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/acr
COPY pyproject.toml README.md LICENSE ./
COPY agentic_code_review ./agentic_code_review
RUN pip install --no-cache-dir ".[claude]"

RUN useradd --uid 10001 --create-home acr \
    && git config --system --add safe.directory '*'
USER 10001
WORKDIR /src

ENTRYPOINT ["acr"]
CMD ["review", "--help"]
