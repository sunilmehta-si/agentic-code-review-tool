# Container image for acr. Built to pass its own rules: pinned base, non-root user, clean package cache.
# 3.15.1, built 2026-10-21 (digest from the registry; 14 days old on 2026-11-04). The 3.15.2 build of 2026-11-05 is
# adoptable from 2026-11-19.
FROM python:3.15-slim@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51

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
