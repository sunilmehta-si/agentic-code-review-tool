# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-10-10

### Added
- `.acr.yml` repository config: `fail_on`, `exclude`, `disable` (ids or globs), per-rule `severity`, `scanners`, `ai`, `baseline`; invalid settings fail loudly.
- `acr baseline`: accept existing findings so only new ones fail pull requests; fingerprints use rule and line content, so they survive code moves.
- `acr explain <rule>`: why a rule matters, how to fix it, how to suppress it.
- `--sarif`, `--json`, `--markdown PATH`: several report formats from one run.
- Nine rules: JWT verification disabled, CORS wildcard with credentials, secrets in LLM system prompts (OWASP LLM07), agent loops without a step limit (LLM10), Kubernetes RBAC wildcards and cluster-admin bindings, Kubernetes Secrets with literal values, world-writable permissions in images, workflow-wide OIDC tokens, databases without deletion protection. 58 rules in total.
- "By area" summary line in the review comment.
- pre-commit framework hook, digest-pinned non-root container image, contributing guide, security policy, Dependabot.

### Changed
- External scanners run concurrently (`ACR_SCANNER_WORKERS`, default 4).
- The GitHub Action runs the review once and derives the summary, PR comments, SARIF and gate from that single run, instead of three runs.

## [0.1.0] - 2026-10-09

### Added
- Diff-aware review engine that only reports changed lines, with cross-tool duplicate merging.
- 49 built-in rules across secrets, app code, AI/LLM/agent code (OWASP LLM Top 10, MCP configs, agent skills), Kubernetes, Dockerfile, GitHub Actions and Terraform.
- Optional adapters for gitleaks, semgrep, trivy, checkov, hadolint, actionlint and kube-linter.
- AI review agent for Claude (Anthropic SDK) and OpenAI-compatible endpoints, with read-only, repository-confined tools.
- Markdown, JSON and SARIF reports; inline GitHub PR comments; composite GitHub Action; insecure demo project.

[0.2.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/releases/tag/v0.1.0
