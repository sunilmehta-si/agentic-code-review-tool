# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-10-11

### Added
- Rule-scoped inline suppressions: `acr:ignore[ACR-APP-004, semgrep:*]` silences only the listed rules; a bare `acr:ignore` still silences the line.
- `acr review --staged` reviews the index (what will be committed), not unstaged edits.
- `--format github` prints workflow-command annotations; the GitHub Action shows them by default (`annotations` input), which also works for pull requests from forks.
- `acr init` writes a commented, validated starter `.acr.yml`.
- `acr rules --format markdown|json`; a test keeps the README rule catalogue in sync with the code.
- Ten rules (68 in total): coding agents launched with permission checks or the sandbox off (Claude Code, Codex, Gemini CLI), agent settings that pre-approve any or risky shell commands, auto-approved MCP tools, `secrets: inherit` to external reusable workflows, self-hosted runners on pull-request workflows, TLS or signature checks disabled in image builds, seccomp/AppArmor unconfined, instance metadata without session tokens (IMDSv1, GKE node metadata), predictable randomness for secrets, XML external entities.
- Shell scripts, Makefiles and committed coding-agent settings files are classified, so rules can target them.
- CI installs the built wheel in a clean virtualenv and smoke-tests the CLI.

### Changed
- Inline suppression is applied once, centrally, to every finding: structural rules (checked at the line they report) and external scanners now honour it too.
- The pre-commit hook runs `--staged` at the pre-commit stage only.
- Severity overrides in `.acr.yml` accept globs; an exact rule id wins, then the longest matching pattern.

### Fixed
- A marker scoped to one rule no longer hides other rules' findings on the same line, and a marked `FROM ... AS stage` line keeps its stage alias.
- Container findings pointed at line 1 when the container's `- name:` line had a trailing comment.
- Plural token settings (`http_tokens = "required"`, `max_tokens`) are no longer reported as hardcoded secrets.

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

[0.3.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/releases/tag/v0.1.0
