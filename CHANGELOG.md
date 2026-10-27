# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Lock files are now reviewed. Each rule here comes from a real failure this week: a CA bundle that kept trusting
compromised roots, and a timing side channel in a Go key check that a maintainer caught in review.

### Added
- A `lockfile` file kind: `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `package-lock.json`,
  `npm-shrinkwrap.json`, and pip `requirements*.txt` and `constraints*.txt`.
- `ACR-DEP-001` (high): certifi pinned before 2026.10.23, which still trusts the compromised emSign roots, in any of
  those formats. On KServe it found two test-resource locks a manual sweep had missed.
- `ACR-DEP-002` (high): packages fetched over plain HTTP, or `--trusted-host`, in a lock or pip file.
- `ACR-DEP-003`: `--extra-index-url` in a pip file, which lets a public package that takes an internal name win.
- `ACR-DEP-004` (low): an npm lock entry installed from git or a GitHub tarball, which has no integrity hash.
- `ACR-APP-019`: Go code that compares, measures or sets an ECDSA private key's `D` with `big.Int`, with
  `PrivateKey.Bytes` and `ParseRawPrivateKey` as the fix.

### Changed
- The README's rule table names the dependency area, and its rule count is tested against the registry.

## [0.6.0] - 2026-10-25

The week of the GhostAction campaign, which planted credential-stealing workflows in tens of thousands of repositories,
and of a plugin hash-pin bypass in a coding agent. Six rules for exactly those shapes.

### Added
- `ACR-GHA-014` (critical): a workflow step that posts `${{ secrets.* }}` or the job's token to a host other than
  GitHub's, or pipes its environment into `curl`, `nc` or `base64`. The signature of the GhostAction workflows.
- `ACR-GHA-015`: untrusted event data (titles, bodies, branch names) written into `$GITHUB_ENV` or `$GITHUB_PATH`,
  directly or through an `env:` variable, which injects variables or binaries into every later step.
- `ACR-GHA-016`: `pip`, `uv pip`, `npm`, `go install` or `cargo install` taking a dependency from a moving git ref
  (a branch, `@latest`, no ref) in a workflow.
- `ACR-DOCKER-011`: `COPY --from=` an external image that is not pinned (latest or no tag); the copied binary runs in
  the image with none of the base-image checks applied.
- `ACR-AI-016`: a coding-agent plugin marketplace entry (`.claude-plugin/marketplace.json`, `.grok-plugin/marketplace.json`)
  whose source is not pinned to a 40-character commit sha.
- `ACR-AI-017` (critical): a plugin `hooks.json` command that pipes a download into a shell, reads `~/.ssh`, `~/.aws`
  and the like, or ships its environment out.
- Coding-agent plugins are a file kind of their own (`agent-plugin`): marketplace indexes, plugin manifests and hooks
  under `.claude-plugin/` or `.grok-plugin/`.

## [0.5.0] - 2026-10-13

### Added
- `--format gitlab` (GitLab Code Quality) and `--format junit` (Jenkins, Azure DevOps, CircleCI, Bitbucket), plus a GitLab CI template and integration guides in `docs/ci-integrations.md`.
- `--diff-file PATH|-` reviews any unified diff, from a file or stdin.
- `--min-severity` / `min_severity:` noise floor, applied before the AI step.
- Expiring suppressions: `acr:ignore[ID] until=YYYY-MM-DD`; after the date the finding returns with a note.
- `acr baseline --check` (fails when accepted findings were fixed) and `acr baseline --prune` (removes them, never adds new ones).
- AI cost and privacy controls: `--ai-max-findings` (default 50, most severe first) and `--ai-dry-run` (prints the redacted request without calling a model).
- `--timings`, and rule/scanner durations in the JSON report; `acr rules --category`.
- Docker Compose files and coding-agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, Copilot instructions) are classified; the skill rules now also check instruction files.
- Sixteen rules (103 in total): four Compose rules (privileged/host namespaces, Docker socket and host mounts, unpinned images, databases published on all interfaces), `curl | bash` in workflows, unpinned `docker://` actions, unauthenticated Lambda function URLs, purgeable Key Vaults and secrets, credentials in ConfigMaps, allow-all NetworkPolicies, `enableAllProjectMcpServers`, agent access to the whole disk or home directory, regex built from request input, Django `ALLOWED_HOSTS` wildcard, CSRF disabled, SSH servers in images.
- GitHub Action `min-severity` input; CI checks that the demo fails the gate and every report format renders.
- `docs/architecture.md`; SECURITY.md now lists exactly what the AI step sends.

### Fixed
- The diff parser marked a hunk's whole range as changed, so diffs with context lines (a plain `git diff` passed to `--diff-file`) also reported unchanged lines. Only added lines count now.
- Sixteen rules from 0.1.0 had no direct tests; each now has positive and negative cases, and a test fails if any rule is untested.

## [0.4.0] - 2026-10-12

### Added
- Custom rules in `.acr.yml` (`custom_rules`: id, title, regex pattern, severity, file globs, fix), validated on load, run like built-in rules and listed by `acr rules` / `acr explain`.
- `--include` and `include:` to review only part of a repository; `acr classify` shows a file's kinds and the rules that apply.
- Nineteen rules (87 in total): hostPort, unmasked /proc, ingress-nginx snippets, privileged Pod Security namespaces, unauthenticated services (Ollama, Ray, Jupyter, Redis, ...) exposed outside the cluster, ACTIONS_ALLOW_UNSECURE_COMMANDS, toJSON(secrets), credential files copied into images, resource policies open to any principal, KMS rotation off, CloudTrail logging off, per-object bucket ACLs, model servers with --trust-remote-code, public Gradio share links, skills that pre-approve unrestricted Bash, open redirects, path traversal, deprecated TLS versions, insecure session cookies.
- SARIF: stable `partialFingerprints`, tool execution notifications for failed or missing scanners and AI errors, and full rule help for built-in rules.
- JSON report: `schema_version` and a `gate` section (threshold, blocking count, passed), plus `files_skipped` and `scanners_failed`.
- GitHub Action: `scanners` input and `findings`, `blocking`, `report-file` outputs.
- Markdown summary links each location to the PR head commit and collapses findings beyond the first 25.
- CI fails on Python SyntaxWarnings.

### Changed
- AI agent: credential files are never read or searched, and secrets in the diff and tool output are redacted before they reach the model; findings now include their category and the rule's fix guidance.
- Inline PR comments already posted by an earlier run are not repeated; GitHub API calls retry on 5xx, rate limits and network errors; review bodies stay under GitHub's size limit.
- A scanner that times out or crashes is reported as failed instead of looking clean.
- ACR-GHA-001 also covers issue_comment and workflow_run workflows that check out PR code; ACR-AI-003 covers LangChain `load_tools` with shell or REPL tools; ACR-APP-004 covers joblib, pandas.read_pickle and numpy allow_pickle; ACR-MCP-002 covers keys in server URLs; ACR-K8S-003 reports container runtime sockets as critical.

### Fixed
- Files whose names git quotes (non-ASCII, quotes, backslashes) were silently skipped in every mode.
- ACR-TF-001 counted an open egress block against a restricted ingress rule, and missed all-traffic ingress (`protocol = "-1"`).
- hostPath written in YAML flow style was not detected.
- Shallow clones without a merge base made `--base` fail; acr now falls back to a direct diff and says so.

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

[0.5.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sunilmehta-si/agentic-code-review-tool/releases/tag/v0.1.0
