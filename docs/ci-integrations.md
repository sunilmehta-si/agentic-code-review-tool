# CI integrations

`acr` runs anywhere Python 3.10+ and git run. Pick the report format your CI already displays:

| CI | Format | Where findings appear |
|---|---|---|
| GitHub Actions | `--format github` + SARIF (the bundled action does both) | PR annotations, inline review comments, Security tab |
| GitLab | `--format gitlab` | Merge request Code Quality widget |
| Jenkins, Azure DevOps, CircleCI, Bitbucket | `--format junit` | The pipeline's test report |
| Anything else | `--format json` or `--markdown PATH` | Your own tooling |

In every setup, `--fail-on` decides the exit code, and the JUnit failures match the same threshold.

For an exact pull-request diff, fetch enough history for the merge base (`fetch-depth: 0`, `GIT_DEPTH: "0"` or
`git fetch --unshallow`). On a shallow clone `acr` falls back to a direct diff and prints a warning.

## GitHub Actions

Use the bundled action; see [Use it in GitHub Actions](../README.md#use-it-in-github-actions).

## GitLab

Include the template; it runs on merge request pipelines and publishes a Code Quality report:

```yaml
include:
  - remote: https://raw.githubusercontent.com/sunilmehta-si/agentic-code-review-tool/v0.5.0/templates/gitlab-ci.yml

acr-review:
  variables:
    ACR_FAIL_ON: high        # optional overrides
```

## Jenkins

```groovy
stage('Code review') {
  steps {
    sh 'pip install "git+https://github.com/sunilmehta-si/agentic-code-review-tool@v0.5.0"'
    sh 'acr review --base origin/main --format junit -o acr.xml --markdown acr.md'
  }
  post {
    always { junit 'acr.xml' }
  }
}
```

## Azure DevOps

```yaml
- script: |
    pip install "git+https://github.com/sunilmehta-si/agentic-code-review-tool@v0.5.0"
    acr review --base "origin/$(System.PullRequest.TargetBranch)" --format junit -o acr.xml
  displayName: Agentic code review
- task: PublishTestResults@2
  condition: always()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: acr.xml
```

Azure DevOps reports `System.PullRequest.TargetBranch` as `refs/heads/main`. Strip the prefix first, or pass
`--base origin/main` directly.

## CircleCI

```yaml
- run:
    name: Agentic code review
    command: |
      pip install "git+https://github.com/sunilmehta-si/agentic-code-review-tool@v0.5.0"
      mkdir -p reports && acr review --base origin/main --format junit -o reports/acr.xml
- store_test_results:
    path: reports
```

## Bitbucket Pipelines

```yaml
- step:
    name: Agentic code review
    image: python:3.12-slim
    script:
      - apt-get update && apt-get install -y --no-install-recommends git
      - pip install "git+https://github.com/sunilmehta-si/agentic-code-review-tool@v0.5.0"
      - git fetch origin "$BITBUCKET_PR_DESTINATION_BRANCH"
      - mkdir -p test-results && acr review --base "origin/$BITBUCKET_PR_DESTINATION_BRANCH" --format junit -o test-results/acr.xml
```

Bitbucket picks up JUnit files under `test-results/` automatically.

## Any other system

If the CI can produce a unified diff, `acr` can review it. The files are read from `--root`, and only the diff's added
lines are reported:

```bash
git diff -U0 origin/main...HEAD > change.patch    # or: hg diff, p4 diff, an artifact from another job
acr review --diff-file change.patch --format json -o acr.json
git diff origin/main...HEAD | acr review --diff-file -
```

## Before every commit

The pre-commit hook reviews exactly what is staged. See [As a pre-commit hook](../README.md#as-a-pre-commit-hook).
