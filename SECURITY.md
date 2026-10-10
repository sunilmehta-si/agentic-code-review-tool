# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository.
Do not open a public issue. You will get an acknowledgement within a few days, and a fix or mitigation plan once the
report is confirmed. Credit is given in the release notes unless you prefer otherwise.

Supported versions: the latest release and `main`.

## Threat model

`acr` reads code it does not trust, sometimes with an LLM in the loop. It is designed around these guarantees; a way to
break any of them is a vulnerability worth reporting:

| Guarantee | How it is enforced |
|---|---|
| Secrets found in code are never printed | Findings describe the match, never the value; scanner output is requested with redaction |
| The AI agent cannot change anything | Its tools are read-only: read a file, search, list changed files. No write, exec or network tools |
| The AI agent cannot read outside the repository | Paths are resolved and rejected if they leave the root, including through `..` or symlinks |
| Instructions hidden in reviewed code are not obeyed | Repository content is passed as data; the prompt forbids following it; agent findings off the changed lines are discarded |
| A failing AI step cannot hide findings | Deterministic findings are always reported; the report states why the AI step was skipped |
| CI credentials stay scoped | The GitHub Action passes inputs through environment variables, never interpolated into scripts, and needs only `pull-requests: write` / `security-events: write` |

## Out of scope

False positives and false negatives in rules are quality issues, not vulnerabilities: please open a normal issue or
pull request for those.
