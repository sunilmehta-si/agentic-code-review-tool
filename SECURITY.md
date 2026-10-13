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
| Credentials are not sent to the model provider | The agent's tools refuse credential files (`.env`, private keys, `*.tfstate`, `*.tfvars`, `.npmrc`, ...) and hide them from search; provider keys, private-key blocks and hardcoded passwords in the diff and tool output are replaced with `[REDACTED]` |
| Instructions hidden in reviewed code are not obeyed | Repository content is passed as data; the prompt forbids following it; agent findings off the changed lines are discarded |
| A failing AI step cannot hide findings | Deterministic findings are always reported; the report states why the AI step was skipped |
| CI credentials stay scoped | The GitHub Action passes inputs through environment variables, never interpolated into scripts, and needs only `pull-requests: write` / `security-events: write` |

## What the AI step sends

Only when `--ai` is set, and only to the provider you choose (Anthropic, or an OpenAI-compatible endpoint such as a
local model server):

- a fixed system prompt,
- the findings to verify (rule, title, severity, path, line, detail, the rule's fix text), capped by `--ai-max-findings`,
- the unified diff of the change, redacted and truncated to 60,000 characters,
- the output of the agent's read-only tool calls (file excerpts and search results), redacted.

`acr review --ai-dry-run` prints the system prompt and the first message exactly as they would be sent, without calling
any model, so you can review them before turning the AI step on. Without `--ai`, nothing leaves the machine except
what your configured external scanners send (none of the bundled adapters upload code).

## Out of scope

False positives and false negatives in rules are quality issues, not vulnerabilities: please open a normal issue or
pull request for those.
