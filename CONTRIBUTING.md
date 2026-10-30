# Contributing

Thanks for helping make code review safer. Rules are the most valuable contribution, so this guide starts there.

> **Need a rule only for your organisation?** You don't have to change this project: add it under `custom_rules`
> in your repository's `.acr.yml` (see the README). Contribute it here when it would help everyone.

## Set up

```bash
git clone https://github.com/sunilmehta-si/agentic-code-review-tool
cd agentic-code-review-tool
python -m venv .venv && . .venv/bin/activate
pip install -e ".[claude]"
sh scripts/install-hooks.sh          # pre-commit secret scan
python -m unittest discover -s tests -t .
```

## Add a rule

Rules live in `agentic_code_review/rules/`, one module per area (`app.py`, `ai.py`, `kubernetes.py`, `dockerfile.py`,
`github_actions.py`, `terraform.py`, `agents.py`, `secrets.py`). A rule is a function that yields findings for one file:

```python
@rule("ACR-APP-016", "Short, specific title of the problem", Severity.HIGH, "app-security", ["lang:python"],
      fix="One sentence a developer can act on.",
      references=["https://link-to-the-standard-or-docs"])
def my_rule(path, text, lines):
    yield from line_matches(my_rule.info, path, lines, re.compile(r"the risky pattern"))
```

What makes a rule good here:

- **Precision over recall.** A noisy rule teaches people to ignore the tool. Prefer a narrow pattern that is almost always a real problem; broad coverage belongs to Semgrep/Checkov.
- **Exact line.** Point at the line that needs to change, not the start of the file or block.
- **Never echo secrets.** Describe what was found, never the value.
- **A fix, not just a warning.** The `fix` text is shown in PR comments.
- **Tests both ways.** Add a positive case *and* a nearby safe case that must not fire, in `tests/test_rules.py`.
- **Suppressions come for free.** `run_rules` drops findings whose reported line carries `acr:ignore` or
  `acr:ignore[YOUR-ID]`; don't re-implement that in the rule.
- If it belongs in the demo, add a line to `examples/insecure-app`; `tests/test_examples.py` keeps it firing.
  Append to demo files rather than inserting, so the README's demo table keeps its line numbers.
- **Run it over real code before it ships.** Clone two or three large repositories in the rule's language (for Go,
  say, Argo CD, llm-d and etcd-operator; for Python, MLflow and Kubeflow Pipelines) and run only your rule over them
  with `run_rules` and `classify.kinds`. Read every hit. A false positive you find this way is a pattern to exclude
  now, and the true-positive count belongs in the changelog entry, so a reader knows what the rule finds in practice.
  Several of the shipped rules changed shape at this step: an HTTP client's `Get` matched the SQL rule, test files
  tripped the TLS rule, a umask-masked `0o666` tripped the file-mode rule.

Rule ids are `ACR-<AREA>-<NNN>`; use the next free number in that area (`acr rules` lists them). Then:

```bash
acr rules --format markdown        # paste over the table in README.md "Built-in rules" and update the count
acr classify path/to/sample.file   # check your file kinds route the file to the rule
```

`tests/test_registry.py` checks every rule has a unique id, a fix and known file kinds; `tests/test_engine_report_cli.py`
fails if the README table is stale.

## Before you open a pull request

- `python -W error::SyntaxWarning -m unittest discover -s tests -t .` passes (CI uses the same flags).
- `acr review --all --no-scanners --exclude 'tests/*' --exclude 'examples/*'` is clean: the tool reviews its own code in CI.
- One logical change per commit, with a message that says what and why.

## Security issues

Please don't open public issues for vulnerabilities in this tool; see [SECURITY.md](SECURITY.md).
