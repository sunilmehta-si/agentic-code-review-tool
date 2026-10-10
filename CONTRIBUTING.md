# Contributing

Thanks for helping make code review safer. Rules are the most valuable contribution, so this guide starts there.

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
@rule("ACR-APP-010", "Short, specific title of the problem", Severity.HIGH, "app-security", ["lang:python"],
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
- If it belongs in the demo, add a line to `examples/insecure-app`; `tests/test_examples.py` keeps it firing.

Rule ids are `ACR-<AREA>-<NNN>`; use the next free number in that area (`acr rules` lists them). After adding rules, refresh
the README table (see the comment above it).

## Before you open a pull request

- `python -m unittest discover -s tests -t .` passes.
- `acr review --all --no-scanners --exclude 'tests/*' --exclude 'examples/*'` is clean: the tool reviews its own code in CI.
- One logical change per commit, with a message that says what and why.

## Security issues

Please don't open public issues for vulnerabilities in this tool; see [SECURITY.md](SECURITY.md).
