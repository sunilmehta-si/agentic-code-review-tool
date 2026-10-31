# Deliberately insecure demo

Every file here contains mistakes on purpose, one or more per rule family, so you can see what
`acr` reports. That includes coding-agent settings (`.claude/settings.json`) and a workflow that runs an
agent with its permission checks off, pip pins that invite dependency confusion, a Go key
handled with big.Int, a Go admin endpoint with SQL built by `fmt.Sprintf`, a shell handed a built command, a redirect
and a file path taken from the request, a server with no header timeout and a world-writable file, an authorisation
check written as `assert`, an image that installs tools at whatever version is latest, and a workflow step from
`action/` instead of `actions/`. Nothing here is real: the "secrets" are fake strings. Do not deploy any of it.

```bash
acr review --root examples/insecure-app --all --no-scanners --fail-on never
```

The pinned dependencies in `requirements.txt` are old on purpose, so the dependency rules have something to find;
GitHub's Dependabot alerts on this repository point here and are expected. Nothing in this directory is installed or
run by the tool, its tests or its CI.
