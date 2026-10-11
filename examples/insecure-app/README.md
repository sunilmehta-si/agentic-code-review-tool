# Deliberately insecure demo

Every file here contains mistakes on purpose, one or more per rule family, so you can see what
`acr` reports. That includes coding-agent settings (`.claude/settings.json`) and a workflow that runs an
agent with its permission checks off. Nothing here is real: the "secrets" are fake strings. Do not deploy any of it.

```bash
acr review --root examples/insecure-app --all --no-scanners --fail-on never
```
