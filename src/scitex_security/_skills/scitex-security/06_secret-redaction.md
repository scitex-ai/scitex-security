---
description: |
  [TOPIC] Secret redaction
  [DETAILS] `scitex-security redact` masks secrets in stdin text or in Claude Code PostToolUse hook output — gitleaks (maintained rules, configurable TOML) UNION exact values of credential-named env vars; warns instead of failing open when gitleaks is missing.
tags: [scitex-security-secret-redaction]
---

# Secret redaction

One detector for every caller (agent hooks, pre-commit, CI): callers run
`scitex-security redact SOURCE`; they do not keep their own pattern lists.

## Detection

1. **gitleaks** (`gitleaks stdin`, JSON report kept in-process). The
   packaged `_redact/gitleaks.toml` keeps every upstream rule
   (`[extend] useDefault = true`). Add SciTeX formats or allowlists in a
   gitleaks TOML — never in code.
2. **Exact values**: the live value of every env var whose name matches
   `API_?KEY|SECRET|TOKEN|BEARER|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|DSN|AUTH`
   (value ≥ 12 chars, not a `/`/`~` path) is masked wherever it appears,
   whatever its format.

Every hit becomes `***REDACTED***`. gitleaks missing or failing: (2) still
runs and a warning is emitted — never a silent fail-open.

## CLI

```bash
some-command 2>&1 | scitex-security redact -            # stdin text -> redacted text out
scitex-security redact build.log --config team-gitleaks.toml
scitex-security redact - --hook claude-post-tool-use < event.json
```

SOURCE is a file or `-` (stdin). `--hook claude-post-tool-use` reads the Claude Code PostToolUse JSON and
prints `hookSpecificOutput.updatedToolOutput` (Bash stdout/stderr) when
something was masked, an `additionalContext` warning when redaction ran
degraded, and nothing otherwise. It always exits 0. Register it as the
hook command (`scitex-security redact - --hook claude-post-tool-use`) for the
`Bash` matcher.

## Python

```python
from scitex_security import build_redactor, redact_text

redact_text("log line").text  # one-shot
r = build_redactor()  # reuse: one env scan
outs = r.redact_many([stdout, stderr])  # one gitleaks run for both
```

## Config (`redact:` section of the scitex-security config chain)

| Key | Meaning | Default |
|---|---|---|
| `gitleaks_config` | gitleaks TOML (`--config` overrides) | packaged `gitleaks.toml` |
| `gitleaks_bin` | gitleaks binary | `PATH`, then `~/.local/bin/gitleaks` |
| `env_value_min_length` | shortest env value masked | 12 |
| `finding_min_length` | shortest gitleaks match masked | 8 |

## Extending to other tools

`scitex_security._redact._hook.CLAUDE_TOOL_ADAPTERS` maps a `tool_name` to the response
fields to redact and how to rebuild the response. Only `Bash` is
registered; Read / Grep / WebFetch adapters are a follow-up.
