---
name: scitex-security
description: |
  [WHAT] GitHub security-alert utilities (Dependabot, secret scanning, code scanning), a bandit/shellcheck/pip-audit sweep, a look-alike (typosquat / IDN homograph) domain watch, secret redaction of agent tool output (gitleaks + exact env values), and operator-run credential rotation for signed encrypted payloads.
  [WHEN] Checking open security alerts on GitHub repos, sweeping a repo, watching for impersonation domains of a domain you own, masking secrets in text or agent hook output (`scitex-security redact`), or rotating a credential inside a signed payload (`scitex-security rotate-credential`).
  [HOW] `from scitex_security import check_github_alerts` or `scitex-security --help`.
primary_interface: python
interfaces:
  python: 2
  cli: 1
  mcp: 0
  skills: 2
  hook: 1
  http: 0
canonical-location: scitex-security/src/scitex_security/_skills/scitex-security/SKILL.md
tags: [scitex-security]
---

> **Interfaces:** Python ⭐⭐ · CLI ⭐ · MCP — · Skills ⭐⭐ · Hook ⭐ · HTTP —

# scitex-security

GitHub security-alert utilities. `check_github_alerts(repo=...)` returns the open Dependabot/CodeQL alerts as a structured list. Drop-in replacement for `gh api repos/{owner}/{repo}/dependabot/alerts` shell-outs in monitoring dashboards.

See README.md and the package's public `__init__.py` for the full
function list. This skill leaf exists so agents discover the package
exists and roughly what shape it has — refer to the source for
signatures.

## Sub-skills

### Core (01–09)
- [01_installation.md](01_installation.md) — install + import sanity check
- [02_quick-start.md](02_quick-start.md) — 30-second tour
- [03_python-api.md](03_python-api.md) — Python API surface
- [04_cli-reference.md](04_cli-reference.md) — CLI subcommands
- [05_domain-watch.md](05_domain-watch.md) — look-alike domain watch (typos, homoglyphs, TLD swaps; DNS/MX, CT, RDAP; alerts)
- [06_secret-redaction.md](06_secret-redaction.md) — `redact`: gitleaks + exact credential env values; Claude Code PostToolUse hook mode
- [07_credential-rotation.md](07_credential-rotation.md) — operator-run `rotate-credential` for signed encrypted payloads

### Configuration (20–29)
- [20_env-vars.md](20_env-vars.md) — environment variables
